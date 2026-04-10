#include "ETWConsumer.h"

#include <evntrace.h>
#include <tdh.h>
#include <vector>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <algorithm>
#include <cctype>
#include <deque>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// ── Define SystemTraceControlGuid manually ─────────────────────────────────
// (avoids dependency on initguid.h which the user removed)
static const GUID g_SystemTraceGuid =
    { 0x9e814aad, 0x3204, 0x11d2, { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };

// ── Global session state ───────────────────────────────────────────────────

static TRACEHANDLE g_sessionHandle = 0;
static TRACEHANDLE g_traceHandle = 0;
static EVENT_TRACE_PROPERTIES* g_properties = nullptr;
static std::atomic_bool g_running{ false };
static ImageLoadCallback g_callback;
static InjectionAlertCallback g_alertCallback;

// ── Injection detection state ──────────────────────────────────────────────

static std::mutex g_detectionMutex;

// Baseline: first 5 seconds records normal DLL loads per process
static std::unordered_map<DWORD, std::unordered_set<std::wstring>> g_processBaseline;
static bool g_baselinePhase = true;
static ULONGLONG g_sessionStartTick = 0;

// Remote thread tracking: records cross-process thread creation events
// Key = target PID, Value = list of (sourcePID, threadID, timestamp)
struct RemoteThreadRecord
{
    DWORD sourcePid;
    DWORD threadId;
    ULONGLONG timestamp;
};
static std::unordered_map<DWORD, std::deque<RemoteThreadRecord>> g_remoteThreads;

// Suspicious DLL loads: records non-trusted DLL loads
// Key = target PID, Value = list of (dllPath, timestamp)
struct SuspiciousDllRecord
{
    std::wstring dllPath;
    ULONGLONG timestamp;
};
static std::unordered_map<DWORD, std::deque<SuspiciousDllRecord>> g_suspiciousDlls;

// Correlation window: alert if remote thread + suspicious DLL within this ms
static const ULONGLONG CORRELATION_WINDOW_MS = 5000;

// Already-alerted PIDs (avoid duplicate alerts)
static std::unordered_set<DWORD> g_alertedPids;

// Tracked standalone remote threads to prevent spam without blocking the main alerts
static std::unordered_set<DWORD> g_alertedRemoteThreads;

// Process parent tracking: PID → parent PID
static std::unordered_map<DWORD, DWORD> g_processParents;
// Process image path tracking: PID → full image path
static std::unordered_map<DWORD, std::wstring> g_processImagePaths;

// ── Trusted path check ─────────────────────────────────────────────────────

static bool IsTrustedPath(const std::wstring& path)
{
    if (path.empty()) return true;

    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    // System directories
    if (lower.find(L"\\windows\\system32\\")       != std::wstring::npos) return true;
    if (lower.find(L"\\windows\\syswow64\\")       != std::wstring::npos) return true;
    if (lower.find(L"\\windows\\winsxs\\")         != std::wstring::npos) return true;
    if (lower.find(L"\\windows\\microsoft.net\\")  != std::wstring::npos) return true;
    if (lower.find(L"\\windows\\assembly\\")       != std::wstring::npos) return true;

    // Common safe app paths
    if (lower.find(L"\\program files\\")           != std::wstring::npos) return true;
    if (lower.find(L"\\program files (x86)\\")     != std::wstring::npos) return true;

    return false;
}

static std::wstring GetFilenameFromPath(const std::wstring& path)
{
    auto pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
}

void SetInjectionAlertCallback(InjectionAlertCallback callback)
{
    std::lock_guard<std::mutex> lk(g_detectionMutex);
    g_alertCallback = std::move(callback);
}

// ── Helper to enrich alert with process context ───────────────────────────

static void EnrichAlert(InjectionAlertEvent& alert)
{
    // Populate parent PID from tracked process-start events
    auto parentIt = g_processParents.find(alert.sourcePid);
    if (parentIt != g_processParents.end())
        alert.parentPid = parentIt->second;

    // Populate source image path
    auto imgIt = g_processImagePaths.find(alert.sourcePid);
    if (imgIt != g_processImagePaths.end())
        alert.sourceImagePath = imgIt->second;
}

// ── Correlation engine ─────────────────────────────────────────────────────
// Tries to match a remote thread event with a suspicious DLL load targeting
// the same PID within the correlation window.  Fires an alert on match.

static void TryCorrelate(DWORD targetPid)
{
    if (g_alertedPids.count(targetPid))
        return;  // Already alerted for this PID

    ULONGLONG now = GetTickCount64();

    auto rt_it = g_remoteThreads.find(targetPid);
    auto dl_it = g_suspiciousDlls.find(targetPid);

    // Need both a remote thread and a suspicious DLL load 
    if (rt_it == g_remoteThreads.end() || rt_it->second.empty())
        return;
    if (dl_it == g_suspiciousDlls.end() || dl_it->second.empty())
    {
        // Even without a DLL match, a remote thread alone is suspicious
        // if it comes from a non-system process.  Fire a Medium alert.
        auto& rt = rt_it->second.back();
        if (now - rt.timestamp < CORRELATION_WINDOW_MS)
        {
            if (g_alertCallback && !g_alertedRemoteThreads.count(targetPid))
            {
                g_alertedRemoteThreads.insert(targetPid);
                InjectionAlertEvent alert;
                alert.sourcePid = rt.sourcePid;
                alert.targetPid = targetPid;
                alert.remoteThreadId = rt.threadId;
                alert.technique = "Remote Thread Injection";
                alert.severity = "Medium";
                EnrichAlert(alert);
                g_alertCallback(alert);
            }
        }
        return;
    }

    // Check for time-correlated remote thread + DLL load
    for (auto& rt : rt_it->second)
    {
        for (auto& dll : dl_it->second)
        {
            ULONGLONG timeDiff = (rt.timestamp > dll.timestamp)
                ? (rt.timestamp - dll.timestamp)
                : (dll.timestamp - rt.timestamp);

            if (timeDiff <= CORRELATION_WINDOW_MS)
            {
                // MATCH — injection detected!
                g_alertedPids.insert(targetPid);

                if (g_alertCallback)
                {
                    InjectionAlertEvent alert;
                    alert.sourcePid = rt.sourcePid;
                    alert.targetPid = targetPid;
                    alert.remoteThreadId = rt.threadId;
                    alert.dllPath = dll.dllPath;
                    alert.technique = "LoadLibrary Injection";
                    alert.severity = "Critical";

                    // Check for known malicious names
                    std::wstring filename = GetFilenameFromPath(dll.dllPath);
                    std::transform(filename.begin(), filename.end(), filename.begin(), ::towlower);
                    if (filename.find(L"malicious") != std::wstring::npos ||
                        filename.find(L"inject")    != std::wstring::npos ||
                        filename.find(L"payload")   != std::wstring::npos ||
                        filename.find(L"hook")      != std::wstring::npos)
                    {
                        alert.severity = "Critical";
                    }

                    EnrichAlert(alert);
                    g_alertCallback(alert);
                }
                return;
            }
        }
    }
}

// Pruning: remove records older than correlation window
static void PruneOldRecords()
{
    ULONGLONG now = GetTickCount64();
    ULONGLONG cutoff = (now > CORRELATION_WINDOW_MS * 2)
        ? (now - CORRELATION_WINDOW_MS * 2) : 0;

    for (auto& pair : g_remoteThreads)
    {
        auto& records = pair.second;
        while (!records.empty() && records.front().timestamp < cutoff)
            records.pop_front();
    }
    for (auto& pair : g_suspiciousDlls)
    {
        auto& records = pair.second;
        while (!records.empty() && records.front().timestamp < cutoff)
            records.pop_front();
    }
}

// ── TDH property helpers ───────────────────────────────────────────────────

static bool GetPropertyBuffer(
    PEVENT_RECORD event,
    PCWSTR name,
    std::vector<BYTE>& buffer,
    EVENT_PROPERTY_INFO* outPropInfo)
{
    if (!event || !name)
        return false;

    ULONG infoSize = 0;
    ULONG status = TdhGetEventInformation(event, 0, nullptr, nullptr, &infoSize);
    if (status != ERROR_INSUFFICIENT_BUFFER)
        return false;

    std::vector<BYTE> infoBuffer(infoSize);
    auto info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
    status = TdhGetEventInformation(event, 0, nullptr, info, &infoSize);
    if (status != ERROR_SUCCESS)
        return false;

    PROPERTY_DATA_DESCRIPTOR desc = {};
    desc.PropertyName = (ULONGLONG)name;
    desc.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    status = TdhGetPropertySize(event, 0, nullptr, 1, &desc, &size);
    if (status != ERROR_SUCCESS || size == 0)
        return false;

    buffer.resize(size);
    status = TdhGetProperty(event, 0, nullptr, 1, &desc, size, buffer.data());
    if (status != ERROR_SUCCESS)
        return false;

    if (outPropInfo)
    {
        // Find the matching property info
        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
        {
            const EVENT_PROPERTY_INFO& prop = info->EventPropertyInfoArray[i];
            PCWSTR propName = (PCWSTR)((PBYTE)info + prop.NameOffset);
            if (propName && _wcsicmp(propName, name) == 0)
            {
                *outPropInfo = prop;
                break;
            }
        }
    }

    return true;
}

static bool GetPropertyUInt64(PEVENT_RECORD event, PCWSTR name, ULONG64& value)
{
    std::vector<BYTE> buffer;
    if (!GetPropertyBuffer(event, name, buffer, nullptr))
        return false;

    if (buffer.size() == sizeof(ULONG64))
    {
        value = *reinterpret_cast<const ULONG64*>(buffer.data());
        return true;
    }
    if (buffer.size() == sizeof(ULONG))
    {
        value = static_cast<ULONG64>(*reinterpret_cast<const ULONG*>(buffer.data()));
        return true;
    }
    return false;
}

static bool GetPropertyUInt32(PEVENT_RECORD event, PCWSTR name, ULONG& value)
{
    ULONG64 temp = 0;
    if (!GetPropertyUInt64(event, name, temp))
        return false;
    value = static_cast<ULONG>(temp);
    return true;
}

static bool GetPropertyString(PEVENT_RECORD event, PCWSTR name, std::wstring& value)
{
    std::vector<BYTE> buffer;
    EVENT_PROPERTY_INFO propInfo = {};
    if (!GetPropertyBuffer(event, name, buffer, &propInfo))
        return false;

    USHORT inType = propInfo.nonStructType.InType;
    if (inType == TDH_INTYPE_UNICODESTRING)
    {
        value.assign(reinterpret_cast<const wchar_t*>(buffer.data()));
        return true;
    }
    if (inType == TDH_INTYPE_ANSISTRING)
    {
        std::string ansi(reinterpret_cast<const char*>(buffer.data()));
        if (!ansi.empty())
        {
            int needed = MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, nullptr, 0);
            if (needed > 0)
            {
                std::wstring wide(needed - 1, L'\0');
                MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, &wide[0], needed);
                value = wide;
                return true;
            }
        }
    }
    return false;
}

// ── ETW event callback (handles all 4 providers) ───────────────────────────

// Opcode constants
#define OPCODE_PROCESS_START  1
#define OPCODE_PROCESS_END    2
#define OPCODE_THREAD_START   1
#define OPCODE_THREAD_END     2
#define OPCODE_IMAGE_LOAD     10  // EVENT_TRACE_TYPE_LOAD

static void WINAPI EventRecordCallback(PEVENT_RECORD event)
{
    if (!g_running.load() || !event)
        return;

    // We only handle kernel events from the system trace
    // Event header fields tell us which provider + opcode

    const UCHAR opcode = event->EventHeader.EventDescriptor.Opcode;
    const USHORT eventId = event->EventHeader.EventDescriptor.Id;

    // ── Kernel-Image: DLL load events ──────────────────────────────────
    // EventId = 0, Opcode = 10 (EVENT_TRACE_TYPE_LOAD)
    if (opcode == EVENT_TRACE_TYPE_LOAD)
    {
        ImageLoadEvent payload;
        GetPropertyUInt32(event, L"ProcessId", payload.processId);
        GetPropertyUInt64(event, L"ImageBase", payload.imageBase);
        GetPropertyUInt32(event, L"ImageSize", payload.imageSize);

        if (!GetPropertyString(event, L"FileName", payload.imagePath))
            GetPropertyString(event, L"ImageFileName", payload.imagePath);

        if (payload.processId == 0)
            return;     // Skip kernel image loads

        // Invoke the raw image-load callback
        if (g_callback)
            g_callback(payload);

        // ── Injection detection for image loads ────────────────────────
        {
            std::lock_guard<std::mutex> lk(g_detectionMutex);

            ULONGLONG now = GetTickCount64();
            if (g_baselinePhase && (now - g_sessionStartTick > 5000))
                g_baselinePhase = false;

            std::wstring lowerPath = payload.imagePath;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

            if (g_baselinePhase)
            {
                g_processBaseline[payload.processId].insert(lowerPath);
                return;
            }

            // Skip if already known
            auto it = g_processBaseline.find(payload.processId);
            if (it != g_processBaseline.end() && it->second.count(lowerPath))
                return;
            g_processBaseline[payload.processId].insert(lowerPath);

            // Flag non-trusted DLL loads as suspicious
            if (!IsTrustedPath(payload.imagePath))
            {
                SuspiciousDllRecord rec;
                rec.dllPath = payload.imagePath;
                rec.timestamp = now;
                g_suspiciousDlls[payload.processId].push_back(rec);

                // Try to correlate with an existing remote thread record
                TryCorrelate(payload.processId);

                // Only alert on standalone DLL loads if the name explicitly matches a malicious string.
                // This prevents extreme false positives for legitimate unsinged DLLs.
                if (!g_alertedPids.count(payload.processId) && g_alertCallback)
                {
                    std::wstring filename = GetFilenameFromPath(payload.imagePath);
                    std::transform(filename.begin(), filename.end(), filename.begin(), ::towlower);
                    if (filename.find(L"malicious") != std::wstring::npos ||
                        filename.find(L"inject")    != std::wstring::npos ||
                        filename.find(L"payload")   != std::wstring::npos ||
                        filename.find(L"hook")      != std::wstring::npos)
                    {
                        g_alertedPids.insert(payload.processId);

                        InjectionAlertEvent alert;
                        alert.sourcePid = 0;
                        alert.targetPid = payload.processId;
                        alert.dllPath = payload.imagePath;
                        alert.technique = "LoadLibrary Injection";
                        alert.severity = "High";
                        EnrichAlert(alert);
                        g_alertCallback(alert);
                    }
                }
            }
        }
        return;
    }

    // ── Kernel-Thread: thread creation (detect remote threads) ─────────
    // Opcode 1 = Thread Start
    if (opcode == OPCODE_THREAD_START)
    {
        ULONG threadPid = 0;   // PID the new thread belongs to
        ULONG threadId = 0;
        ULONG callerPid = 0;   // PID that created the thread

        // In kernel thread events: ProcessId = target, but the header
        // EventHeader.ProcessId is the calling process.
        callerPid = event->EventHeader.ProcessId;
        GetPropertyUInt32(event, L"ProcessId", threadPid);
        GetPropertyUInt32(event, L"TThreadId", threadId);
        if (threadId == 0)
            GetPropertyUInt32(event, L"ThreadId", threadId);

        if (threadPid == 0 || callerPid == 0)
            return;

        // Detect REMOTE thread creation: caller PID != target PID
        if (callerPid != threadPid && callerPid != 0 && callerPid != 4 /*System*/)
        {
            std::lock_guard<std::mutex> lk(g_detectionMutex);

            RemoteThreadRecord rec;
            rec.sourcePid = callerPid;
            rec.threadId = threadId;
            rec.timestamp = GetTickCount64();
            g_remoteThreads[threadPid].push_back(rec);

            // Immediately try to correlate with existing suspicious DLL loads
            TryCorrelate(threadPid);

            PruneOldRecords();
        }
        return;
    }

    // ── Kernel-Process: process creation ───────────────────────────────
    // Opcode 1 = Process Start, Opcode 2 = Process End
    if (opcode == OPCODE_PROCESS_START || opcode == OPCODE_PROCESS_END)
    {
        ULONG pid = 0;
        GetPropertyUInt32(event, L"ProcessId", pid);

        if (opcode == OPCODE_PROCESS_START && pid != 0)
        {
            std::lock_guard<std::mutex> lk(g_detectionMutex);

            // Track parent PID (from event header = calling process)
            DWORD parentPid = event->EventHeader.ProcessId;
            g_processParents[pid] = parentPid;

            // Track image path
            std::wstring imageName;
            if (GetPropertyString(event, L"ImageFileName", imageName))
                g_processImagePaths[pid] = imageName;
        }

        if (opcode == OPCODE_PROCESS_END && pid != 0)
        {
            // Clean up tracking state for exited processes
            std::lock_guard<std::mutex> lk(g_detectionMutex);
            g_processBaseline.erase(pid);
            g_remoteThreads.erase(pid);
            g_suspiciousDlls.erase(pid);
            g_alertedPids.erase(pid);
            g_alertedRemoteThreads.erase(pid);
            g_processParents.erase(pid);
            g_processImagePaths.erase(pid);
        }
        return;
    }
}

// ── Session management ──────────────────────────────────────────────────────

bool StartEtwSession(ImageLoadCallback callback)
{
    if (g_running.exchange(true))
        return false;

    g_callback = std::move(callback);
    g_sessionStartTick = GetTickCount64();
    g_baselinePhase = true;

    const ULONG propertiesSize = sizeof(EVENT_TRACE_PROPERTIES) + (MAX_PATH * sizeof(wchar_t));
    g_properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(calloc(1, propertiesSize));
    if (!g_properties)
    {
        g_running.store(false);
        return false;
    }

    g_properties->Wnode.BufferSize = propertiesSize;
    g_properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_properties->Wnode.Guid = g_SystemTraceGuid;   // Manual GUID definition
    g_properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    // ── 4 Kernel Providers ─────────────────────────────────────────────
    g_properties->EnableFlags =
        EVENT_TRACE_FLAG_PROCESS               // Kernel-Process
        | EVENT_TRACE_FLAG_THREAD              // Kernel-Thread
        | EVENT_TRACE_FLAG_IMAGE_LOAD          // Kernel-Image
        | EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS; // Kernel-Memory

    g_properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTrace(&g_sessionHandle, KERNEL_LOGGER_NAME, g_properties);
    if (status == ERROR_ALREADY_EXISTS)
    {
        ControlTrace(0, KERNEL_LOGGER_NAME, g_properties, EVENT_TRACE_CONTROL_STOP);
        status = StartTrace(&g_sessionHandle, KERNEL_LOGGER_NAME, g_properties);
    }

    if (status != ERROR_SUCCESS)
    {
        StopEtwSession();
        return false;
    }

    EVENT_TRACE_LOGFILEW trace = {};
    trace.LoggerName = const_cast<LPWSTR>(KERNEL_LOGGER_NAME);
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = EventRecordCallback;

    g_traceHandle = OpenTrace(&trace);
    if (g_traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        StopEtwSession();
        return false;
    }

    // This call BLOCKS until StopEtwSession() is called
    ProcessTrace(&g_traceHandle, 1, nullptr, nullptr);
    StopEtwSession();
    return true;
}

void StopEtwSession()
{
    if (!g_running.exchange(false))
        return;

    if (g_traceHandle && g_traceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(g_traceHandle);
        g_traceHandle = 0;
    }

    if (g_sessionHandle)
    {
        if (g_properties)
            ControlTrace(g_sessionHandle, KERNEL_LOGGER_NAME, g_properties, EVENT_TRACE_CONTROL_STOP);
        g_sessionHandle = 0;
    }

    if (g_properties)
    {
        free(g_properties);
        g_properties = nullptr;
    }

    // Clear detection state
    {
        std::lock_guard<std::mutex> lk(g_detectionMutex);
        g_processBaseline.clear();
        g_remoteThreads.clear();
        g_suspiciousDlls.clear();
        g_alertedPids.clear();
        g_alertedRemoteThreads.clear();
        g_processParents.clear();
        g_processImagePaths.clear();
    }
}