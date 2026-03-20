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

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

static TRACEHANDLE g_sessionHandle = 0;
static TRACEHANDLE g_traceHandle = 0;
static EVENT_TRACE_PROPERTIES* g_properties = nullptr;
static std::atomic_bool g_running{ false };
static ImageLoadCallback g_callback;
static InjectionAlertCallback g_alertCallback;

// ── Injection detection state ──────────────────────────────────────────────
// We keep a set of "known-safe" DLL directories.  Any DLL loaded from
// outside these paths is suspicious – especially when the loading event's
// thread PID differs from the target PID (cross-process image load).
// ────────────────────────────────────────────────────────────────────────────

static std::mutex g_detectionMutex;

// Track which PIDs have loaded which DLLs already (startup baseline)
static std::unordered_map<DWORD, std::unordered_set<std::wstring>> g_processBaseline;
static bool g_baselinePhase = true;   // first 5 seconds = baseline
static ULONGLONG g_sessionStartTick = 0;

// Trusted DLL directories (case-insensitive comparison done in helper)
static bool IsTrustedPath(const std::wstring& path)
{
    if (path.empty()) return true;

    // Lowercase copy
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    // System directories
    if (lower.find(L"\\windows\\system32\\") != std::wstring::npos) return true;
    if (lower.find(L"\\windows\\syswow64\\") != std::wstring::npos) return true;
    if (lower.find(L"\\windows\\winsxs\\")   != std::wstring::npos) return true;
    if (lower.find(L"\\windows\\microsoft.net\\") != std::wstring::npos) return true;

    // Common safe app paths
    if (lower.find(L"\\program files\\")     != std::wstring::npos) return true;
    if (lower.find(L"\\program files (x86)\\") != std::wstring::npos) return true;

    return false;
}

static std::wstring GetFilenameFromPath(const std::wstring& path)
{
    auto pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        return path.substr(pos + 1);
    return path;
}

void SetInjectionAlertCallback(InjectionAlertCallback callback)
{
    std::lock_guard<std::mutex> lk(g_detectionMutex);
    g_alertCallback = std::move(callback);
}

// ── TDH helpers ────────────────────────────────────────────────────────────

static bool FindPropertyInfo(
    const TRACE_EVENT_INFO* info,
    PCWSTR name,
    EVENT_PROPERTY_INFO* outInfo)
{
    if (!info || !name || !outInfo)
        return false;

    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
    {
        const EVENT_PROPERTY_INFO& prop = info->EventPropertyInfoArray[i];
        PCWSTR propName = (PCWSTR)((PBYTE)info + prop.NameOffset);
        if (propName && _wcsicmp(propName, name) == 0)
        {
            *outInfo = prop;
            return true;
        }
    }

    return false;
}

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

    EVENT_PROPERTY_INFO propInfo = {};
    if (!FindPropertyInfo(info, name, &propInfo))
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
        *outPropInfo = propInfo;

    return true;
}

static bool GetPropertyUInt64(PEVENT_RECORD event, PCWSTR name, ULONG64& value)
{
    std::vector<BYTE> buffer;
    EVENT_PROPERTY_INFO propInfo = {};
    if (!GetPropertyBuffer(event, name, buffer, &propInfo))
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

// ── ETW event callback ─────────────────────────────────────────────────────

static void WINAPI EventRecordCallback(PEVENT_RECORD event)
{
    if (!g_running.load() || !g_callback)
        return;

    if (event->EventHeader.ProviderId != SystemTraceControlGuid)
        return;

    if (event->EventHeader.EventDescriptor.Opcode != EVENT_TRACE_TYPE_LOAD)
        return;

    ImageLoadEvent payload;
    GetPropertyUInt32(event, L"ProcessId", payload.processId);
    GetPropertyUInt64(event, L"ImageBase", payload.imageBase);
    GetPropertyUInt32(event, L"ImageSize", payload.imageSize);

    if (!GetPropertyString(event, L"FileName", payload.imagePath))
        GetPropertyString(event, L"ImageFileName", payload.imagePath);

    g_callback(payload);

    // ── Injection detection logic ──────────────────────────────────────
    // During the baseline phase (first 5 s) we record what each PID loads
    // at startup.  After that, any DLL loaded from a non-trusted path that
    // hasn't been seen before is flagged as suspicious.
    // ────────────────────────────────────────────────────────────────────

    {
        std::lock_guard<std::mutex> lk(g_detectionMutex);

        ULONGLONG now = GetTickCount64();
        if (g_baselinePhase && (now - g_sessionStartTick > 5000))
            g_baselinePhase = false;

        std::wstring lowerPath = payload.imagePath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

        if (g_baselinePhase)
        {
            // Record baseline DLLs per process
            g_processBaseline[payload.processId].insert(lowerPath);
            return;
        }

        // Skip if this DLL was already in the baseline for this PID
        auto it = g_processBaseline.find(payload.processId);
        if (it != g_processBaseline.end() && it->second.count(lowerPath))
            return;

        // Add to known set so we only alert once
        g_processBaseline[payload.processId].insert(lowerPath);

        // Check if the path is non-trusted (suspicious)
        if (!IsTrustedPath(payload.imagePath))
        {
            // This is a DLL loaded from a non-standard location — flag it
            if (g_alertCallback)
            {
                InjectionAlertEvent alert;
                alert.sourcePid = 0;  // ETW image-load doesn't tell us who called LoadLibrary
                alert.targetPid = payload.processId;
                alert.dllPath   = payload.imagePath;
                alert.technique = "LoadLibrary";
                alert.severity  = "High";

                // Check for known malicious DLL names
                std::wstring filename = GetFilenameFromPath(lowerPath);
                if (filename.find(L"malicious") != std::wstring::npos ||
                    filename.find(L"inject")    != std::wstring::npos ||
                    filename.find(L"evil")      != std::wstring::npos ||
                    filename.find(L"payload")   != std::wstring::npos ||
                    filename.find(L"hook")      != std::wstring::npos)
                {
                    alert.severity = "Critical";
                }

                g_alertCallback(alert);
            }
        }
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
    g_properties->Wnode.Guid = SystemTraceControlGuid;
    g_properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_properties->EnableFlags = EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_PROCESS;
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
    }
}