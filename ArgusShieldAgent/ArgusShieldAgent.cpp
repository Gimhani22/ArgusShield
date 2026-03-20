// ============================================================================
// ArgusShield Agent — Windows Service  (Multi-Layer Scoring Engine)
//
// Runs as LocalSystem (admin privileges), auto-starts on boot.
// Receives injection alerts from ArgusShieldService via named pipe,
// applies a multi-layer scoring system to decide Ignore / Alert / Block,
// then forwards alerts + actions to the Dashboard pipe.
// Both detection and blocking actions are written to the shared events.log
// database file.
// ============================================================================

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <deque>
#include <algorithm>
#include <mutex>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// ── Pipe names ──────────────────────────────────────────────────────────────
static const wchar_t* kServicePipe     = L"\\\\.\\pipe\\ArgusShieldEtw";
static const wchar_t* kDashboardPipe   = L"\\\\.\\pipe\\ArgusShieldAgent";

// ── Service globals ─────────────────────────────────────────────────────────
static SERVICE_STATUS        g_ServiceStatus;
static SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
static HANDLE                g_StopEvent = NULL;
static bool                  g_Running = true;

// ── Score thresholds ────────────────────────────────────────────────────────
static const int THRESHOLD_IGNORE = 30;   // Score < 30 → Ignore
static const int THRESHOLD_ALERT  = 70;   // Score 30–70 → Alert only
                                          // Score > 70 → Block

// ── Known system/safe processes (will get negative score, never blocked) ─────
static const std::unordered_set<std::string> g_CriticalSystemProcesses = {
    // Windows core
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe",
    "taskhostw.exe", "runtimebroker.exe", "searchindexer.exe",
    "securityhealthservice.exe", "msmpeng.exe", "nissrv.exe",
    // Windows shell & UI
    "explorer.exe", "sihost.exe", "fontdrvhost.exe", "ctfmon.exe",
    "conhost.exe", "applicationframehost.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "searchui.exe", "searchapp.exe",
    "textinputhost.exe", "dllhost.exe", "taskmgr.exe", "mmc.exe",
    // Windows services & tools
    "spoolsv.exe", "lsm.exe", "wuauclt.exe", "audiodg.exe",
    "wmiprvse.exe", "wmi.exe", "trustedinstaller.exe",
    "tiworker.exe", "msiexec.exe", "consent.exe",
    "smartscreen.exe", "sgrmbroker.exe", "registry.exe",
    "dashost.exe", "devicecensus.exe", "compattelrunner.exe",
    "musnotification.exe", "backgroundtaskhost.exe",
    // ArgusShield
    "argusshieldservice.exe", "argusshieldagent.exe"
};

// ── High-risk injection targets ─────────────────────────────────────────────
static const std::unordered_set<std::string> g_HighRiskTargets = {
    "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "wininit.exe", "smss.exe"
};

static const std::unordered_set<std::string> g_MediumRiskTargets = {
    "svchost.exe", "dwm.exe", "taskhostw.exe",
    "runtimebroker.exe"
};

// ── Trusted publishers (code signing) ───────────────────────────────────────
static const std::unordered_set<std::string> g_TrustedPublishers = {
    "microsoft corporation", "microsoft windows",
    "microsoft windows hardware compatibility publisher",
    "microsoft windows publisher",
    "google llc", "google inc",
    "mozilla corporation", "mozilla foundation",
    "adobe inc.", "adobe systems incorporated",
    "oracle corporation", "oracle america, inc.",
    "apple inc.",
    "nvidia corporation",
    "intel corporation", "intel(r) software development products",
    "amd", "advanced micro devices, inc.",
    "dell inc.", "dell technologies inc.",
    "hp inc.", "hewlett-packard company",
    "lenovo", "lenovo (beijing) limited",
    "samsung electronics co., ltd.",
    "logitech", "logitech inc",
    "realtek semiconductor corp.",
    "broadcom corporation", "broadcom inc.",
    "slack technologies, inc.", "slack technologies, llc",
    "valve corp.",
    "jetbrains s.r.o.",
    "zoom video communications, inc.",
    "discord inc.",
    "spotify ab",
    "dropbox, inc.",
    "github, inc.",
    "1password",
    "nordvpn s.a.",
    "symantec corporation", "norton lifelock inc.",
    "mcafee, llc", "mcafee, inc.",
    "malwarebytes inc.", "malwarebytes corporation",
    "avast software s.r.o.",
    "eset, spol. s r.o.",
    "kaspersky lab",
    "bitdefender srl",
    "trend micro, inc.",
};

// ── Known safe tools (debuggers, browsers, AV, accessibility — negative score)
static const std::unordered_set<std::string> g_SafeDebuggers = {
    // Debuggers & dev tools
    "devenv.exe", "msvsmon.exe", "windbg.exe", "windbgx.exe",
    "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "ida.exe", "ida64.exe",
    "vscode.exe", "code.exe",
    "msbuild.exe", "vstest.console.exe", "dotnet.exe",
    // Browsers (perform cross-process operations for rendering)
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
    // Common apps that do cross-process work
    "teams.exe", "slack.exe", "discord.exe", "zoom.exe",
    "spotify.exe", "steam.exe", "epicgameslauncher.exe",
    // Accessibility & input
    "osk.exe", "magnify.exe", "narrator.exe",
    // AV / security tools (they inject for protection)
    "msmpeng.exe", "mpcmdrun.exe", "securityhealthsystray.exe",
};

// ── Suspicious parent-child pairs ───────────────────────────────────────────
struct SuspiciousParentChild
{
    std::string parent;
    std::string child;
};
static const SuspiciousParentChild g_SuspiciousPairs[] = {
    {"winword.exe",  "powershell.exe"},
    {"winword.exe",  "cmd.exe"},
    {"excel.exe",    "powershell.exe"},
    {"excel.exe",    "cmd.exe"},
    {"outlook.exe",  "powershell.exe"},
    {"mshta.exe",    "powershell.exe"},
    {"wscript.exe",  "powershell.exe"},
    {"cscript.exe",  "powershell.exe"},
};

// ── Paths ───────────────────────────────────────────────────────────────────

static std::wstring g_DataDir;

static void InitPaths()
{
    wchar_t pd[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH);
    if (len == 0)
        wcscpy_s(pd, L"C:\\ProgramData");

    g_DataDir = std::wstring(pd) + L"\\ArgusShield";
    CreateDirectoryW(g_DataDir.c_str(), NULL);
}

// ── Timestamps ──────────────────────────────────────────────────────────────

static std::string CurrentTimestamp()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[32];
    sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

// ── Logging (agent.log) ─────────────────────────────────────────────────────

static void Log(const std::string& msg)
{
    std::wstring logPath = g_DataDir + L"\\agent.log";
    std::ofstream f(logPath, std::ios::app);
    if (f.is_open())
    {
        f << "[" << CurrentTimestamp() << "] " << msg << std::endl;
    }
}

// ── Shared events database (events.log) ─────────────────────────────────────

static void WriteEvent(
    const std::string& type,
    DWORD pid,
    DWORD targetPid,
    const std::string& dllPath,
    const std::string& technique,
    const std::string& severity,
    const std::string& action,
    const std::string& details)
{
    std::wstring eventsPath = g_DataDir + L"\\events.log";
    std::ofstream f(eventsPath, std::ios::app);
    if (f.is_open())
    {
        f << CurrentTimestamp() << "|"
          << "Agent" << "|"
          << type << "|"
          << pid << "|"
          << targetPid << "|"
          << dllPath << "|"
          << technique << "|"
          << severity << "|"
          << action << "|"
          << details << std::endl;
    }
}

// ── Dashboard pipe (Agent → Dashboard) ──────────────────────────────────────

static HANDLE g_DashPipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_DashLock;
static bool g_DashConnected = false;

static DWORD WINAPI DashPipeThread(LPVOID)
{
    while (g_Running)
    {
        HANDLE pipe = CreateNamedPipeW(
            kDashboardPipe,
            PIPE_ACCESS_OUTBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 8192, 8192, 0, nullptr);

        if (pipe == INVALID_HANDLE_VALUE)
        {
            Sleep(500);
            continue;
        }

        BOOL ok = ConnectNamedPipe(pipe, nullptr);
        if (!ok && GetLastError() != ERROR_PIPE_CONNECTED)
        {
            CloseHandle(pipe);
            Sleep(500);
            continue;
        }

        Log("Dashboard connected to agent pipe");

        EnterCriticalSection(&g_DashLock);
        g_DashPipe = pipe;
        g_DashConnected = true;
        LeaveCriticalSection(&g_DashLock);

        // Wait until pipe breaks
        while (g_Running)
        {
            Sleep(1000);
            EnterCriticalSection(&g_DashLock);
            bool connected = g_DashConnected;
            LeaveCriticalSection(&g_DashLock);
            if (!connected) break;
        }

        Log("Dashboard disconnected");
    }
    return 0;
}

static void SendToDashboard(const std::string& msg)
{
    EnterCriticalSection(&g_DashLock);
    if (!g_DashConnected || g_DashPipe == INVALID_HANDLE_VALUE)
    {
        LeaveCriticalSection(&g_DashLock);
        return;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(g_DashPipe, msg.data(), (DWORD)msg.size(), &written, nullptr);
    if (!ok)
    {
        DisconnectNamedPipe(g_DashPipe);
        CloseHandle(g_DashPipe);
        g_DashPipe = INVALID_HANDLE_VALUE;
        g_DashConnected = false;
    }
    LeaveCriticalSection(&g_DashLock);
}

// ── String helpers ──────────────────────────────────────────────────────────

static std::string ToLower(const std::string& s)
{
    std::string result = s;
    for (auto& c : result) c = (char)tolower((unsigned char)c);
    return result;
}

// ── Process info helpers ────────────────────────────────────────────────────

static std::string GetProcessImagePath(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
        return "";

    char path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameA(hProcess, 0, path, &size);
    CloseHandle(hProcess);

    if (!ok || size == 0)
        return "";
    return std::string(path);
}

static std::string GetFilenameFromPath(const std::string& path)
{
    auto pos = path.find_last_of("\\/");
    if (pos != std::string::npos)
        return path.substr(pos + 1);
    return path;
}

static std::string GetProcessName(DWORD pid)
{
    return GetFilenameFromPath(GetProcessImagePath(pid));
}

static DWORD GetParentPid(DWORD pid)
{
    // Use NtQueryInformationProcess or snapshot; simplified approach via snapshot
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);
    DWORD parentPid = 0;

    if (Process32First(hSnap, &pe))
    {
        do {
            if (pe.th32ProcessID == pid)
            {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return parentPid;
}

// ══════════════════════════════════════════════════════════════════════════════
// LAYER 2 — Code Signing Validation
// ══════════════════════════════════════════════════════════════════════════════

struct SigningInfo
{
    bool isSigned = false;
    std::string signerName;
};

static SigningInfo CheckCodeSigning(const std::string& filePath)
{
    SigningInfo info;
    if (filePath.empty())
        return info;

    // Convert to wide string for WinVerifyTrust
    int wideLen = MultiByteToWideChar(CP_ACP, 0, filePath.c_str(), -1, nullptr, 0);
    if (wideLen <= 0) return info;
    std::wstring widePath(wideLen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, filePath.c_str(), -1, &widePath[0], wideLen);

    // Step 1: Verify signature with WinVerifyTrust
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = widePath.c_str();

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);
    if (status == ERROR_SUCCESS)
    {
        info.isSigned = true;
    }

    // Cleanup WinVerifyTrust state
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    if (!info.isSigned)
        return info;

    // Step 2: Extract signer name
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        widePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, &dwEncoding, &dwContentType, &dwFormatType,
        &hStore, &hMsg, NULL);

    if (ok && hStore)
    {
        PCCERT_CONTEXT pCert = CertEnumCertificatesInStore(hStore, NULL);
        if (pCert)
        {
            char name[256] = {};
            DWORD nameLen = CertGetNameStringA(
                pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0, NULL, name, sizeof(name));
            if (nameLen > 1)
                info.signerName = std::string(name);

            CertFreeCertificateContext(pCert);
        }
        CertCloseStore(hStore, 0);
    }
    if (hMsg) CryptMsgClose(hMsg);

    return info;
}

// ══════════════════════════════════════════════════════════════════════════════
// LAYER 3 — Behavior History (per-process injection tracking)
// ══════════════════════════════════════════════════════════════════════════════

static std::mutex g_HistoryMutex;

struct InjectionRecord
{
    ULONGLONG timestamp;
    DWORD targetPid;
};

// Maps source PID → list of recent injection attempts
static std::unordered_map<DWORD, std::deque<InjectionRecord>> g_InjectionHistory;

static const ULONGLONG BURST_WINDOW_MS = 10000;  // 10 seconds
static const int BURST_THRESHOLD = 3;            // 3+ injections = burst

static void RecordInjection(DWORD sourcePid, DWORD targetPid)
{
    std::lock_guard<std::mutex> lk(g_HistoryMutex);
    ULONGLONG now = GetTickCount64();

    InjectionRecord rec;
    rec.timestamp = now;
    rec.targetPid = targetPid;
    g_InjectionHistory[sourcePid].push_back(rec);

    // Prune old records
    auto& records = g_InjectionHistory[sourcePid];
    while (!records.empty() && (now - records.front().timestamp > BURST_WINDOW_MS * 2))
        records.pop_front();
}

static int GetRecentInjectionCount(DWORD sourcePid)
{
    std::lock_guard<std::mutex> lk(g_HistoryMutex);
    ULONGLONG now = GetTickCount64();
    ULONGLONG cutoff = (now > BURST_WINDOW_MS) ? (now - BURST_WINDOW_MS) : 0;

    auto it = g_InjectionHistory.find(sourcePid);
    if (it == g_InjectionHistory.end())
        return 0;

    int count = 0;
    for (auto& rec : it->second)
    {
        if (rec.timestamp >= cutoff)
            count++;
    }
    return count;
}

// ══════════════════════════════════════════════════════════════════════════════
// LAYER 4 — Threat Scoring Engine
// ══════════════════════════════════════════════════════════════════════════════

struct ScoreBreakdown
{
    int total = 0;
    std::vector<std::pair<std::string, int>> factors;

    void Add(const std::string& reason, int score)
    {
        factors.push_back({ reason, score });
        total += score;
    }

    std::string ToString() const
    {
        std::ostringstream ss;
        ss << "Score=" << total << " [";
        for (size_t i = 0; i < factors.size(); i++)
        {
            if (i > 0) ss << ", ";
            ss << factors[i].first << "=" << (factors[i].second >= 0 ? "+" : "")
               << factors[i].second;
        }
        ss << "]";
        return ss.str();
    }
};

enum class PathCategory
{
    System,        // Windows\System32, SysWOW64
    ProgramFiles,  // Program Files, Program Files (x86)
    Temp,          // Temp, AppData\Local\Temp
    AppData,       // AppData (non-temp)
    Downloads,     // Downloads folder
    Desktop,       // Desktop
    UserFolder,    // Other user locations
    Unknown
};

static PathCategory ClassifyPath(const std::string& path)
{
    std::string lower = ToLower(path);

    if (lower.find("\\windows\\system32\\") != std::string::npos ||
        lower.find("\\windows\\syswow64\\") != std::string::npos)
        return PathCategory::System;

    if (lower.find("\\program files\\") != std::string::npos ||
        lower.find("\\program files (x86)\\") != std::string::npos)
        return PathCategory::ProgramFiles;

    if (lower.find("\\temp\\") != std::string::npos ||
        lower.find("\\tmp\\") != std::string::npos ||
        lower.find("\\appdata\\local\\temp\\") != std::string::npos)
        return PathCategory::Temp;

    if (lower.find("\\downloads\\") != std::string::npos)
        return PathCategory::Downloads;

    if (lower.find("\\desktop\\") != std::string::npos)
        return PathCategory::Desktop;

    if (lower.find("\\appdata\\") != std::string::npos)
        return PathCategory::AppData;

    if (lower.find("\\users\\") != std::string::npos)
        return PathCategory::UserFolder;

    return PathCategory::Unknown;
}

static ScoreBreakdown CalculateThreatScore(
    DWORD sourcePid,
    DWORD targetPid,
    DWORD parentPid,
    const std::string& dllPath,
    const std::string& sourceImage,
    const std::string& technique)
{
    ScoreBreakdown score;

    // ── Immediate safe returns ──────────────────────────────────────────
    // Self-injection is always safe
    if (sourcePid == targetPid && sourcePid != 0)
    {
        score.Add("SelfInjection", -100);
        return score;
    }

    // Kernel PID 4 is always safe
    if (sourcePid == 4)
    {
        score.Add("KernelPID", -100);
        return score;
    }

    // ── Get source process info ─────────────────────────────────────────
    std::string sourceImagePath = sourceImage;
    if (sourceImagePath.empty() && sourcePid != 0)
        sourceImagePath = GetProcessImagePath(sourcePid);

    std::string sourceName = GetFilenameFromPath(sourceImagePath);
    std::string sourceNameLower = ToLower(sourceName);

    // Check if source is a critical system process
    if (g_CriticalSystemProcesses.count(sourceNameLower))
    {
        score.Add("CriticalSystemProcess", -100);
        return score;
    }

    // ── Base score: injection into another process ──────────────────────
    score.Add("CrossProcessInjection", +30);

    // ── Code Signing ────────────────────────────────────────────────────
    SigningInfo signing = CheckCodeSigning(sourceImagePath);
    if (!signing.isSigned)
    {
        score.Add("UnsignedBinary", +20);
    }
    else
    {
        std::string signerLower = ToLower(signing.signerName);
        if (g_TrustedPublishers.count(signerLower))
        {
            score.Add("TrustedSigner(" + signing.signerName + ")", -50);
        }
        else
        {
            score.Add("UnknownSigner(" + signing.signerName + ")", +10);
        }
    }

    // ── Source file path category ────────────────────────────────────────
    PathCategory srcCat = ClassifyPath(sourceImagePath);
    switch (srcCat)
    {
    case PathCategory::System:
        score.Add("SourceInSystem32", -30);
        break;
    case PathCategory::ProgramFiles:
        score.Add("SourceInProgramFiles", -30);
        break;
    case PathCategory::Temp:
        score.Add("SourceInTemp", +25);
        break;
    case PathCategory::AppData:
        score.Add("SourceInAppData", +25);
        break;
    case PathCategory::Downloads:
        score.Add("SourceInDownloads", +25);
        break;
    case PathCategory::Desktop:
        score.Add("SourceOnDesktop", +15);
        break;
    case PathCategory::UserFolder:
        score.Add("SourceInUserFolder", +15);
        break;
    default:
        break;
    }

    // ── DLL path analysis ───────────────────────────────────────────────
    if (!dllPath.empty())
    {
        PathCategory dllCat = ClassifyPath(dllPath);
        if (dllCat == PathCategory::Temp || dllCat == PathCategory::AppData ||
            dllCat == PathCategory::Downloads)
        {
            score.Add("DllFromSuspiciousPath", +15);
        }

        // Check for known malicious DLL names
        std::string dllLower = ToLower(dllPath);
        if (dllLower.find("malicious") != std::string::npos ||
            dllLower.find("inject") != std::string::npos ||
            dllLower.find("payload") != std::string::npos ||
            dllLower.find("hook") != std::string::npos)
        {
            score.Add("SuspiciousDllName", +20);
        }
    }

    // ── Target risk analysis ────────────────────────────────────────────
    std::string targetName = ToLower(GetProcessName(targetPid));
    if (g_HighRiskTargets.count(targetName))
    {
        score.Add("HighRiskTarget(" + targetName + ")", +40);
    }
    else if (g_MediumRiskTargets.count(targetName))
    {
        score.Add("MediumRiskTarget(" + targetName + ")", +20);
    }

    // ── Debugger / dev tool check ───────────────────────────────────────
    if (g_SafeDebuggers.count(sourceNameLower))
    {
        score.Add("KnownDebugger(" + sourceName + ")", -40);
    }

    // ── Parent-child relationship ───────────────────────────────────────
    DWORD actualParentPid = parentPid;
    if (actualParentPid == 0 && sourcePid != 0)
        actualParentPid = GetParentPid(sourcePid);

    if (actualParentPid != 0)
    {
        std::string parentName = ToLower(GetProcessName(actualParentPid));
        for (const auto& pair : g_SuspiciousPairs)
        {
            if (parentName == pair.parent && sourceNameLower == pair.child)
            {
                score.Add("SuspiciousParentChild(" + parentName + "->" + sourceNameLower + ")", +25);
                break;
            }
        }
    }

    // ── Burst detection ─────────────────────────────────────────────────
    int recentCount = GetRecentInjectionCount(sourcePid);
    if (recentCount >= BURST_THRESHOLD)
    {
        score.Add("BurstInjection(count=" + std::to_string(recentCount) + ")", +30);
    }

    return score;
}

// ── BLOCKING — TerminateProcess on the injecting process ────────────────────

static bool BlockInjection(DWORD sourcePid, DWORD targetPid, DWORD threadId)
{
    bool blocked = false;

    // Strategy 1: Terminate the INJECTOR process (source PID)
    if (sourcePid != 0)
    {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, sourcePid);
        if (hProcess)
        {
            if (TerminateProcess(hProcess, 1))
            {
                Log("BLOCKED: Terminated injector process PID=" + std::to_string(sourcePid));
                blocked = true;
            }
            else
            {
                Log("WARN: Failed to terminate PID=" + std::to_string(sourcePid)
                    + " Error=" + std::to_string(GetLastError()));
            }
            CloseHandle(hProcess);
        }
    }

    // Strategy 2: Suspend the remote thread in the target process
    if (threadId != 0)
    {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_TERMINATE, FALSE, threadId);
        if (hThread)
        {
            SuspendThread(hThread);
            TerminateThread(hThread, 1);
            CloseHandle(hThread);
            Log("BLOCKED: Terminated remote thread ID=" + std::to_string(threadId));
            blocked = true;
        }
    }

    return blocked;
}

// ── Parse pipe message fields ───────────────────────────────────────────────

static std::string GetField(const std::string& line, const std::string& key)
{
    std::string search = key + "=";
    auto pos = line.find(search);
    if (pos == std::string::npos)
        return "";

    pos += search.size();
    auto end = line.find('|', pos);
    if (end == std::string::npos)
        end = line.size();
    return line.substr(pos, end - pos);
}

// ── Process incoming messages from the Service pipe ─────────────────────────

static void ProcessLine(const std::string& line)
{
    // ── Injection Alert from the Service ────────────────────────────────
    if (line.rfind("InjectionAlert|", 0) == 0)
    {
        DWORD sourcePid  = (DWORD)atoi(GetField(line, "source_pid").c_str());
        DWORD targetPid  = (DWORD)atoi(GetField(line, "target_pid").c_str());
        DWORD threadId   = (DWORD)atoi(GetField(line, "thread_id").c_str());
        DWORD parentPid  = (DWORD)atoi(GetField(line, "parent_pid").c_str());
        std::string dllPath     = GetField(line, "dll_path");
        std::string sourceImage = GetField(line, "source_image");
        std::string technique   = GetField(line, "technique");
        std::string severity    = GetField(line, "severity");

        Log("INJECTION ALERT: " + technique + " [" + severity + "]"
            + " Source=" + std::to_string(sourcePid)
            + " Target=" + std::to_string(targetPid)
            + " DLL=" + dllPath);

        // ── Record injection in behavior history ───────────────────────
        RecordInjection(sourcePid, targetPid);

        // ── Calculate threat score (multi-layer) ───────────────────────
        ScoreBreakdown score = CalculateThreatScore(
            sourcePid, targetPid, parentPid,
            dllPath, sourceImage, technique);

        Log("SCORING: " + score.ToString());

        // ── Decision based on score ────────────────────────────────────
        std::string decision;
        std::string action;
        std::string details;

        if (score.total < THRESHOLD_IGNORE)
        {
            // IGNORE — legitimate activity
            decision = "Ignore";
            action = "Skipped";
            details = "Score " + std::to_string(score.total) + " below threshold — legitimate";

            Log("DECISION: IGNORE (score=" + std::to_string(score.total) + ")");

            WriteEvent("SKIPPED", sourcePid, targetPid,
                dllPath, technique, severity,
                action, details);

            // Do NOT forward Ignore events to Dashboard — reduces overhead
            // and prevents unnecessary notifications for legitimate activity
            return;
        }
        else if (score.total <= THRESHOLD_ALERT)
        {
            // ALERT — suspicious but not enough to block
            decision = "Alert";
            action = "Alerted";
            details = "Score " + std::to_string(score.total) + " — suspicious, monitoring";

            Log("DECISION: ALERT (score=" + std::to_string(score.total) + ")");

            WriteEvent("ALERT", sourcePid, targetPid,
                dllPath, technique, severity,
                action, details);
        }
        else
        {
            // BLOCK — high confidence malicious
            decision = "Block";

            bool blocked = BlockInjection(sourcePid, targetPid, threadId);
            action = blocked ? "Blocked" : "DetectedOnly";
            details = blocked
                ? "Score " + std::to_string(score.total) + " — injector terminated"
                : "Score " + std::to_string(score.total) + " — could not terminate";

            Log("DECISION: BLOCK (score=" + std::to_string(score.total) + ") "
                + (blocked ? "SUCCESS" : "FAILED"));

            WriteEvent("BLOCKING", sourcePid, targetPid,
                dllPath, technique, severity,
                action, details);
        }

        // ── Forward to Dashboard with score ────────────────────────────
        std::ostringstream dashMsg;
        dashMsg << "InjectionAlert"
                << "|source_pid=" << sourcePid
                << "|target_pid=" << targetPid
                << "|dll_path=" << dllPath
                << "|technique=" << technique
                << "|severity=" << severity
                << "|action=" << action
                << "|score=" << score.total
                << "|decision=" << decision
                << "\n";
        SendToDashboard(dashMsg.str());
        return;
    }

    // ── Forward ImageLoad events to Dashboard ──────────────────────────
    if (line.rfind("ImageLoad|", 0) == 0)
    {
        SendToDashboard(line + "\n");
    }
}

// ── Service pipe reader (Service → Agent) ───────────────────────────────────

static bool ConnectServicePipe(HANDLE& pipeHandle)
{
    pipeHandle = CreateFileW(
        kServicePipe,
        GENERIC_READ,
        0, nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (pipeHandle == INVALID_HANDLE_VALUE)
        return false;

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipeHandle, &mode, nullptr, nullptr);
    return true;
}

static void ReadServicePipe(HANDLE pipeHandle)
{
    std::string pending;
    std::vector<char> buffer(8192);

    while (g_Running)
    {
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(pipeHandle, buffer.data(),
                           static_cast<DWORD>(buffer.size()), &bytesRead, nullptr);
        if (!ok || bytesRead == 0)
            break;

        pending.append(buffer.data(), buffer.data() + bytesRead);

        size_t pos = 0;
        while ((pos = pending.find('\n')) != std::string::npos)
        {
            std::string line = pending.substr(0, pos);
            pending.erase(0, pos + 1);
            if (!line.empty())
                ProcessLine(line);
        }
    }
}

// ── Worker thread (runs the actual agent logic) ─────────────────────────────

static DWORD WINAPI AgentWorkerThread(LPVOID)
{
    Log("ArgusShield Agent started (Multi-Layer Scoring Engine)");
    Log("Thresholds: Ignore<" + std::to_string(THRESHOLD_IGNORE)
        + " Alert<=" + std::to_string(THRESHOLD_ALERT)
        + " Block>" + std::to_string(THRESHOLD_ALERT));

    InitializeCriticalSection(&g_DashLock);

    // Start Dashboard pipe server thread
    HANDLE hDashThread = CreateThread(nullptr, 0, DashPipeThread, nullptr, 0, nullptr);

    // Main loop: connect to Service pipe and process events
    while (g_Running)
    {
        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
        if (!ConnectServicePipe(pipeHandle))
        {
            Sleep(2000);
            continue;
        }

        Log("Connected to ETW service pipe");
        ReadServicePipe(pipeHandle);

        CloseHandle(pipeHandle);
        Log("Service pipe disconnected. Reconnecting...");
        Sleep(2000);
    }

    // Cleanup
    if (hDashThread)
    {
        WaitForSingleObject(hDashThread, 3000);
        CloseHandle(hDashThread);
    }
    DeleteCriticalSection(&g_DashLock);

    Log("ArgusShield Agent stopped.");
    return 0;
}

// ── Windows Service entry points ────────────────────────────────────────────

void WINAPI AgentServiceCtrlHandler(DWORD CtrlCode)
{
    switch (CtrlCode)
    {
    case SERVICE_CONTROL_STOP:
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

        g_Running = false;
        if (g_StopEvent)
            SetEvent(g_StopEvent);
        break;

    default:
        break;
    }
}

void WINAPI AgentServiceMain(DWORD argc, LPWSTR* argv)
{
    g_StatusHandle = RegisterServiceCtrlHandler(L"ArgusShieldAgent", AgentServiceCtrlHandler);
    if (!g_StatusHandle)
        return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    // Start worker thread
    HANDLE hWorker = CreateThread(NULL, 0, AgentWorkerThread, NULL, 0, NULL);

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Wait for stop signal
    WaitForSingleObject(g_StopEvent, INFINITE);
    g_Running = false;

    // Wait for worker to finish
    if (hWorker)
    {
        WaitForSingleObject(hWorker, 10000);
        CloseHandle(hWorker);
    }

    CloseHandle(g_StopEvent);
    g_StopEvent = NULL;

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// ── main() — service dispatcher ─────────────────────────────────────────────

int main()
{
    InitPaths();

    SERVICE_TABLE_ENTRY ServiceTable[] =
    {
        { (LPWSTR)L"ArgusShieldAgent", (LPSERVICE_MAIN_FUNCTION)AgentServiceMain },
        { NULL, NULL }
    };

    StartServiceCtrlDispatcher(ServiceTable);
    return 0;
}
