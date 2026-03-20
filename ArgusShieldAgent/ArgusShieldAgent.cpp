// ============================================================================
// ArgusShield Agent — Windows Service
//
// Runs as LocalSystem (admin privileges), auto-starts on boot.
// Receives injection alerts from ArgusShieldService via named pipe,
// validates and BLOCKS the attack by terminating the malicious process,
// then forwards alerts + actions to the Dashboard pipe.
// Both detection and blocking actions are written to the shared events.log
// database file.
// ============================================================================

#include <windows.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_set>

// ── Pipe names ──────────────────────────────────────────────────────────────
static const wchar_t* kServicePipe     = L"\\\\.\\pipe\\ArgusShieldEtw";
static const wchar_t* kDashboardPipe   = L"\\\\.\\pipe\\ArgusShieldAgent";

// ── Service globals ─────────────────────────────────────────────────────────
static SERVICE_STATUS        g_ServiceStatus;
static SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
static HANDLE                g_StopEvent = NULL;
static bool                  g_Running = true;

// ── Known system processes (not to be terminated) ───────────────────────────
static const std::unordered_set<std::string> g_SystemProcesses = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe",
    "explorer.exe", "taskhostw.exe", "runtimebroker.exe",
    "searchindexer.exe", "securityhealthservice.exe",
    "argusshieldservice.exe", "argusshieldagent.exe"
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

// ── Process name lookup ─────────────────────────────────────────────────────

static std::string GetProcessName(DWORD pid)
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

    std::string fullPath(path);
    auto pos = fullPath.find_last_of("\\/");
    if (pos != std::string::npos)
        return fullPath.substr(pos + 1);
    return fullPath;
}

// ── Legitimacy check ────────────────────────────────────────────────────────
// Returns true if the injection should be SKIPPED (not blocked).

static bool IsLegitimate(DWORD sourcePid, DWORD targetPid, const std::string& dllPath)
{
    // Self-injection is always legitimate
    if (sourcePid == targetPid && sourcePid != 0)
        return true;

    // System PID 4 is the kernel — ignore
    if (sourcePid == 4)
        return true;

    // Check if source is a known system process
    std::string sourceName = GetProcessName(sourcePid);
    if (!sourceName.empty())
    {
        std::string lower = sourceName;
        for (auto& c : lower) c = (char)tolower(c);
        if (g_SystemProcesses.count(lower))
            return true;
    }

    // DLL from trusted path is often legitimate
    std::string lowerDll = dllPath;
    for (auto& c : lowerDll) c = (char)tolower(c);
    if (lowerDll.find("\\windows\\system32\\") != std::string::npos ||
        lowerDll.find("\\windows\\syswow64\\") != std::string::npos ||
        lowerDll.find("\\program files\\")     != std::string::npos ||
        lowerDll.find("\\program files (x86)\\") != std::string::npos)
    {
        return true;
    }

    return false;
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
        DWORD sourcePid = (DWORD)atoi(GetField(line, "source_pid").c_str());
        DWORD targetPid = (DWORD)atoi(GetField(line, "target_pid").c_str());
        DWORD threadId  = (DWORD)atoi(GetField(line, "thread_id").c_str());
        std::string dllPath   = GetField(line, "dll_path");
        std::string technique = GetField(line, "technique");
        std::string severity  = GetField(line, "severity");

        Log("INJECTION ALERT: " + technique + " [" + severity + "]"
            + " Source=" + std::to_string(sourcePid)
            + " Target=" + std::to_string(targetPid)
            + " DLL=" + dllPath);

        // ── Step 1: Legitimacy check (fast, no delays) ─────────────────
        if (IsLegitimate(sourcePid, targetPid, dllPath))
        {
            Log("SKIP: Injection appears legitimate (system process or trusted path)");

            WriteEvent("SKIPPED", sourcePid, targetPid,
                dllPath, technique, severity,
                "Skipped", "Legitimate injection — not blocked");

            // Still forward to Dashboard for visibility
            SendToDashboard(line + "|action=Allowed\n");
            return;
        }

        // ── Step 2: BLOCK — terminate the malicious process ────────────
        bool blocked = BlockInjection(sourcePid, targetPid, threadId);

        std::string action = blocked ? "Blocked" : "DetectedOnly";
        std::string details = blocked
            ? "Injector terminated, remote thread killed"
            : "Could not terminate — process may have exited";

        // ── Step 3: Write to shared events database ────────────────────
        WriteEvent("BLOCKING", sourcePid, targetPid,
            dllPath, technique, severity,
            action, details);

        // ── Step 4: Forward to Dashboard with action result ────────────
        std::ostringstream dashMsg;
        dashMsg << "InjectionAlert"
                << "|source_pid=" << sourcePid
                << "|target_pid=" << targetPid
                << "|dll_path=" << dllPath
                << "|technique=" << technique
                << "|severity=" << severity
                << "|action=" << action
                << "\n";
        SendToDashboard(dashMsg.str());

        Log(action + ": " + details);
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
    Log("ArgusShield Agent started (Windows Service, admin privileges)");

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
