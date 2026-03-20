#include <windows.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

// ── Pipe names ──────────────────────────────────────────────────────────────
// Service → Agent pipe  (reads ETW events from the background service)
static const wchar_t* kServicePipe = L"\\\\.\\pipe\\ArgusShieldEtw";
// Agent → Dashboard pipe  (forwards alerts to the Python dashboard)
static const wchar_t* kDashboardPipeName = L"\\\\.\\pipe\\ArgusShieldAgent";

// ── Logging ─────────────────────────────────────────────────────────────────

static std::wstring GetLogPath()
{
    wchar_t pd[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH);
    if (len == 0)
        wcscpy_s(pd, L"C:\\ProgramData");

    std::wstring dir = std::wstring(pd) + L"\\ArgusShield";
    CreateDirectoryW(dir.c_str(), NULL);
    return dir + L"\\agent.log";
}

static void Log(const std::string& msg)
{
    static std::wstring path = GetLogPath();
    std::ofstream f(path, std::ios::app);
    if (f.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char ts[64];
        sprintf_s(ts, "[%04d-%02d-%02d %02d:%02d:%02d] ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        f << ts << msg << std::endl;
    }
}

// ── Dashboard pipe (Agent → Dashboard) ──────────────────────────────────────

static HANDLE g_DashPipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_DashLock;
static bool g_DashConnected = false;

static DWORD WINAPI DashPipeThread(LPVOID)
{
    while (true)
    {
        HANDLE pipe = CreateNamedPipeW(
            kDashboardPipeName,
            PIPE_ACCESS_OUTBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 4096, 4096, 0, nullptr);

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

        // Wait until the pipe breaks (dashboard disconnects)
        while (true)
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

// ── Service pipe reader (Service → Agent) ───────────────────────────────────

static bool ConnectServicePipe(HANDLE& pipeHandle)
{
    pipeHandle = CreateFileW(
        kServicePipe,
        GENERIC_READ,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (pipeHandle == INVALID_HANDLE_VALUE)
        return false;

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipeHandle, &mode, nullptr, nullptr);
    return true;
}

static void ProcessLine(const std::string& line)
{
    // Forward injection alerts to the dashboard
    if (line.rfind("InjectionAlert|", 0) == 0)
    {
        Log("INJECTION ALERT: " + line);
        SendToDashboard(line + "\n");
        return;
    }

    // Forward image-load events to the dashboard (for live monitoring)
    if (line.rfind("ImageLoad|", 0) == 0)
    {
        SendToDashboard(line + "\n");
    }
}

static void ReadServicePipe(HANDLE pipeHandle)
{
    std::string pending;
    std::vector<char> buffer(4096);

    while (true)
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

// ── Auto-start registry helper ──────────────────────────────────────────────

static void EnsureAutoStart()
{
    // Add this agent to HKCU\...\Run so it launches automatically after login.
    HKEY hKey = NULL;
    LONG res = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_READ | KEY_WRITE, &hKey);

    if (res != ERROR_SUCCESS)
        return;

    // Check if we're already registered
    wchar_t existing[MAX_PATH] = {};
    DWORD size = sizeof(existing);
    DWORD type = 0;
    res = RegQueryValueExW(hKey, L"ArgusShieldAgent", NULL, &type, (BYTE*)existing, &size);
    if (res == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return;  // already registered
    }

    // Register current executable path
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    RegSetValueExW(hKey, L"ArgusShieldAgent", 0, REG_SZ,
                   (BYTE*)exePath, (DWORD)((wcslen(exePath) + 1) * sizeof(wchar_t)));

    RegCloseKey(hKey);
    Log("Auto-start registry entry created");
}

// ── Entry point (WinMain — no console window) ───────────────────────────────

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    // Prevent multiple instances
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"ArgusShieldAgentMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(hMutex);
        return 0;
    }

    Log("ArgusShield Agent starting...");
    EnsureAutoStart();

    InitializeCriticalSection(&g_DashLock);

    // Start the Dashboard pipe server thread
    CreateThread(nullptr, 0, DashPipeThread, nullptr, 0, nullptr);

    // Main loop: connect to the service pipe and read events
    while (true)
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

    DeleteCriticalSection(&g_DashLock);
    CloseHandle(hMutex);
    return 0;
}
