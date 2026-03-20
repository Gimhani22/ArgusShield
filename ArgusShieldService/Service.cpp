#include <windows.h>
#include <fstream>
#include <string>
#include <sstream>
#include <ctime>

#include "ETWConsumer.h"
#include "PipeServer.h"

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;
HANDLE hServiceThread = NULL;
bool g_Running = true;
HANDLE g_EtwThread = NULL;
PipeServer g_PipeServer;

// ── Paths ───────────────────────────────────────────────────────────────────

static std::wstring g_DataDir;

static void InitPaths()
{
    wchar_t programData[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
    if (len == 0)
        wcscpy_s(programData, L"C:\\ProgramData");

    g_DataDir = std::wstring(programData) + L"\\ArgusShield";
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

// ── Service log ─────────────────────────────────────────────────────────────

void WriteLog(const std::string& message)
{
    std::wstring logPath = g_DataDir + L"\\service.log";
    std::ofstream log(logPath, std::ios::app);
    if (log.is_open())
    {
        log << "[" << CurrentTimestamp() << "] " << message << std::endl;
        log.close();
    }
}

// ── Shared events database (events.log) ─────────────────────────────────────
// Format: TIMESTAMP|COMPONENT|TYPE|PID|TARGET_PID|DLL_PATH|TECHNIQUE|SEVERITY|ACTION|DETAILS
// Both Service and Agent append to this file.  Dashboard reads it.

static void WriteEvent(
    const std::string& component,
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
          << component << "|"
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

// ── String helpers ──────────────────────────────────────────────────────────

static std::string WideToUtf8(const std::wstring& text)
{
    if (text.empty()) return std::string();
    int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return std::string();
    std::string result(needed - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, &result[0], needed, nullptr, nullptr);
    return result;
}

// ── ETW thread ──────────────────────────────────────────────────────────────

static DWORD WINAPI EtwThread(LPVOID)
{
    // Register injection alert callback
    SetInjectionAlertCallback([](const InjectionAlertEvent& alert)
    {
        std::string dllPathUtf8 = WideToUtf8(alert.dllPath);

        // 1. Write to shared events database
        WriteEvent("Service", "DETECTION",
            alert.sourcePid, alert.targetPid,
            dllPathUtf8, alert.technique, alert.severity,
            "Detected", "Injection detected by ETW");

        // 2. Send alert through pipe to Agent
        std::ostringstream line;
        line << "InjectionAlert"
             << "|source_pid=" << alert.sourcePid
             << "|target_pid=" << alert.targetPid
             << "|thread_id=" << alert.remoteThreadId
             << "|dll_path=" << dllPathUtf8
             << "|technique=" << alert.technique
             << "|severity=" << alert.severity
             << "\n";
        g_PipeServer.Send(line.str());

        // 3. Write to service log
        WriteLog("ALERT: " + alert.severity + " — " + alert.technique
                 + " injection detected. Source PID=" + std::to_string(alert.sourcePid)
                 + " Target PID=" + std::to_string(alert.targetPid)
                 + " DLL=" + dllPathUtf8);
    });

    // Start the ETW session with 4 kernel providers (blocks until stopped)
    StartEtwSession([](const ImageLoadEvent& evt)
    {
        // Forward all image-load events to the Agent via pipe
        std::ostringstream line;
        line << "ImageLoad"
             << "|pid=" << evt.processId
             << "|base=0x" << std::hex << evt.imageBase
             << "|size=" << std::dec << evt.imageSize
             << "|path=" << WideToUtf8(evt.imagePath)
             << "\n";
        g_PipeServer.Send(line.str());
    });

    return ERROR_SUCCESS;
}

// ── Service thread ──────────────────────────────────────────────────────────

DWORD WINAPI ServiceThread(LPVOID lpParam)
{
    WriteLog("ArgusShield Service initialized (4 kernel providers: Process, Thread, Image, Memory)");

    g_PipeServer.Start();
    g_EtwThread = CreateThread(nullptr, 0, EtwThread, nullptr, 0, nullptr);

    while (g_Running)
    {
        Sleep(5000);
    }

    StopEtwSession();

    if (g_EtwThread)
    {
        WaitForSingleObject(g_EtwThread, 5000);
        CloseHandle(g_EtwThread);
        g_EtwThread = NULL;
    }

    g_PipeServer.Stop();

    WriteLog("ArgusShield Service stopped.");
    return ERROR_SUCCESS;
}

// ── Service control ─────────────────────────────────────────────────────────

void WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
    switch (CtrlCode)
    {
    case SERVICE_CONTROL_STOP:
        ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(hStatus, &ServiceStatus);

        g_Running = false;
        StopEtwSession();
        WaitForSingleObject(hServiceThread, INFINITE);

        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        break;

    default:
        break;
    }
}

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv)
{
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    hStatus = RegisterServiceCtrlHandler(L"ArgusShieldService", ServiceCtrlHandler);
    if (hStatus == NULL)
        return;

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    hServiceThread = CreateThread(NULL, 0, ServiceThread, NULL, 0, NULL);
}

int main()
{
    InitPaths();

    SERVICE_TABLE_ENTRY ServiceTable[] =
    {
        { (LPWSTR)L"ArgusShieldService", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    StartServiceCtrlDispatcher(ServiceTable);
    return 0;
}