#include <windows.h>
#include <fstream>
#include <string>
#include <sstream>
#include <ctime>

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;
HANDLE hServiceThread = NULL;
bool g_Running = true;

// Returns C:\ProgramData\ArgusShield\service.log
// Creates the folder if it does not exist.
static std::wstring GetLogPath()
{
    wchar_t programData[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
    if (len == 0)
        wcscpy_s(programData, L"C:\\ProgramData");

    std::wstring dir = std::wstring(programData) + L"\\ArgusShield";

    // Create C:\ProgramData\ArgusShield if it doesn't already exist
    CreateDirectoryW(dir.c_str(), NULL);

    return dir + L"\\service.log";
}

static std::string CurrentTimestamp()
{
    std::time_t now = std::time(nullptr);
    char buf[32] = {};
    struct tm tm_info;
    localtime_s(&tm_info, &now);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    return std::string(buf);
}

void WriteLog(const std::string& message)
{
    static std::wstring logPath = GetLogPath();

    std::ofstream log(logPath, std::ios::app);
    if (log.is_open())
    {
        log << "[" << CurrentTimestamp() << "] " << message << std::endl;
        log.close();
    }
}

DWORD WINAPI ServiceThread(LPVOID lpParam)
{
    WriteLog("ArgusShield Service started.");

    while (g_Running)
    {
        WriteLog("ArgusShield Service is running...");
        Sleep(5000); // Sleep for 5 seconds
    }

    WriteLog("ArgusShield Service stopped.");
    return ERROR_SUCCESS;
}

void WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
    switch (CtrlCode)
    {
    case SERVICE_CONTROL_STOP:
        ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(hStatus, &ServiceStatus);

        g_Running = false;
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
    SERVICE_TABLE_ENTRY ServiceTable[] =
    {
        { (LPWSTR)L"ArgusShieldService", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    StartServiceCtrlDispatcher(ServiceTable);

    return 0;
}