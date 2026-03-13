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

static std::string WideToUtf8(const std::wstring& text)
{
    if (text.empty())
        return std::string();

    int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return std::string();

    std::string result(needed - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, &result[0], needed, nullptr, nullptr);
    return result;
}

static DWORD WINAPI EtwThread(LPVOID)
{
    StartEtwSession([](const ImageLoadEvent& evt)
    {
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

DWORD WINAPI ServiceThread(LPVOID lpParam)
{
    WriteLog("ArgusShield initialized");

    g_PipeServer.Start();
    g_EtwThread = CreateThread(nullptr, 0, EtwThread, nullptr, 0, nullptr);

    while (g_Running)
    {
        Sleep(5000); // Sleep for 5 seconds
    }

    StopEtwSession();

    if (g_EtwThread)
    {
        WaitForSingleObject(g_EtwThread, INFINITE);
        CloseHandle(g_EtwThread);
        g_EtwThread = NULL;
    }

    g_PipeServer.Stop();

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
    SERVICE_TABLE_ENTRY ServiceTable[] =
    {
        { (LPWSTR)L"ArgusShieldService", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    StartServiceCtrlDispatcher(ServiceTable);

    return 0;
}