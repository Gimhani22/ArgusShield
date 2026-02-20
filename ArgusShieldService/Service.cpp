#include <windows.h>
#include <fstream>
#include <string>

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;
HANDLE hServiceThread = NULL;
bool g_Running = true;

void WriteLog(const std::string& message)
{
    std::ofstream log("C:\\TestServiceLog.txt", std::ios::app);
    log << message << std::endl;
    log.close();
}

DWORD WINAPI ServiceThread(LPVOID lpParam)
{
    while (g_Running)
    {
        WriteLog("Test Service is running...");
        Sleep(5000); // Sleep for 5 seconds
    }

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

    hStatus = RegisterServiceCtrlHandler(L"TestService", ServiceCtrlHandler);
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
        { (LPWSTR)L"TestService", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    StartServiceCtrlDispatcher(ServiceTable);

    return 0;
}