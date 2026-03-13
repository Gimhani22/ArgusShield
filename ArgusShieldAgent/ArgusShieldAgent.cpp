#include <windows.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static const wchar_t* kPipeName = L"\\\\.\\pipe\\ArgusShieldEtw";

static bool ConnectPipe(HANDLE& pipeHandle)
{
    pipeHandle = CreateFileW(
        kPipeName,
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
    if (line.rfind("ImageLoad|", 0) != 0)
        return;

    std::string pid;
    std::string base;
    std::string size;
    std::string path;

    std::istringstream stream(line);
    std::string token;
    while (std::getline(stream, token, '|'))
    {
        if (token.rfind("pid=", 0) == 0)
            pid = token.substr(4);
        else if (token.rfind("base=", 0) == 0)
            base = token.substr(5);
        else if (token.rfind("size=", 0) == 0)
            size = token.substr(5);
        else if (token.rfind("path=", 0) == 0)
            path = token.substr(5);
    }

    std::cout << "[ImageLoad] pid=" << pid
              << " base=" << base
              << " size=" << size
              << " path=" << path
              << std::endl;

    // LoadLibrary detection is based on image load events.
    // Add correlation rules here (OpenProcess -> WriteProcessMemory -> CreateRemoteThread).
}

static void ReadPipe(HANDLE pipeHandle)
{
    std::string pending;
    std::vector<char> buffer(4096);

    while (true)
    {
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(pipeHandle, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr);
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

int main()
{
    std::cout << "ArgusShield Agent: waiting for ETW service stream..." << std::endl;

    while (true)
    {
        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
        if (!ConnectPipe(pipeHandle))
        {
            Sleep(1000);
            continue;
        }

        std::cout << "Connected to ETW pipe." << std::endl;
        ReadPipe(pipeHandle);

        CloseHandle(pipeHandle);
        std::cout << "Pipe disconnected. Reconnecting..." << std::endl;
        Sleep(1000);
    }

    return 0;
}
