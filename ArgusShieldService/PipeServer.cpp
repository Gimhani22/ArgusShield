
#include "PipeServer.h"

static const wchar_t* kPipeName = L"\\\\.\\pipe\\ArgusShieldEtw";

PipeServer::PipeServer()
	: pipeHandle_(INVALID_HANDLE_VALUE)
	, threadHandle_(nullptr)
	, running_(false)
	, connected_(false)
{
	InitializeCriticalSection(&lock_);
}

PipeServer::~PipeServer()
{
	Stop();
	DeleteCriticalSection(&lock_);
}

bool PipeServer::Start()
{
	EnterCriticalSection(&lock_);
	if (running_)
	{
		LeaveCriticalSection(&lock_);
		return true;
	}

	running_ = true;
	LeaveCriticalSection(&lock_);

	threadHandle_ = CreateThread(nullptr, 0, &PipeServer::ConnectThread, this, 0, nullptr);
	return threadHandle_ != nullptr;
}

void PipeServer::Stop()
{
	EnterCriticalSection(&lock_);
	running_ = false;
	LeaveCriticalSection(&lock_);

	if (pipeHandle_ != INVALID_HANDLE_VALUE)
	{
		DisconnectNamedPipe(pipeHandle_);
		CloseHandle(pipeHandle_);
		pipeHandle_ = INVALID_HANDLE_VALUE;
	}

	if (threadHandle_)
	{
		CancelSynchronousIo(threadHandle_);
		WaitForSingleObject(threadHandle_, INFINITE);
		CloseHandle(threadHandle_);
		threadHandle_ = nullptr;
	}

	connected_ = false;
}

void PipeServer::Send(const std::string& message)
{
	EnterCriticalSection(&lock_);
	if (!connected_ || pipeHandle_ == INVALID_HANDLE_VALUE)
	{
		LeaveCriticalSection(&lock_);
		return;
	}

	DWORD bytesWritten = 0;
	BOOL ok = WriteFile(pipeHandle_, message.data(), static_cast<DWORD>(message.size()), &bytesWritten, nullptr);
	if (!ok)
	{
		DisconnectNamedPipe(pipeHandle_);
		CloseHandle(pipeHandle_);
		pipeHandle_ = INVALID_HANDLE_VALUE;
		connected_ = false;
	}

	LeaveCriticalSection(&lock_);
}

DWORD WINAPI PipeServer::ConnectThread(LPVOID param)
{
	auto server = reinterpret_cast<PipeServer*>(param);
	if (server)
		server->ConnectLoop();
	return 0;
}

void PipeServer::ConnectLoop()
{
	while (true)
	{
		EnterCriticalSection(&lock_);
		bool running = running_;
		bool connected = connected_;
		LeaveCriticalSection(&lock_);

		if (!running)
			break;

		if (!connected)
		{
			HANDLE pipe = CreateNamedPipeW(
				kPipeName,
				PIPE_ACCESS_OUTBOUND,
				PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
				1,
				4096,
				4096,
				0,
				nullptr);

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

			EnterCriticalSection(&lock_);
			pipeHandle_ = pipe;
			connected_ = true;
			LeaveCriticalSection(&lock_);
		}

		Sleep(250);
	}
}
