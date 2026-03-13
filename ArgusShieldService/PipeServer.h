#pragma once

#include <windows.h>
#include <string>

class PipeServer
{
public:
	PipeServer();
	~PipeServer();

	bool Start();
	void Stop();
	void Send(const std::string& message);

private:
	static DWORD WINAPI ConnectThread(LPVOID param);
	void ConnectLoop();

	HANDLE pipeHandle_;
	HANDLE threadHandle_;
	CRITICAL_SECTION lock_;
	bool running_;
	bool connected_;
};
