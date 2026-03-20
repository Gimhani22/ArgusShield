#pragma once

#include <windows.h>
#include <functional>
#include <string>

struct ImageLoadEvent
{
	DWORD processId = 0;
	ULONG64 imageBase = 0;
	ULONG imageSize = 0;
	std::wstring imagePath;
};

// Raised when the ETW consumer detects a suspicious cross-process DLL load
// that matches the LoadLibrary injection pattern.
struct InjectionAlertEvent
{
	DWORD  sourcePid = 0;      // PID that triggered the load (injector)
	DWORD  targetPid = 0;      // PID that received the DLL
	std::wstring dllPath;      // Full path of the injected DLL
	std::string  technique;    // e.g. "LoadLibrary"
	std::string  severity;     // "Critical", "High", "Medium", "Low"
};

using ImageLoadCallback      = std::function<void(const ImageLoadEvent&)>;
using InjectionAlertCallback  = std::function<void(const InjectionAlertEvent&)>;

// Starts a kernel ETW session to capture image load events.
// This call blocks until StopEtwSession() is called.
bool StartEtwSession(ImageLoadCallback callback);
void StopEtwSession();

// Register a callback that fires when a suspicious injection is detected.
void SetInjectionAlertCallback(InjectionAlertCallback callback);
