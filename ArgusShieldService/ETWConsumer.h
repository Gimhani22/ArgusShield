#pragma once

#include <windows.h>
#include <functional>
#include <string>

// ── Image Load Event (Kernel-Image) ────────────────────────────────────────
struct ImageLoadEvent
{
	DWORD processId = 0;
	ULONG64 imageBase = 0;
	ULONG imageSize = 0;
	std::wstring imagePath;
};

// ── Thread Create Event (Kernel-Thread) ────────────────────────────────────
struct ThreadCreateEvent
{
	DWORD threadId = 0;
	DWORD processId = 0;       // PID that the new thread belongs to
	DWORD parentProcessId = 0; // PID that created the thread (caller)
};

// ── Process Event (Kernel-Process) ─────────────────────────────────────────
struct ProcessCreateEvent
{
	DWORD processId = 0;
	DWORD parentProcessId = 0;
	std::wstring imageName;
};

// ── Injection Alert ────────────────────────────────────────────────────────
// Raised when the ETW consumer detects a suspicious cross-process injection
// pattern (remote thread + suspicious DLL load within a short window).
struct InjectionAlertEvent
{
	DWORD  sourcePid = 0;      // PID of the injecting process
	DWORD  targetPid = 0;      // PID that received the injection
	DWORD  remoteThreadId = 0; // Thread ID of the remote thread
	std::wstring dllPath;      // Full path of the injected DLL (may be empty)
	std::string  technique;    // e.g. "LoadLibrary", "RemoteThread"
	std::string  severity;     // "Critical", "High", "Medium", "Low"
};

// ── Callbacks ──────────────────────────────────────────────────────────────
using ImageLoadCallback      = std::function<void(const ImageLoadEvent&)>;
using InjectionAlertCallback = std::function<void(const InjectionAlertEvent&)>;

// ── API ────────────────────────────────────────────────────────────────────

// Starts a kernel ETW session with 4 providers:
//   Kernel-Process, Kernel-Thread, Kernel-Image, Kernel-Memory
// This call BLOCKS until StopEtwSession() is called from another thread.
bool StartEtwSession(ImageLoadCallback callback);
void StopEtwSession();

// Register a callback that fires when a suspicious injection is detected.
void SetInjectionAlertCallback(InjectionAlertCallback callback);
