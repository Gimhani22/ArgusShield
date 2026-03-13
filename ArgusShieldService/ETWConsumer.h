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

using ImageLoadCallback = std::function<void(const ImageLoadEvent&)>;

// Starts a kernel ETW session to capture image load events.
// This call blocks until StopEtwSession() is called.
bool StartEtwSession(ImageLoadCallback callback);
void StopEtwSession();
