#include "ETWConsumer.h"

#include <evntrace.h>
#include <tdh.h>
#include <vector>
#include <atomic>

#pragma comment(lib, "tdh.lib")

static TRACEHANDLE g_sessionHandle = 0;
static TRACEHANDLE g_traceHandle = 0;
static EVENT_TRACE_PROPERTIES* g_properties = nullptr;
static std::atomic_bool g_running{ false };
static ImageLoadCallback g_callback;

static bool FindPropertyInfo(
    const TRACE_EVENT_INFO* info,
    PCWSTR name,
    EVENT_PROPERTY_INFO* outInfo)
{
    if (!info || !name || !outInfo)
        return false;

    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
    {
        const EVENT_PROPERTY_INFO& prop = info->EventPropertyInfoArray[i];
        PCWSTR propName = (PCWSTR)((PBYTE)info + prop.NameOffset);
        if (propName && _wcsicmp(propName, name) == 0)
        {
            *outInfo = prop;
            return true;
        }
    }

    return false;
}

static bool GetPropertyBuffer(
    PEVENT_RECORD event,
    PCWSTR name,
    std::vector<BYTE>& buffer,
    EVENT_PROPERTY_INFO* outPropInfo)
{
    if (!event || !name)
        return false;

    ULONG infoSize = 0;
    ULONG status = TdhGetEventInformation(event, 0, nullptr, nullptr, &infoSize);
    if (status != ERROR_INSUFFICIENT_BUFFER)
        return false;

    std::vector<BYTE> infoBuffer(infoSize);
    auto info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
    status = TdhGetEventInformation(event, 0, nullptr, info, &infoSize);
    if (status != ERROR_SUCCESS)
        return false;

    EVENT_PROPERTY_INFO propInfo = {};
    if (!FindPropertyInfo(info, name, &propInfo))
        return false;

    PROPERTY_DATA_DESCRIPTOR desc = {};
    desc.PropertyName = (ULONGLONG)name;
    desc.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    status = TdhGetPropertySize(event, 0, nullptr, 1, &desc, &size);
    if (status != ERROR_SUCCESS || size == 0)
        return false;

    buffer.resize(size);
    status = TdhGetProperty(event, 0, nullptr, 1, &desc, size, buffer.data());
    if (status != ERROR_SUCCESS)
        return false;

    if (outPropInfo)
        *outPropInfo = propInfo;

    return true;
}

static bool GetPropertyUInt64(PEVENT_RECORD event, PCWSTR name, ULONG64& value)
{
    std::vector<BYTE> buffer;
    EVENT_PROPERTY_INFO propInfo = {};
    if (!GetPropertyBuffer(event, name, buffer, &propInfo))
        return false;

    if (buffer.size() == sizeof(ULONG64))
    {
        value = *reinterpret_cast<const ULONG64*>(buffer.data());
        return true;
    }

    if (buffer.size() == sizeof(ULONG))
    {
        value = static_cast<ULONG64>(*reinterpret_cast<const ULONG*>(buffer.data()));
        return true;
    }

    return false;
}

static bool GetPropertyUInt32(PEVENT_RECORD event, PCWSTR name, ULONG& value)
{
    ULONG64 temp = 0;
    if (!GetPropertyUInt64(event, name, temp))
        return false;
    value = static_cast<ULONG>(temp);
    return true;
}

static bool GetPropertyString(PEVENT_RECORD event, PCWSTR name, std::wstring& value)
{
    std::vector<BYTE> buffer;
    EVENT_PROPERTY_INFO propInfo = {};
    if (!GetPropertyBuffer(event, name, buffer, &propInfo))
        return false;

    USHORT inType = propInfo.nonStructType.InType;
    if (inType == TDH_INTYPE_UNICODESTRING)
    {
        value.assign(reinterpret_cast<const wchar_t*>(buffer.data()));
        return true;
    }

    if (inType == TDH_INTYPE_ANSISTRING)
    {
        std::string ansi(reinterpret_cast<const char*>(buffer.data()));
        if (!ansi.empty())
        {
            int needed = MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, nullptr, 0);
            if (needed > 0)
            {
                std::wstring wide(needed - 1, L'\0');
                MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, &wide[0], needed);
                value = wide;
                return true;
            }
        }
    }

    return false;
}

static void WINAPI EventRecordCallback(PEVENT_RECORD event)
{
    if (!g_running.load() || !g_callback)
        return;

    if (event->EventHeader.ProviderId != SystemTraceControlGuid)
        return;

    if (event->EventHeader.EventDescriptor.Opcode != EVENT_TRACE_TYPE_LOAD)
        return;

    ImageLoadEvent payload;
    GetPropertyUInt32(event, L"ProcessId", payload.processId);
    GetPropertyUInt64(event, L"ImageBase", payload.imageBase);
    GetPropertyUInt32(event, L"ImageSize", payload.imageSize);

    if (!GetPropertyString(event, L"FileName", payload.imagePath))
        GetPropertyString(event, L"ImageFileName", payload.imagePath);

    g_callback(payload);
}

bool StartEtwSession(ImageLoadCallback callback)
{
    if (g_running.exchange(true))
        return false;

    g_callback = std::move(callback);

    const ULONG propertiesSize = sizeof(EVENT_TRACE_PROPERTIES) + (MAX_PATH * sizeof(wchar_t));
    g_properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(calloc(1, propertiesSize));
    if (!g_properties)
    {
        g_running.store(false);
        return false;
    }

    g_properties->Wnode.BufferSize = propertiesSize;
    g_properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_properties->Wnode.Guid = SystemTraceControlGuid;
    g_properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_properties->EnableFlags = EVENT_TRACE_FLAG_IMAGE_LOAD;
    g_properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTrace(&g_sessionHandle, KERNEL_LOGGER_NAME, g_properties);
    if (status == ERROR_ALREADY_EXISTS)
    {
        ControlTrace(0, KERNEL_LOGGER_NAME, g_properties, EVENT_TRACE_CONTROL_STOP);
        status = StartTrace(&g_sessionHandle, KERNEL_LOGGER_NAME, g_properties);
    }

    if (status != ERROR_SUCCESS)
    {
        StopEtwSession();
        return false;
    }

    EVENT_TRACE_LOGFILEW trace = {};
    trace.LoggerName = const_cast<LPWSTR>(KERNEL_LOGGER_NAME);
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = EventRecordCallback;

    g_traceHandle = OpenTrace(&trace);
    if (g_traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        StopEtwSession();
        return false;
    }

    ProcessTrace(&g_traceHandle, 1, nullptr, nullptr);
    StopEtwSession();
    return true;
}

void StopEtwSession()
{
    if (!g_running.exchange(false))
        return;

    if (g_traceHandle && g_traceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(g_traceHandle);
        g_traceHandle = 0;
    }

    if (g_sessionHandle)
    {
        if (g_properties)
            ControlTrace(g_sessionHandle, KERNEL_LOGGER_NAME, g_properties, EVENT_TRACE_CONTROL_STOP);
        g_sessionHandle = 0;
    }

    if (g_properties)
    {
        free(g_properties);
        g_properties = nullptr;
    }
}