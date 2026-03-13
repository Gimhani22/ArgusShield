#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>

TRACEHANDLE sessionHandle = 0;
TRACEHANDLE traceHandle = 0;

void WINAPI EventRecordCallback(PEVENT_RECORD event)
{
    printf("Event Received from Provider: %lu\n",
           event->EventHeader.ProviderId);
}

void StartETWSession()
{
    EVENT_TRACE_PROPERTIES* properties;
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);

    properties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    ZeroMemory(properties, bufferSize);

    properties->Wnode.BufferSize = bufferSize;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    StartTrace(&sessionHandle, KERNEL_LOGGER_NAME, properties);

    EnableTraceEx2(
        sessionHandle,
        &ImageLoadGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL
    );

    EVENT_TRACE_LOGFILE trace;
    ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));

    trace.LoggerName = KERNEL_LOGGER_NAME;
    trace.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME |
        PROCESS_TRACE_MODE_EVENT_RECORD;

    trace.EventRecordCallback = EventRecordCallback;

    traceHandle = OpenTrace(&trace);

    ProcessTrace(&traceHandle, 1, NULL, NULL);
}