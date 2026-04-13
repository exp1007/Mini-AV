/*++

Module Name:

    MiniAvComm.h

Abstract:

    Prototypes for Mini-AV user-mode port callbacks and IRP_MJ_CREATE pre-callback.

Environment:

    Kernel mode

--*/

#pragma once

#include <fltKernel.h>

FLT_PREOP_CALLBACK_STATUS
PtPreOperationCreateMiniAv (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

NTSTATUS
PtMiniAvConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    );

VOID
PtMiniAvDisconnect (
    _In_opt_ PVOID ConnectionCookie
    );

NTSTATUS
PtMiniAvMessageNotify (
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );
