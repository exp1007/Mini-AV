/*++

Module Name:

    MiniAvComm.c

Abstract:

    Mini-AV user-mode communication: FltCreateCommunicationPort (connect, ping),
    and IRP_MJ_CREATE policy via FltSendMessage / user reply.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include "MiniAvFilterMessages.h"
#include "PassThroughPrivate.h"
#include "MiniAvComm.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//
//  FltSendMessage reply buffer is custom payload only (scanner pattern).
//

C_ASSERT( sizeof( FILTER_REPLY_HEADER ) == MINIAV_FILTER_REPLY_HEADER_WIRE_BYTES );
C_ASSERT( sizeof( MINIAV_CREATE_DECISION_REQUEST ) == MINIAV_CREATE_DECISION_REQUEST_BYTES );
C_ASSERT( sizeof( MINIAV_CREATE_DECISION_REPLY ) == 32 );

static PFLT_PORT gMiniAvClientPort = NULL;

#define MINIAV_DRV_LOG_LEVEL   DPFLTR_WARNING_LEVEL
#define MINIAV_LOG_DENY        0x00000001ul
#define MINIAV_LOG_DIAG        0x00000002ul

#ifndef MINIAV_LOG_DEFAULT
#define MINIAV_LOG_DEFAULT     MINIAV_LOG_DENY
#endif

ULONG gMiniAvLogFlags = MINIAV_LOG_DEFAULT;

#define MiniAvLog( _mask, _fmt, ... )                          \
    do {                                                       \
        if (FlagOn( gMiniAvLogFlags, (_mask) )) {              \
            (VOID)DbgPrintEx( DPFLTR_IHVDRIVER_ID,             \
                              MINIAV_DRV_LOG_LEVEL,            \
                              "[PassThrough:MiniAv] " _fmt,    \
                              ##__VA_ARGS__ );                 \
        }                                                      \
    } while (0)

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, PtMiniAvConnect)
#pragma alloc_text(PAGE, PtMiniAvDisconnect)
#endif

static
ULONG
PtMiniAvClassifyCreateSubtype (
    _Inout_ PFLT_CALLBACK_DATA Data
    )
{
    ACCESS_MASK desiredAccess = 0;
    ULONG disposition;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    if (iopb->Parameters.Create.SecurityContext != NULL) {
        desiredAccess = iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }

    disposition = (iopb->Parameters.Create.Options >> 24) & 0xFFUL;

    if (BooleanFlagOn( desiredAccess, FILE_EXECUTE ) ||
        BooleanFlagOn( desiredAccess, GENERIC_EXECUTE )) {

        return (ULONG)MiniAvOpExecuteOrImage;
    }

    if ((disposition == FILE_SUPERSEDE) ||
        (disposition == FILE_CREATE) ||
        (disposition == FILE_OVERWRITE) ||
        (disposition == FILE_OVERWRITE_IF)) {

        return (ULONG)MiniAvOpCreateWrite;
    }

    return (ULONG)MiniAvOpRead;
}


NTSTATUS
PtMiniAvConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext );

    PAGED_CODE();

    *ConnectionPortCookie = ClientPort;

    (VOID)InterlockedExchangePointer( (PVOID volatile *)&gMiniAvClientPort, ClientPort );

    MiniAvLog( MINIAV_LOG_DIAG, "port: client connected (%p)\n", ClientPort );

    return STATUS_SUCCESS;
}


VOID
PtMiniAvDisconnect (
    _In_opt_ PVOID ConnectionCookie
    )
{
    PFLT_PORT clientPort = (PFLT_PORT)ConnectionCookie;

    PAGED_CODE();

    (VOID)InterlockedExchangePointer( (PVOID volatile *)&gMiniAvClientPort, NULL );

    if (clientPort != NULL) {
        FltCloseClientPort( gFilterHandle, &clientPort );
    }

    MiniAvLog( MINIAV_LOG_DIAG, "port: client disconnected\n" );
}


NTSTATUS
PtMiniAvMessageNotify (
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PMINIAV_PING_REQUEST req;
    PMINIAV_PING_REPLY reply;

    UNREFERENCED_PARAMETER( PortCookie );

    if (ReturnOutputBufferLength != NULL) {
        *ReturnOutputBufferLength = 0;
    }

    if ((InputBuffer == NULL) ||
        (InputBufferLength < sizeof( MINIAV_PING_REQUEST )) ||
        (ReturnOutputBufferLength == NULL)) {

        return STATUS_INVALID_PARAMETER;
    }

    req = (PMINIAV_PING_REQUEST)InputBuffer;

    if ((req->Magic != MINIAV_MSG_MAGIC) ||
        (req->Version != MINIAV_PROTOCOL_VERSION) ||
        (req->MessageType != MiniAvMsgPing)) {

        return STATUS_INVALID_PARAMETER;
    }

    if ((OutputBuffer == NULL) ||
        (OutputBufferLength < sizeof( MINIAV_PING_REPLY ))) {

        return STATUS_BUFFER_TOO_SMALL;
    }

    reply = (PMINIAV_PING_REPLY)OutputBuffer;

    RtlZeroMemory( reply, sizeof( *reply ) );

    reply->Magic = MINIAV_MSG_MAGIC;
    reply->Version = MINIAV_PROTOCOL_VERSION;
    reply->CookieEcho = req->Cookie;
    reply->NtStatus = (LONG)STATUS_SUCCESS;

    *ReturnOutputBufferLength = sizeof( MINIAV_PING_REPLY );

    return STATUS_SUCCESS;
}


FLT_PREOP_CALLBACK_STATUS
PtPreOperationCreateMiniAv (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PFLT_PORT clientPort;
    MINIAV_CREATE_DECISION_REQUEST req;
    MINIAV_CREATE_DECISION_REPLY replyBody;
    ULONG replyLength;
    NTSTATUS sendStatus;
    LARGE_INTEGER timeout;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS nameStatus;
    ULONG copyChars;
    ULONG copyBytes;
    ULONG maxCopyBytes;
    PEPROCESS process;

    UNREFERENCED_PARAMETER( FltObjects );

    *CompletionContext = NULL;

    RtlZeroMemory( &replyBody, sizeof( replyBody ) );

    if (FlagOn( Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE )) {

        MiniAvLog( MINIAV_LOG_DIAG, "CREATE: skip directory\n" );
        PtPassthroughRequestOpStatusIfNeeded( Data );
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    clientPort = (PFLT_PORT)InterlockedCompareExchangePointer( (PVOID volatile *)&gMiniAvClientPort,
                                                               NULL,
                                                               NULL );
    if (clientPort == NULL) {

        MiniAvLog( MINIAV_LOG_DIAG, "CREATE: skip (no client on %ls)\n", MINIAV_PORT_NAME );
        PtPassthroughRequestOpStatusIfNeeded( Data );
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    nameStatus = FltGetFileNameInformation( Data,
                                           FLT_FILE_NAME_NORMALIZED |
                                               FLT_FILE_NAME_QUERY_DEFAULT,
                                           &nameInfo );

    if (!NT_SUCCESS( nameStatus )) {

        MiniAvLog( MINIAV_LOG_DIAG, "CREATE: skip name query 0x%08X\n", nameStatus );
        PtPassthroughRequestOpStatusIfNeeded( Data );
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    (VOID)FltParseFileNameInformation( nameInfo );

    RtlZeroMemory( &req, sizeof( req ) );
    req.Magic = MINIAV_MSG_MAGIC;
    req.Version = MINIAV_PROTOCOL_VERSION;
    req.MessageType = MiniAvMsgCreateDecision;
    req.OperationSubtype = PtMiniAvClassifyCreateSubtype( Data );
    process = FltGetRequestorProcess( Data );
    if (process != NULL) {
        req.ProcessId = (ULONG)(ULONG_PTR)PsGetProcessId( process );
    }

    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        req.DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }

    maxCopyBytes = (ULONG)((MINIAV_MAX_PATH_CHARS - 1) * sizeof( WCHAR ));
    copyBytes = nameInfo->Name.Length;
    if (copyBytes > maxCopyBytes) {
        copyBytes = maxCopyBytes;
    }

    copyBytes &= ~((ULONG)sizeof( WCHAR ) - 1);
    copyChars = copyBytes / sizeof( WCHAR );

    if ((nameInfo->Name.Buffer != NULL) && (copyBytes > 0)) {
        RtlCopyMemory( req.Path, nameInfo->Name.Buffer, copyBytes );
    }

    req.Path[copyChars] = L'\0';
    req.PathLengthChars = copyChars;

    replyLength = sizeof( replyBody );
    timeout.QuadPart = -20000000LL;

    MiniAvLog( MINIAV_LOG_DIAG, "CREATE: ask UM pid=%lu subtype=%lu\n", req.ProcessId, req.OperationSubtype );

    sendStatus = FltSendMessage( gFilterHandle,
                                 &clientPort,
                                 &req,
                                 sizeof( req ),
                                 &replyBody,
                                 &replyLength,
                                 &timeout );

    FltReleaseFileNameInformation( nameInfo );

    MiniAvLog(
        MINIAV_LOG_DIAG,
        "CREATE: FltSendMessage 0x%08X len=%lu path=%ls\n",
        sendStatus,
        replyLength,
        req.Path );

    if (!NT_SUCCESS( sendStatus ) ||
        (replyLength < sizeof( MINIAV_CREATE_DECISION_REPLY )) ||
        (replyBody.Magic != MINIAV_MSG_MAGIC) ||
        (replyBody.Version != MINIAV_PROTOCOL_VERSION)) {

        MiniAvLog(
            MINIAV_LOG_DIAG,
            "CREATE: fail-open send=0x%08X len=%lu magic=0x%08lX ver=%lu\n",
            sendStatus,
            replyLength,
            replyBody.Magic,
            replyBody.Version );

        PtPassthroughRequestOpStatusIfNeeded( Data );
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    MiniAvLog(
        MINIAV_LOG_DIAG,
        "CREATE: verdict=%lu denyStatus=0x%08lX\n",
        replyBody.Verdict,
        (ULONG)(LONG)replyBody.NtStatusIfDeny );

    if (replyBody.Verdict == MiniAvVerdictDeny) {

        NTSTATUS denyStatus = (NTSTATUS)(LONG)replyBody.NtStatusIfDeny;

        if (NT_SUCCESS( denyStatus )) {
            denyStatus = STATUS_ACCESS_DENIED;
        }

        Data->IoStatus.Status = denyStatus;
        Data->IoStatus.Information = 0;
        MiniAvLog( MINIAV_LOG_DENY, "CREATE: DENY -> COMPLETE 0x%08X\n", denyStatus );
        PtPassthroughRequestOpStatusIfNeeded( Data );
        return FLT_PREOP_COMPLETE;
    }

    MiniAvLog( MINIAV_LOG_DIAG, "CREATE: allow\n" );
    PtPassthroughRequestOpStatusIfNeeded( Data );
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}
