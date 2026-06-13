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
static ULONG gMiniAvClientPid = 0;

//
//  Run-down protection over the client port. The CREATE pre-callback holds it
//  across FltSendMessage so the port object cannot be freed mid-send; the
//  disconnect callback waits for all holders to drain before FltCloseClientPort.
//  This closes the use-after-free race that bugchecks 0x18 (REFERENCE_BY_POINTER)
//  inside FltSendMessage when a create and a disconnect run concurrently.
//
static EX_RUNDOWN_REF gMiniAvPortRundown;

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

VOID
PtMiniAvInitialize (
    VOID
    )
{
    //
    //  One-time init of the port run-down protection, before the communication
    //  port is created (so before any connect/create can reference it). Each
    //  connect re-initializes it for the new client session.
    //
    ExInitializeRundownProtection( &gMiniAvPortRundown );
}


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

    PMINIAV_CONNECT_CONTEXT ctx;

    PAGED_CODE();

    *ConnectionPortCookie = ClientPort;

    gMiniAvClientPid = 0;

    if ((ConnectionContext != NULL) &&
        (SizeOfContext >= sizeof( MINIAV_CONNECT_CONTEXT ))) {

        ctx = (PMINIAV_CONNECT_CONTEXT)ConnectionContext;

        if ((ctx->Magic == MINIAV_MSG_MAGIC) &&
            (ctx->Version == MINIAV_PROTOCOL_VERSION)) {

            gMiniAvClientPid = ctx->ClientProcessId;
        }
    }

    //
    //  The run-down protection is left armed by PtMiniAvInitialize and re-armed at
    //  the end of each PtMiniAvDisconnect, so it is already usable here. (We must
    //  not re-init it on the connect path: a create with no client may briefly hold
    //  it around the NULL-port check, and re-initializing under a live holder
    //  corrupts the count.)
    //
    (VOID)InterlockedExchangePointer( (PVOID volatile *)&gMiniAvClientPort, ClientPort );

    MiniAvLog( MINIAV_LOG_DIAG, "port: client connected (%p) pid=%lu\n", ClientPort, gMiniAvClientPid );

    return STATUS_SUCCESS;
}


VOID
PtMiniAvDisconnect (
    _In_opt_ PVOID ConnectionCookie
    )
{
    PFLT_PORT clientPort = (PFLT_PORT)ConnectionCookie;

    PAGED_CODE();

    gMiniAvClientPid = 0;

    //
    //  Stop new creates from picking up the port, then wait for every in-flight
    //  create that already acquired run-down protection (i.e. is inside or about
    //  to call FltSendMessage) to release it. Only then is it safe to close the
    //  port object — otherwise FltSendMessage would reference freed memory and
    //  bugcheck 0x18. After this returns, no create can be using the port.
    //
    (VOID)InterlockedExchangePointer( (PVOID volatile *)&gMiniAvClientPort, NULL );

    ExWaitForRundownProtectionRelease( &gMiniAvPortRundown );

    if (clientPort != NULL) {
        FltCloseClientPort( gFilterHandle, &clientPort );
    }

    //
    //  Re-arm for the next session. Safe here: the wait above completed the
    //  run-down, so no create can hold it and any concurrent acquire simply fails
    //  (fail-open) until this re-init makes it usable again.
    //
    ExReInitializeRundownProtection( &gMiniAvPortRundown );

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

    process = FltGetRequestorProcess( Data );
    if ((process != NULL) && (gMiniAvClientPid != 0)) {
        ULONG requestorPid = (ULONG)(ULONG_PTR)PsGetProcessId( process );

        if (requestorPid == gMiniAvClientPid) {

            MiniAvLog( MINIAV_LOG_DIAG, "CREATE: self-skip pid=%lu\n", requestorPid );
            PtPassthroughRequestOpStatusIfNeeded( Data );
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
    }

    //
    //  Take run-down protection for the whole port-using region below (read the
    //  port, then FltSendMessage). A failed acquire means a disconnect/teardown is
    //  already in progress, so there is no usable port -> fail open. Every return
    //  path after this point must release before returning.
    //
    if (!ExAcquireRundownProtection( &gMiniAvPortRundown )) {

        MiniAvLog( MINIAV_LOG_DIAG, "CREATE: skip (port tearing down)\n" );
        PtPassthroughRequestOpStatusIfNeeded( Data );
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    clientPort = (PFLT_PORT)InterlockedCompareExchangePointer( (PVOID volatile *)&gMiniAvClientPort,
                                                               NULL,
                                                               NULL );
    if (clientPort == NULL) {

        ExReleaseRundownProtection( &gMiniAvPortRundown );
        MiniAvLog( MINIAV_LOG_DIAG, "CREATE: skip (no client on %ls)\n", MINIAV_PORT_NAME );
        PtPassthroughRequestOpStatusIfNeeded( Data );
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    nameStatus = FltGetFileNameInformation( Data,
                                           FLT_FILE_NAME_NORMALIZED |
                                               FLT_FILE_NAME_QUERY_DEFAULT,
                                           &nameInfo );

    if (!NT_SUCCESS( nameStatus )) {

        ExReleaseRundownProtection( &gMiniAvPortRundown );
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

    //
    //  Done with the port; the reply lives in local buffers from here on. Release
    //  before the (potentially long) reply handling so disconnect isn't blocked
    //  longer than the send itself.
    //
    ExReleaseRundownProtection( &gMiniAvPortRundown );

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
