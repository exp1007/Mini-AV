/*++

Module Name:

    PassThroughPrivate.h

Abstract:

    Cross-module declarations for PassThrough.c and MiniAvComm.c (filter handle
    and pass-through helper used from CREATE pre-callback).

Environment:

    Kernel mode

--*/

#pragma once

#include <fltKernel.h>

extern PFLT_FILTER gFilterHandle;

VOID
PtPassthroughRequestOpStatusIfNeeded (
    _Inout_ PFLT_CALLBACK_DATA Data
    );
