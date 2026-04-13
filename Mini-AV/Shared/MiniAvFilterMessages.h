#pragma once

#define MINIAV_MSG_MAGIC          0x4D494E41ul /* 'MINA' little-endian */
#define MINIAV_PROTOCOL_VERSION   1u

#define MINIAV_PORT_NAME          L"\\MiniAvPort"
#define MINIAV_TEST_DENY_FILENAME L"MiniAvBlockTest.txt"
#define MINIAV_MAX_PATH_CHARS     512u

// Expected sizeof(MINIAV_CREATE_DECISION_REQUEST): 7 ULONGs + Path WCHAR[512] (2 bytes/WCHAR).
#define MINIAV_CREATE_DECISION_REQUEST_BYTES (7u * 4u + MINIAV_MAX_PATH_CHARS * 2u)

// Sizes of Windows filter-manager user/kernel headers (fltUserStructures.h baseline).
// Do not use sizeof(FILTER_*_HEADER) alone for wire placement in mixed TU builds.
#define MINIAV_FILTER_MESSAGE_HEADER_WIRE_BYTES 16u
#define MINIAV_FILTER_REPLY_HEADER_WIRE_BYTES   16u

typedef enum _MINIAV_MESSAGE_TYPE {
    MiniAvMsgPing = 1,
    MiniAvMsgCreateDecision = 2
} MINIAV_MESSAGE_TYPE;

typedef enum _MINIAV_OPERATION_SUBTYPE {
    MiniAvOpRead = 1,
    MiniAvOpCreateWrite = 2,
    MiniAvOpExecuteOrImage = 3
} MINIAV_OPERATION_SUBTYPE;

typedef enum _MINIAV_VERDICT {
    MiniAvVerdictAllow = 0,
    MiniAvVerdictDeny = 1
} MINIAV_VERDICT;

typedef struct _MINIAV_PING_REQUEST {
    unsigned long Magic;
    unsigned long Version;
    unsigned long MessageType;
    unsigned long Cookie;
} MINIAV_PING_REQUEST, *PMINIAV_PING_REQUEST;

typedef struct _MINIAV_PING_REPLY {
    unsigned long Magic;
    unsigned long Version;
    unsigned long CookieEcho;
    long          NtStatus;
} MINIAV_PING_REPLY, *PMINIAV_PING_REPLY;

typedef struct _MINIAV_CREATE_DECISION_REQUEST {
    unsigned long Magic;
    unsigned long Version;
    unsigned long MessageType;
    unsigned long OperationSubtype;
    unsigned long ProcessId;
    unsigned long DesiredAccess;
    unsigned long PathLengthChars;
    WCHAR         Path[MINIAV_MAX_PATH_CHARS];
} MINIAV_CREATE_DECISION_REQUEST, *PMINIAV_CREATE_DECISION_REQUEST;

typedef struct _MINIAV_CREATE_DECISION_REPLY {
    unsigned long Magic;
    unsigned long Version;
    unsigned long Verdict;
    long          NtStatusIfDeny;
    unsigned long Reserved[4];
} MINIAV_CREATE_DECISION_REPLY, *PMINIAV_CREATE_DECISION_REPLY;
