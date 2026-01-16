#include "Protections.h"
#include "../Config.h"
#include "../Utils/Utils.h"

#include <Windows.h>
#include <stdio.h>
#include <set>

// https://cplusplus.com/forum/windows/95774/

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
typedef NTSTATUS(NTAPI* _NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;


PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName) {
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

struct HandleEntity {
    DWORD PID;
    uint16_t Handle;
    std::string Name;
    DWORD AccessMask;

    bool operator<(const HandleEntity& other) const {
        return Handle < other.Handle;
    }
    bool operator==(const HandleEntity& other) const {
        return Handle == other.Handle && PID == other.PID;
    }
};

// Handle enumeration from https://cplusplus.com/forum/windows/95774/
void GetHandles(DWORD PID,  std::string TargetProcName, std::set<HandleEntity>* HandlesList) {
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress((char*)("ntdll.dll"), (char*)("NtQuerySystemInformation"));
    _NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetLibraryProcAddress((char*)("ntdll.dll"), (char*)("NtDuplicateObject"));
    _NtQueryObject NtQueryObject = (_NtQueryObject)GetLibraryProcAddress((char*)("ntdll.dll"), (char*)("NtQueryObject"));

    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = 0x10000;
    HANDLE processHandle;
    ULONG i;

    if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, PID)))
        printf("Could not open PID %d! (Don't try to open a system process.)\n", PID);

    handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

    /* NtQuerySystemInformation won't give us the correct buffer size,
       so we guess by doubling the buffer size. */
    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        handleInfo,
        handleInfoSize,
        NULL
    )) == STATUS_INFO_LENGTH_MISMATCH)
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
    /* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */

    if (!NT_SUCCESS(status)) {
        printf("NtQuerySystemInformation failed!\n");
        return;
    }

    for (i = 0; i < handleInfo->HandleCount; i++) {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];
        HANDLE dupHandle = NULL;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        PVOID objectNameInfo;
        UNICODE_STRING objectName;
        ULONG returnLength;

        /* Check if this handle belongs to the PID the user specified. */
        if (handle.ProcessId != PID)
            continue;

        /* Duplicate the handle so we can query it. */
        NtDuplicateObject(
            processHandle,
            (void*)handle.Handle,
            GetCurrentProcess(),
            &dupHandle,
            0,
            0,
            DUPLICATE_SAME_ACCESS
        );

        /* Query the object type. */
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL
        ))) {
            CloseHandle(dupHandle);
            continue;
        }

        /* Query the object name (unless it has an access of
           0x0012019f, on which NtQueryObject could hang. */
        if (handle.GrantedAccess == 0x0012019f) {
            free(objectTypeInfo);
            CloseHandle(dupHandle);
            continue;
        }

        objectNameInfo = malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(dupHandle,ObjectNameInformation,objectNameInfo,0x1000, &returnLength))) {
            /* Reallocate the buffer and try again. */
            objectNameInfo = realloc(objectNameInfo, returnLength);
            if (!NT_SUCCESS(NtQueryObject(
                dupHandle,
                ObjectNameInformation,
                objectNameInfo,
                returnLength,
                NULL
            )))
            {
                free(objectTypeInfo);
                free(objectNameInfo);
                CloseHandle(dupHandle);
                continue;
            }
        }

        /* Cast our buffer into an UNICODE_STRING. */
        objectName = *(PUNICODE_STRING)objectNameInfo;

        if (Utils::WideToMultiByte(objectTypeInfo->Name.Buffer) == "Process") {
            DWORD AccessedPID = GetProcessId(dupHandle);
            if (AccessedPID == Config::Data.ProtectedProc.PID) {
                HandleEntity TempHandleObj;
                TempHandleObj.Handle = handle.Handle;
                TempHandleObj.Handle = handle.ProcessId;
                TempHandleObj.Name = Utils::GetProcName(handle.ProcessId);
                HandlesList->insert(TempHandleObj);
            }
        }

        free(objectTypeInfo);
        free(objectNameInfo);
        CloseHandle(dupHandle);
    }

    free(handleInfo);
    CloseHandle(processHandle);
}

void Protections::CheckHandles() {
    static std::set<HandleEntity> OldHandles;
    std::set<HandleEntity> CurrHandles;

    CurrHandles.clear();
    for (auto proc : Protections::ProcessList) {
        if(proc.Name == "Tests.exe")
            GetHandles(proc.PID, Config::Data.ProtectedProc.Name, &CurrHandles);
    }

    if (OldHandles.size() == 0) {
        OldHandles.insert(CurrHandles.begin(), CurrHandles.end());
        return;
    }

    for (auto h : CurrHandles) {
        if(OldHandles.find(h) == OldHandles.end())
            printf("[HandleScanner] New handle (%d) accessing (%s) from process (%s) \n", h.Handle, Config::Data.ProtectedProc.Name.c_str(), h.Name.c_str());
    }
}