#ifndef SYSCALLS_H
#define SYSCALLS_H


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
);

typedef unsigned __int64 QWORD;
DWORD g_NtCloseSSN;
QWORD g_NtCloseSyscall;
extern NTSTATUS NtClose(
    _In_ HANDLE Handle
);

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

extern PPEB _getPeb(void);

/**
 * @brief Retrieves the syscall number and syscall instruction address for a given NT function.
 *
 * @param NtdllHandle Handle to the loaded ntdll.dll module.
 * @param NtFunctionName Pointer to a null-terminated string with the NT function name.
 * @param NtFunctionSSN Pointer to a DWORD that will receive the system call number (SSN).
 * @param NtFunctionSyscall Pointer to a UINT_PTR that will receive the address of the syscall instruction.
 * @return BOOL Returns TRUE if there is syscall instruction at the pointed memory address, otherwise FALSE.
 */
BOOL IndirectPreludeDLL(HMODULE NtdllHandle, char NtFunctionName[], PDWORD NtFunctionSSN, PUINT_PTR NtFunctionSyscall);

/**
 * @brief Queries the process ID (PID) by process name.
 *
 * @param processName Pointer to a null-terminated string specifying the process name.
 *                    Must not be NULL.
 * @return DWORD Process ID if the process exists, otherwise returns 0.
 */
DWORD getProcessPID(const char* processName);

/**
 * @brief Retrieves the base address of ntdll.dll module by parsing the PEB.
 *
 * @return HMODULE Returns the base address of ntdll.dll if found, otherwise returns NULL.
 */
HMODULE getModuleHandle();

/**
 * @brief Retrieves the address of an exported function from a given module.
 *
 * @param module Handle to the module from which the function address will be retrieved.
 * @param target Null-terminated string representing the name of the function to locate.
 *
 * @return UINT_PTR Returns the address of the exported function if found, otherwise returns 0.
 */
UINT_PTR getAddr(HMODULE module, char target[]);

#endif
