#pragma once
// Client-side TitanEngine SDK header for dll_tracer.
// Selectively extracts the types, constants and function declarations
// needed without depending on TitanEngine's internal headers.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

// =====================================================================
// Structures (must match TitanEngine's #pragma pack(1) layout)
// =====================================================================
#pragma pack(push, 1)

typedef struct
{
    HANDLE hFile;
    void*  BaseOfDll;
    HANDLE hFileMapping;
    void*  hFileMappingView;
    char   szLibraryPath[MAX_PATH];
    char   szLibraryName[MAX_PATH];
} LIBRARY_ITEM_DATA, *PLIBRARY_ITEM_DATA;

#pragma pack(pop)

// =====================================================================
// Constants — register indices for GetContextData
// =====================================================================
#define UE_EAX   1
#define UE_EBX   2
#define UE_ECX   3
#define UE_EDX   4
#define UE_EDI   5
#define UE_ESI   6
#define UE_EBP   7
#define UE_ESP   8
#define UE_EIP   9
#define UE_RAX  17
#define UE_RBX  18
#define UE_RCX  19
#define UE_RDX  20
#define UE_RDI  21
#define UE_RSI  22
#define UE_RBP  23
#define UE_RSP  24
#define UE_RIP  25
#define UE_CIP  35   // Generic: EIP on x86, RIP on x64
#define UE_CSP  36   // Generic: ESP on x86, RSP on x64

// =====================================================================
// Constants — SetCustomHandler event IDs
// =====================================================================
#define UE_CH_EXITPROCESS    17
#define UE_CH_LOADDLL        18
#define UE_CH_UNLOADDLL      19

// =====================================================================
// Constants — memory breakpoint access types (SetMemoryBPXEx)
// =====================================================================
#define UE_MEMORY           3
#define UE_MEMORY_READ      4
#define UE_MEMORY_WRITE     5
#define UE_MEMORY_EXECUTE   6

// =====================================================================
// Breakpoint type constants
// =====================================================================
#define UE_BREAKPOINT   0
#define UE_SINGLESHOOT  1
#define UE_HARDWARE     2

// =====================================================================
// Function declarations (imported from TitanEngine.dll)
// TITCALL is empty in TitanEngine (default calling convention)
// =====================================================================
#define TITCALL

#ifdef __cplusplus
extern "C" {
#endif

// Debugger lifecycle
__declspec(dllimport) void*  TITCALL InitDebugW(
    wchar_t* szFileName,
    wchar_t* szCommandLine,
    wchar_t* szCurrentFolder);

__declspec(dllimport) bool   TITCALL StopDebug();
__declspec(dllimport) void   TITCALL DebugLoop();

// Event handlers
__declspec(dllimport) void   TITCALL SetCustomHandler(DWORD ExceptionId, LPVOID CallBack);

// Single-step
__declspec(dllimport) void   TITCALL StepInto(LPVOID traceCallBack);

// Memory breakpoints
__declspec(dllimport) bool   TITCALL SetMemoryBPXEx(
    ULONG_PTR MemoryStart,
    SIZE_T    SizeOfMemory,
    DWORD     BreakPointType,
    bool      RestoreOnHit,
    LPVOID    bpxCallBack);

__declspec(dllimport) bool   TITCALL RemoveMemoryBPX(
    ULONG_PTR MemoryStart,
    SIZE_T    SizeOfMemory);

// Context access
__declspec(dllimport) ULONG_PTR TITCALL GetContextData(DWORD IndexOfRegister);

// Process information
__declspec(dllimport) PROCESS_INFORMATION* TITCALL TitanGetProcessInformation();

// Library/DLL information
// Returns LIBRARY_ITEM_DATA* (with char szLibraryName) or NULL
__declspec(dllimport) void* TITCALL LibrarianGetLibraryInfoEx(void* BaseOfDll);

// Disassembler — returns instruction length, or -1 on error (distorm-backed)
__declspec(dllimport) long  TITCALL LengthDisassembleEx(HANDLE hProcess, LPVOID DisassmAddress);

// Software breakpoints
__declspec(dllimport) bool  TITCALL SetBPX(ULONG_PTR bpxAddress, DWORD bpxType, LPVOID bpxCallback);
__declspec(dllimport) bool  TITCALL DeleteBPX(ULONG_PTR bpxAddress);

#ifdef __cplusplus
}
#endif
