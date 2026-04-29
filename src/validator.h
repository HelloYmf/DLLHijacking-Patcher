#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "space_calc.h"

struct ValidationResult {
    int   validated;  // 1=YES (both BPs hit), 0=TIMEOUT, -1=NO (crash/exit)
    DWORD blankFoa;   // blank region FOA (aligned start)
    DWORD blankRva;   // blank region RVA (aligned start)
    DWORD blankSize;  // blank region size after alignment
};

// Validates a single "point" by:
//   1. Creating a per-point subdirectory under tmpRoot_
//   2. Copying EXE + DLL into it
//   3. Redirecting the E8 rel32 CALL at caller_rva to blank.rva
//   4. Zero-filling the blank region in the DLL copy (strict test)
//   5. Launching a debug session with two BPs:
//        BP1 at caller_rva  (confirms CALL site is reached)
//        BP2 at blank.rva   (confirms redirect worked)
//   6. On success: saves an output copy under outputRoot_ with only the
//      CALL redirect (blank region keeps original bytes, optionally +shellcode)
//
// On success: tmp subdir deleted, output saved under outputRoot_.
// On failure: tmp subdir retained for manual inspection.
// After all calls, invoke Cleanup().
class PointValidator {
public:
    void Init(const std::wstring& exePath,
              const std::wstring& dllPath,
              const std::wstring& tmpRoot,
              const std::wstring& outputRoot,
              bool                dllIs64,
              const std::vector<BYTE>& shellcode = {});

    // callerInstrSize must be 5 and the byte at callerFoa must be 0xE8.
    // Returns validated=1 (YES), 0 (TIMEOUT), -1 (NO/SKIP).
    ValidationResult Validate(DWORD callerRva, DWORD callerInstrSize,
                               const BlankRegion& blank, int timeoutSec = 5);

    // Sweep old abandoned subdirs; retain only this-run failed dirs.
    void Cleanup();

private:
    std::wstring              exePath_;
    std::wstring              dllPath_;
    std::wstring              tmpRoot_;
    std::wstring              outputRoot_;
    bool                      dllIs64_       = false;
    std::vector<BYTE>         shellcodeBytes_;
    std::string               dllNameLower_;
    std::vector<std::wstring> failedDirs_;

    // TitanEngine callback state (static — callbacks have no user context).
    static PointValidator* g_val_;
    static bool            g_callerHit_;
    static bool            g_blankHit_;
    static bool            g_timedOut_;
    static DWORD           g_targetRva_;   // caller_rva
    static DWORD           g_blankRva_;    // blank region RVA
    static ULONG_PTR       g_dllBaseV_;    // runtime DLL base

    static void OnLoadDll(void* specialDbg);
    static void OnCallerBP(void* bpAddr);
    static void OnBlankBP(void* bpAddr);
    static void OnExitProcess(void* specialDbg);
    static DWORD WINAPI WatchdogThread(LPVOID timeoutMsPtr);

    void SaveOutput(DWORD callerRva, DWORD callerFoa,
                    const BlankRegion& blank);

    static void RemoveDirectoryContents(const std::wstring& dir);
    static bool IsDirectoryEmpty(const std::wstring& dir);
};
