#include "validator.h"
#include "TitanEngine.h"
#include "pe_parser.h"
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

// ---- static member definitions ----

PointValidator* PointValidator::g_val_       = nullptr;
bool            PointValidator::g_callerHit_ = false;
bool            PointValidator::g_blankHit_  = false;
bool            PointValidator::g_timedOut_  = false;
DWORD           PointValidator::g_targetRva_ = 0;
DWORD           PointValidator::g_blankRva_  = 0;
ULONG_PTR       PointValidator::g_dllBaseV_  = 0;

// ---- string helpers ----

static std::string WStrToUtf8V(const std::wstring& w)
{
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (sz <= 1) return {};
    std::string s(static_cast<size_t>(sz) - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
    return s;
}

static std::string ToLowerV(const std::string& s)
{
    std::string r = s;
    for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return r;
}

// ---- Init ----

void PointValidator::Init(const std::wstring& exePath,
                           const std::wstring& dllPath,
                           const std::wstring& tmpRoot,
                           const std::wstring& outputRoot,
                           bool                dllIs64,
                           const std::vector<BYTE>& shellcode)
{
    exePath_       = exePath;
    dllPath_       = dllPath;
    tmpRoot_       = tmpRoot;
    outputRoot_    = outputRoot;
    dllIs64_       = dllIs64;
    shellcodeBytes_ = shellcode;
    dllNameLower_  = ToLowerV(WStrToUtf8V(fs::path(dllPath).filename().wstring()));
    failedDirs_.clear();
}

// ---- Directory helpers ----

void PointValidator::RemoveDirectoryContents(const std::wstring& dir)
{
    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd = {};
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            RemoveDirectoryContents(full);
            RemoveDirectoryW(full.c_str());
        } else {
            DeleteFileW(full.c_str());
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

bool PointValidator::IsDirectoryEmpty(const std::wstring& dir)
{
    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd = {};
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return true;
    bool empty = true;
    do {
        if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
            empty = false;
            break;
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return empty;
}

// ---- TitanEngine callbacks ----

static DWORD WINAPI ValDeferredStopWorker(LPVOID)
{
    Sleep(50);
    StopDebug();
    return 0;
}

static void RequestValDeferredStop()
{
    HANDLE h = CreateThread(nullptr, 0, ValDeferredStopWorker, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
}

void PointValidator::OnLoadDll(void* specialDbg)
{
    auto* info    = reinterpret_cast<LOAD_DLL_DEBUG_INFO*>(specialDbg);
    auto* libInfo = reinterpret_cast<LIBRARY_ITEM_DATA*>(
        LibrarianGetLibraryInfoEx(info->lpBaseOfDll));
    if (!libInfo) return;

    std::string loaded = ToLowerV(libInfo->szLibraryName);
    if (loaded != g_val_->dllNameLower_) return;

    g_dllBaseV_ = reinterpret_cast<ULONG_PTR>(info->lpBaseOfDll);

    ULONG_PTR callerVA = g_dllBaseV_ + g_targetRva_;
    ULONG_PTR blankVA  = g_dllBaseV_ + g_blankRva_;

    SetBPX(callerVA, UE_SINGLESHOOT, reinterpret_cast<LPVOID>(OnCallerBP));
    SetBPX(blankVA,  UE_SINGLESHOOT, reinterpret_cast<LPVOID>(OnBlankBP));
}

void PointValidator::OnCallerBP(void* /*bpAddr*/)
{
    g_callerHit_ = true;
    // Do NOT stop — continue execution so the redirected CALL can fire.
}

void PointValidator::OnBlankBP(void* /*bpAddr*/)
{
    g_blankHit_ = true;
    RequestValDeferredStop();
}

void PointValidator::OnExitProcess(void* /*specialDbg*/)
{
    // DebugLoop will return naturally; nothing extra needed.
}

DWORD WINAPI PointValidator::WatchdogThread(LPVOID timeoutMsPtr)
{
    DWORD ms = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(timeoutMsPtr));
    Sleep(ms);
    if (!g_blankHit_) {
        g_timedOut_ = true;
        StopDebug();
    }
    return 0;
}

// ---- SaveOutput ----

void PointValidator::SaveOutput(DWORD callerRva, DWORD callerFoa,
                                 const BlankRegion& blank)
{
    // Sub-directory name: <callerRva8>_<blankFoa8>_<blankSize8>
    wchar_t dirName[64];
    swprintf_s(dirName, L"%08X_%08X_%08X", callerRva, blank.foa, blank.size);
    std::wstring outDir = outputRoot_ + L"\\" + dirName;
    CreateDirectoryW(outputRoot_.c_str(), nullptr);
    CreateDirectoryW(outDir.c_str(), nullptr);

    // Copy original EXE
    std::wstring outExe = outDir + L"\\" + fs::path(exePath_).filename().wstring();
    CopyFileW(exePath_.c_str(), outExe.c_str(), FALSE);

    // Copy original DLL (blank region keeps ORIGINAL bytes)
    std::wstring outDll = outDir + L"\\" + fs::path(dllPath_).filename().wstring();
    CopyFileW(dllPath_.c_str(), outDll.c_str(), FALSE);

    // Patch output DLL: only redirect the CALL rel32 (keep blank region bytes)
    HANDLE hOut = CreateFileW(outDll.c_str(), GENERIC_WRITE,
                              0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        INT32 rel32 = static_cast<INT32>(blank.rva - (callerRva + 5));
        BYTE  patch[5] = { 0xE8 };
        memcpy(patch + 1, &rel32, 4);
        SetFilePointer(hOut, static_cast<LONG>(callerFoa), nullptr, FILE_BEGIN);
        WriteFile(hOut, patch, 5, &written, nullptr);

        // Optional: write shellcode into blank region
        if (!shellcodeBytes_.empty()) {
            if (shellcodeBytes_.size() <= static_cast<size_t>(blank.size)) {
                SetFilePointer(hOut, static_cast<LONG>(blank.foa), nullptr, FILE_BEGIN);
                WriteFile(hOut, shellcodeBytes_.data(),
                          static_cast<DWORD>(shellcodeBytes_.size()), &written, nullptr);
            } else {
                printf("[validate] WARN  shellcode %zu bytes > blank %u bytes — not written\n",
                       shellcodeBytes_.size(), blank.size);
            }
        }
        CloseHandle(hOut);

        // Neutralise base-relocation entries overlapping the blank region so the
        // loader does not patch over the injected shellcode at load time.
        PatchOutRelocEntries(outDll, blank.rva, blank.rva + blank.size);
    }

    printf("[validate] output  caller_rva=0x%08X  blank_rva=0x%08X  size=0x%X  dir=%s\n",
           callerRva, blank.rva, blank.size, WStrToUtf8V(outDir).c_str());
}

// ---- Core validation ----

ValidationResult PointValidator::Validate(DWORD callerRva, DWORD callerInstrSize,
                                           const BlankRegion& blank, int timeoutSec)
{
    ValidationResult result = { -1, blank.foa, blank.rva, blank.size };

    // Precondition 1: blank region must exist
    if (blank.size == 0) {
        printf("[validate] SKIP  caller_rva=0x%08X  no blank region found\n", callerRva);
        return result;
    }

    // Precondition 2: must be a 5-byte E8 CALL instruction
    if (callerInstrSize != 5) {
        printf("[validate] SKIP  caller_rva=0x%08X  instr size %u != 5\n",
               callerRva, callerInstrSize);
        return result;
    }
    DWORD callerFoa = RvaToFoa(dllPath_, callerRva);
    if (callerFoa == 0) {
        printf("[validate] SKIP  caller_rva=0x%08X  RvaToFoa returned 0\n", callerRva);
        return result;
    }
    bool byteOk = false;
    BYTE firstByte = ReadOneByte(dllPath_, callerFoa, &byteOk);
    if (!byteOk || firstByte != 0xE8) {
        printf("[validate] SKIP  caller_rva=0x%08X  not E8 CALL (opcode=0x%02X)\n",
               callerRva, firstByte);
        return result;
    }

    // Build CALL redirect patch: keep 0xE8, replace rel32
    INT32 rel32 = static_cast<INT32>(blank.rva - (callerRva + 5));
    BYTE  callPatch[5] = { 0xE8 };
    memcpy(callPatch + 1, &rel32, 4);

    // 1. Generate subdirectory name: HHmmss_XXXXXXXX
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    wchar_t subDirName[64];
    swprintf_s(subDirName, L"%02u%02u%02u_%08X",
               st.wHour, st.wMinute, st.wSecond, callerRva);

    std::wstring subDir = tmpRoot_ + L"\\" + subDirName;
    CreateDirectoryW(subDir.c_str(), nullptr);

    // 2. Copy EXE and DLL into the subdirectory.
    std::wstring exeFile = fs::path(exePath_).filename().wstring();
    std::wstring dllFile = fs::path(dllPath_).filename().wstring();
    std::wstring subExe  = subDir + L"\\" + exeFile;
    std::wstring subDll  = subDir + L"\\" + dllFile;

    if (!CopyFileW(exePath_.c_str(), subExe.c_str(), FALSE) ||
        !CopyFileW(dllPath_.c_str(), subDll.c_str(), FALSE))
    {
        printf("[validate] ERROR  caller_rva=0x%08X  CopyFile failed (err=%u)\n",
               callerRva, GetLastError());
        RemoveDirectoryContents(subDir);
        RemoveDirectoryW(subDir.c_str());
        return result;
    }

    // 3. Patch the DLL copy: redirect CALL + zero-fill blank region (strict test).
    HANDLE hFile = CreateFileW(subDll.c_str(), GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[validate] ERROR  caller_rva=0x%08X  cannot open patched DLL (err=%u)\n",
               callerRva, GetLastError());
        RemoveDirectoryContents(subDir);
        RemoveDirectoryW(subDir.c_str());
        return result;
    }
    DWORD written = 0;
    // Redirect CALL rel32
    SetFilePointer(hFile, static_cast<LONG>(callerFoa), nullptr, FILE_BEGIN);
    WriteFile(hFile, callPatch, 5, &written, nullptr);
    // Zero-fill blank region for strict test
    SetFilePointer(hFile, static_cast<LONG>(blank.foa), nullptr, FILE_BEGIN);
    std::vector<BYTE> zeros(blank.size, 0x00);
    WriteFile(hFile, zeros.data(), blank.size, &written, nullptr);
    CloseHandle(hFile);

    // Neutralise any base-relocation entries that target bytes inside the blank
    // region, so the loader does not overwrite the zero-filled test bytes.
    {
        int nReloc = PatchOutRelocEntries(subDll, blank.rva, blank.rva + blank.size);
        if (nReloc > 0)
            printf("[validate] neutralised %d reloc entries in blank region\n", nReloc);
    }

    // 4. Set up globals for callbacks.
    g_val_       = this;
    g_callerHit_ = false;
    g_blankHit_  = false;
    g_timedOut_  = false;
    g_targetRva_ = callerRva;
    g_blankRva_  = blank.rva;
    g_dllBaseV_  = 0;

    // 5. Launch the debug session.
    InitDebugW(const_cast<wchar_t*>(subExe.c_str()),
               nullptr,
               const_cast<wchar_t*>(subDir.c_str()));

    SetCustomHandler(UE_CH_LOADDLL,     reinterpret_cast<LPVOID>(OnLoadDll));
    SetCustomHandler(UE_CH_EXITPROCESS, reinterpret_cast<LPVOID>(OnExitProcess));

    // 6. Start watchdog thread.
    DWORD timeoutMs = static_cast<DWORD>(timeoutSec) * 1000u;
    HANDLE hWatchdog = CreateThread(nullptr, 0, WatchdogThread,
        reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(timeoutMs)), 0, nullptr);

    // 7. Block until both BPs fire, process exits, or watchdog kicks in.
    DebugLoop();

    // 8. Reap the watchdog.
    if (hWatchdog) {
        WaitForSingleObject(hWatchdog, 2000);
        CloseHandle(hWatchdog);
    }

    result.validated = (g_callerHit_ && g_blankHit_) ? 1
                     : (g_timedOut_                  ? 0 : -1);

    const char* reason = (result.validated == 1) ? "YES"
                       : (result.validated == 0) ? "TIMEOUT" : "CRASHED";
    printf("[validate] %s  caller_rva=0x%08X  blank=[rva=0x%08X,foa=0x%X,+0x%X]%s\n",
           reason, callerRva, blank.rva, blank.foa, blank.size,
           (result.validated == 1) ? "" :
           (g_callerHit_ ? "  (caller BP hit, redirect missed)" : ""));

    // 9. Clean up tmp subdir or retain for inspection.
    if (result.validated == 1) {
        RemoveDirectoryContents(subDir);
        for (int i = 0; i < 5; ++i) {
            if (RemoveDirectoryW(subDir.c_str())) break;
            Sleep(200);
            RemoveDirectoryContents(subDir);
        }
        // Save permanent output (original bytes + CALL redirect + optional shellcode)
        SaveOutput(callerRva, callerFoa, blank);
    } else {
        std::string subDirA = WStrToUtf8V(subDir);
        printf("[validate]   retained: %s\n", subDirA.c_str());
        failedDirs_.push_back(subDir);
    }

    return result;
}

// ---- Cleanup ----

void PointValidator::Cleanup()
{
    if (tmpRoot_.empty()) return;

    // Delete any subdirs NOT in this run's failedDirs_ (sweeps old abandoned dirs).
    {
        std::wstring pattern = tmpRoot_ + L"\\*";
        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                std::wstring full = tmpRoot_ + L"\\" + fd.cFileName;
                bool isFailed = false;
                for (const auto& fdir : failedDirs_)
                    if (fdir == full) { isFailed = true; break; }
                if (!isFailed) {
                    RemoveDirectoryContents(full);
                    RemoveDirectoryW(full.c_str());
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    if (failedDirs_.empty()) {
        RemoveDirectoryW(tmpRoot_.c_str());
        printf("[validate] tmp dir removed (all points valid)\n");
    } else {
        printf("[validate] tmp dir retained (%zu failed point dir(s)): %s\n",
               failedDirs_.size(), WStrToUtf8V(tmpRoot_).c_str());
        for (const auto& d : failedDirs_)
            printf("[validate]   -> %s\n", WStrToUtf8V(d).c_str());
    }
}
