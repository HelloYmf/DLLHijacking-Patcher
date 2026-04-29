#include "debugger.h"
#include "tracer.h"
#include "database.h"
#include "TitanEngine.h"
#include <cctype>
#include <algorithm>
#include <cstdio>

// Global bridge — TitanEngine callbacks cannot carry context, so we use a
// global pointer to the active DebugSession.
static DebugSession* g_session = nullptr;

// Worker thread that calls StopDebug() ~50 ms after a callback returns.
// This keeps TitanEngine outside of any debug-event callback when the target
// process is terminated, avoiding iterator-invalidation asserts in its STL.
static DWORD WINAPI DeferredStopWorker(LPVOID)
{
    Sleep(50);
    StopDebug();
    return 0;
}

static void RequestDeferredStop()
{
    HANDLE hThread = CreateThread(nullptr, 0, DeferredStopWorker, nullptr, 0, nullptr);
    if (hThread) CloseHandle(hThread);
}

// ---- helpers ----

static std::string ToLowerA(const char* s)
{
    std::string r(s ? s : "");
    for (auto& c : r)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return r;
}

// ---- public API ----

void DebugSession::Init(const Config& cfg, DllTracer* tracer, AnalysisDB* db)
{
    cfg_    = cfg;
    tracer_ = tracer;
    db_     = db;
}

void DebugSession::Run()
{
    g_session = this;

    // 1. Create the target process (TitanEngine starts it suspended internally)
    InitDebugW(
        const_cast<wchar_t*>(cfg_.exePath.c_str()),
        nullptr,
        const_cast<wchar_t*>(cfg_.samDir.c_str()));

    // 2. Register custom event handlers *before* DebugLoop so we catch even
    //    statically-linked DLL load events.
    SetCustomHandler(UE_CH_LOADDLL,     reinterpret_cast<LPVOID>(OnLoadDll));
    SetCustomHandler(UE_CH_UNLOADDLL,   reinterpret_cast<LPVOID>(OnUnloadDll));
    SetCustomHandler(UE_CH_EXITPROCESS, reinterpret_cast<LPVOID>(OnExitProcess));

    // 3. Retrieve the process handle for ReadProcessMemory calls.
    PROCESS_INFORMATION* pi = TitanGetProcessInformation();
    hProcess_ = pi->hProcess;

    // 4. Block in the debug loop until the target exits or StopDebug() is called.
    DebugLoop();
}

// ---- TitanEngine callbacks ----

// Called with &DBGEvent.u.LoadDll (LOAD_DLL_DEBUG_INFO*)
void DebugSession::OnLoadDll(void* specialDbg)
{
    auto* info      = reinterpret_cast<LOAD_DLL_DEBUG_INFO*>(specialDbg);
    auto  baseOfDll = reinterpret_cast<ULONG_PTR>(info->lpBaseOfDll);

    // Ask TitanEngine's librarian for the DLL metadata (char name fields).
    auto* libInfo = reinterpret_cast<LIBRARY_ITEM_DATA*>(
        LibrarianGetLibraryInfoEx(info->lpBaseOfDll));
    if (!libInfo) return;

    std::string loadedName = ToLowerA(libInfo->szLibraryName);
    if (loadedName != g_session->cfg_.targetDllName) return;

    // ---- Found our target DLL ----
    g_session->dllBase_ = baseOfDll;

    // Read SizeOfImage from the remote process PE header.
    IMAGE_DOS_HEADER dosHdr = {};
    ReadProcessMemory(g_session->hProcess_, info->lpBaseOfDll,
                      &dosHdr, sizeof(dosHdr), nullptr);

    ULONG_PTR ntAddr = baseOfDll + dosHdr.e_lfanew;

    DWORD           sig       = 0;
    IMAGE_FILE_HEADER fileHdr = {};
    ReadProcessMemory(g_session->hProcess_,
                      reinterpret_cast<LPCVOID>(ntAddr),
                      &sig, 4, nullptr);
    ReadProcessMemory(g_session->hProcess_,
                      reinterpret_cast<LPCVOID>(ntAddr + 4),
                      &fileHdr, sizeof(fileHdr), nullptr);

    ULONG_PTR optAddr  = ntAddr + 4 + sizeof(IMAGE_FILE_HEADER);
    DWORD     imgSize  = 0;

    if (fileHdr.Machine == IMAGE_FILE_MACHINE_AMD64) {
        IMAGE_OPTIONAL_HEADER64 opt = {};
        ReadProcessMemory(g_session->hProcess_,
                          reinterpret_cast<LPCVOID>(optAddr),
                          &opt, sizeof(opt), nullptr);
        imgSize = opt.SizeOfImage;
    } else {
        IMAGE_OPTIONAL_HEADER32 opt = {};
        ReadProcessMemory(g_session->hProcess_,
                          reinterpret_cast<LPCVOID>(optAddr),
                          &opt, sizeof(opt), nullptr);
        imgSize = opt.SizeOfImage;
    }

    g_session->dllSize_   = imgSize;
    g_session->dllLoaded_ = true;

    printf("[tracer] DLL loaded: %s  base=0x%llX  size=0x%X\n",
           libInfo->szLibraryName,
           static_cast<unsigned long long>(baseOfDll),
           imgSize);

    g_session->tracer_->OnDllLoaded(baseOfDll, imgSize);
    g_session->ArmMemoryBPX();
}

// Called with &DBGEvent.u.UnloadDll (UNLOAD_DLL_DEBUG_INFO*)
void DebugSession::OnUnloadDll(void* specialDbg)
{
    auto* info = reinterpret_cast<UNLOAD_DLL_DEBUG_INFO*>(specialDbg);
    if (reinterpret_cast<ULONG_PTR>(info->lpBaseOfDll) != g_session->dllBase_) return;

    g_session->dllLoaded_ = false;
    g_session->tracing_   = false;
    // Do not re-arm MemBPX — the DLL is gone.
}

// Called with &DBGEvent.u.ExitProcess (EXIT_PROCESS_DEBUG_INFO*)
void DebugSession::OnExitProcess(void* /*specialDbg*/)
{
    // DebugLoop() will return naturally; nothing to do here.
}

// Called by TitanEngine as fCustomHandler(void*) — accessAddr = the faulting address.
void DebugSession::OnMemoryBP(void* /*accessAddr*/)
{
    if (!g_session->dllLoaded_) return;

    ULONG_PTR cip = GetContextData(UE_CIP);

    // Record this instruction and check continue flag.
    bool cont = g_session->tracer_->OnInstruction(cip, g_session->hProcess_);
    if (!cont) {
        g_session->stopRequested_ = true;
        RequestDeferredStop();   // terminates target after this callback returns
        return;                  // do NOT enter StepInto chain
    }

    // Enter StepInto chain to stay inside the DLL.
    g_session->tracing_ = true;
    StepInto(reinterpret_cast<LPVOID>(OnStep));
}

// Called by TitanEngine as fCustomBreakPoint(void) — no parameters.
void DebugSession::OnStep()
{
    ULONG_PTR cip = GetContextData(UE_CIP);

    const bool insideDll = g_session->dllLoaded_
                        && cip >= g_session->dllBase_
                        && cip <  g_session->dllBase_ + static_cast<ULONG_PTR>(g_session->dllSize_);

    if (g_session->stopRequested_) return;   // drain: let target run free until it dies

    if (insideDll) {
        bool cont = g_session->tracer_->OnInstruction(cip, g_session->hProcess_);
        if (!cont) {
            g_session->stopRequested_ = true;
            RequestDeferredStop();
            return;
        }
        StepInto(reinterpret_cast<LPVOID>(OnStep));   // continue chain
    } else {
        // Execution left the DLL via an external CALL (or a tail-jump out).
        // Clear the CALL state so that when execution returns to the DLL the
        // re-entry address is NOT recorded as a false point.
        g_session->tracer_->ClearCallState();
        g_session->tracing_ = false;
        if (g_session->dllLoaded_ && !g_session->stopRequested_)
            g_session->ArmMemoryBPX();   // re-arm for next entry
    }
}

// ---- Memory BPX management ----

void DebugSession::ArmMemoryBPX()
{
    if (stopRequested_) return;   // don't arm after stop was requested
    SetMemoryBPXEx(
        dllBase_,
        static_cast<SIZE_T>(dllSize_),
        UE_MEMORY_EXECUTE,
        false,                                  // one-shot: remove on hit
        reinterpret_cast<LPVOID>(OnMemoryBP));
}

void DebugSession::DisarmMemoryBPX()
{
    RemoveMemoryBPX(dllBase_, static_cast<SIZE_T>(dllSize_));
}
