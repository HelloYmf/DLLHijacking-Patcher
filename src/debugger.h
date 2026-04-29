#pragma once
#include <windows.h>
#include <string>

class DllTracer;
class AnalysisDB;

class DebugSession {
public:
    struct Config {
        std::wstring exePath;
        std::wstring samDir;        // working directory for the target process
        std::string  targetDllName; // lower-case filename, e.g. "mpclient.dll"
        DWORD        maxPoints = 0; // 0 = unlimited
    };

    void Init(const Config& cfg, DllTracer* tracer, AnalysisDB* db);

    // Starts the debug session and blocks until the target exits or
    // max-points is reached.  Calls StopDebug() internally when needed.
    void Run();

private:
    Config      cfg_;
    DllTracer*  tracer_   = nullptr;
    AnalysisDB* db_       = nullptr;
    HANDLE      hProcess_ = nullptr;

    ULONG_PTR dllBase_        = 0;
    DWORD     dllSize_        = 0;
    bool      dllLoaded_      = false;
    bool      tracing_        = false;   // currently inside a StepInto chain
    bool      stopRequested_  = false;   // set when max-points reached; defers StopDebug

    // TitanEngine callbacks.
    // Custom handlers: void(void*) — TitanEngine passes the debug-event struct.
    // Step/MemBPX callbacks: void(void*) for memory BPX (accessAddr param),
    //                        void()     for StepInto.
    static void OnLoadDll(void* specialDbg);
    static void OnUnloadDll(void* specialDbg);
    static void OnExitProcess(void* specialDbg);
    static void OnMemoryBP(void* accessAddr);   // called by SetMemoryBPXEx
    static void OnStep();                        // called by StepInto

    void ArmMemoryBPX();
    void DisarmMemoryBPX();
};
