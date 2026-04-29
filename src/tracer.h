#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include "pe_parser.h"
#include "database.h"

class DllTracer {
public:
    DllTracer(const std::vector<ExportEntry>& exports, DWORD maxPoints);

    // Called when the target DLL is mapped into the process.
    void OnDllLoaded(ULONG_PTR base, DWORD size);

    // Called for every instruction executed inside the DLL.
    // Returns false when the caller should stop the debug session
    // (max-points limit reached).
    bool OnInstruction(ULONG_PTR cip, HANDLE hProcess);

    // Flush residual buffers and write runtime metadata to the DB.
    // Call once after DebugLoop() returns.
    void Finish();

    // Called by the debugger when execution leaves the DLL mid-step-chain
    // (i.e. the last detected CALL was to an external function).
    // Prevents the BPX re-entry return address from being recorded as a point.
    void ClearCallState() { prevWasCall_ = false; prevCallAddr_ = 0; }

    void SetDB(AnalysisDB* db) { db_ = db; }

private:
    AnalysisDB* db_      = nullptr;
    ULONG_PTR   dllBase_ = 0;
    DWORD       dllSize_ = 0;
    DWORD       maxPoints_;

    std::unordered_set<DWORD>              exportRvaSet_;
    std::unordered_map<DWORD, std::string> rvaToName_;

    enum Phase { INIT_PHASE, POST_INIT_PHASE } phase_ = INIT_PHASE;

    // In-memory instruction buffer; flushed to DB every FLUSH_THRESHOLD rows.
    std::vector<InstructionRecord> instrBuf_;

    // Accumulates every RVA executed during INIT_PHASE so we can build
    // initRegion_ when the phase transition occurs, regardless of flushes.
    std::unordered_set<DWORD> allExecutedRvas_;

    // Set of RVAs belonging to the initialisation region (before first export call).
    std::unordered_set<DWORD> initRegion_;

    // RVA of the last instruction before phase transition (marked is_init_end=1).
    DWORD initEndRva_ = 0;

    // Whether initEndRva_ was already flushed to the DB (needs UPDATE instead of flag).
    bool initEndFlushed_ = false;

    std::vector<PointRecord> pointBuf_;
    DWORD totalPoints_ = 0;

    DWORD execOrder_ = 0;

    // State for CALL detection across instruction boundaries.
    bool      prevWasCall_  = false;
    ULONG_PTR prevCallAddr_ = 0;

    static constexpr DWORD FLUSH_THRESHOLD = 10000;

    void MaybeFlush();
};
