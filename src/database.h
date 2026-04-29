#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <sqlite3.h>
#include "pe_parser.h"

struct InstructionRecord {
    DWORD rva;
    DWORD order;
    DWORD instrSize;    // instruction length in bytes (from LengthDisassembleEx, 0 if unknown)
    bool  isInitEnd;
    bool  inInitRegion;
};

struct PointRecord {
    DWORD rva;
    DWORD callerRva;
    DWORD order;
};

struct PointInfo {
    sqlite3_int64 id;
    DWORD         callerRva;
    DWORD         executionOrder;
};

class AnalysisDB {
public:
    bool Open(const std::wstring& dbPath);
    void Close();

    void InsertExport(const ExportEntry& e);
    void SetMeta(const char* key, const char* value);

    // Mark the last instruction before phase transition as init_end.
    // Called after Finish() if initEndRva was already flushed to DB.
    void MarkInitEnd(DWORD rva);

    // Batch writers — callers accumulate records then call these.
    void FlushInstructions(const std::vector<InstructionRecord>& batch);
    void FlushPoints(const std::vector<PointRecord>& batch);

    // Post-trace queries used by the validation phase.
    // Returns all points sorted by execution_order ascending.
    std::vector<PointInfo> QueryAllPoints();
    // Returns distinct (rva, instr_size) pairs for execution_order in [fromOrder, toOrder),
    // grouped by rva (MAX instr_size), sorted by rva ascending.
    std::vector<std::pair<DWORD,DWORD>> QueryDeltaInstructions(DWORD fromOrder, DWORD toOrder);
    // Returns the first non-zero instr_size recorded for the given rva, or 0.
    DWORD GetInstrSize(DWORD rva);
    // Write blank_foa, blank_rva, blank_size, and validated for a point row.
    void UpdatePointResult(sqlite3_int64 pointId, DWORD blankFoa, DWORD blankRva, DWORD blankSize, int validated);

private:
    sqlite3*      db_         = nullptr;
    sqlite3_stmt* stmtInstr_  = nullptr;
    sqlite3_stmt* stmtPoint_  = nullptr;
    sqlite3_stmt* stmtExport_ = nullptr;
    sqlite3_stmt* stmtMeta_   = nullptr;

    bool Exec(const char* sql);
    bool PrepareStatements();

public:
    sqlite3* Handle() const { return db_; }
};
