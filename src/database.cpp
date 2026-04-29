#include "database.h"
#include <cstdio>

static std::string WStrToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (sz <= 1) return {};
    std::string s(static_cast<size_t>(sz) - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
    return s;
}

bool AnalysisDB::Exec(const char* sql)
{
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errMsg);
    if (errMsg) sqlite3_free(errMsg);
    return rc == SQLITE_OK;
}

bool AnalysisDB::Open(const std::wstring& dbPath)
{
    std::string utf8Path = WStrToUtf8(dbPath);
    if (sqlite3_open(utf8Path.c_str(), &db_) != SQLITE_OK) {
        db_ = nullptr;
        return false;
    }

    Exec("PRAGMA journal_mode=WAL;");
    Exec("PRAGMA synchronous=NORMAL;");
    Exec("PRAGMA cache_size=-8192;");

    const char* ddl =
        "CREATE TABLE IF NOT EXISTS dll_instructions ("
        "  id              INTEGER PRIMARY KEY,"
        "  rva             INTEGER NOT NULL,"
        "  execution_order INTEGER NOT NULL,"
        "  instr_size      INTEGER DEFAULT 0,"
        "  is_init_end     INTEGER DEFAULT 0,"
        "  in_init_region  INTEGER DEFAULT 0"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_instr_rva   ON dll_instructions(rva);"
        "CREATE INDEX IF NOT EXISTS idx_instr_order ON dll_instructions(execution_order);"

        "CREATE TABLE IF NOT EXISTS points ("
        "  id              INTEGER PRIMARY KEY,"
        "  rva             INTEGER NOT NULL,"
        "  caller_rva      INTEGER,"
        "  execution_order INTEGER,"
        "  blank_foa       INTEGER DEFAULT 0,"
        "  blank_rva       INTEGER DEFAULT 0,"
        "  blank_size      INTEGER DEFAULT 0,"
        "  validated       INTEGER DEFAULT 0"
        ");"

        "CREATE TABLE IF NOT EXISTS exports ("
        "  id      INTEGER PRIMARY KEY,"
        "  name    TEXT,"
        "  ordinal INTEGER,"
        "  rva     INTEGER NOT NULL"
        ");"

        "CREATE TABLE IF NOT EXISTS analysis_meta ("
        "  key   TEXT PRIMARY KEY,"
        "  value TEXT"
        ");";

    if (!Exec(ddl)) return false;
    return PrepareStatements();
}

bool AnalysisDB::PrepareStatements()
{
    if (sqlite3_prepare_v2(db_,
            "INSERT INTO dll_instructions(rva,execution_order,instr_size,is_init_end,in_init_region)"
            " VALUES(?,?,?,?,?);",
            -1, &stmtInstr_, nullptr) != SQLITE_OK)
        return false;

    if (sqlite3_prepare_v2(db_,
            "INSERT INTO points(rva,caller_rva,execution_order)"
            " VALUES(?,?,?);",
            -1, &stmtPoint_, nullptr) != SQLITE_OK)
        return false;

    if (sqlite3_prepare_v2(db_,
            "INSERT INTO exports(name,ordinal,rva) VALUES(?,?,?);",
            -1, &stmtExport_, nullptr) != SQLITE_OK)
        return false;

    if (sqlite3_prepare_v2(db_,
            "INSERT OR REPLACE INTO analysis_meta(key,value) VALUES(?,?);",
            -1, &stmtMeta_, nullptr) != SQLITE_OK)
        return false;

    return true;
}

void AnalysisDB::Close()
{
    if (stmtInstr_)  { sqlite3_finalize(stmtInstr_);  stmtInstr_  = nullptr; }
    if (stmtPoint_)  { sqlite3_finalize(stmtPoint_);  stmtPoint_  = nullptr; }
    if (stmtExport_) { sqlite3_finalize(stmtExport_); stmtExport_ = nullptr; }
    if (stmtMeta_)   { sqlite3_finalize(stmtMeta_);   stmtMeta_   = nullptr; }
    if (db_) {
        Exec("PRAGMA wal_checkpoint(TRUNCATE);");
        Exec("PRAGMA journal_mode=DELETE;");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

void AnalysisDB::InsertExport(const ExportEntry& e)
{
    if (!stmtExport_) return;
    Exec("BEGIN IMMEDIATE;");
    sqlite3_reset(stmtExport_);
    if (e.name.empty())
        sqlite3_bind_null(stmtExport_, 1);
    else
        sqlite3_bind_text(stmtExport_, 1, e.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmtExport_, 2, static_cast<sqlite3_int64>(e.ordinal));
    sqlite3_bind_int64(stmtExport_, 3, static_cast<sqlite3_int64>(e.rva));
    sqlite3_step(stmtExport_);
    Exec("COMMIT;");
}

void AnalysisDB::SetMeta(const char* key, const char* value)
{
    if (!stmtMeta_) return;
    Exec("BEGIN IMMEDIATE;");
    sqlite3_reset(stmtMeta_);
    sqlite3_bind_text(stmtMeta_, 1, key,   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmtMeta_, 2, value, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmtMeta_);
    Exec("COMMIT;");
}

void AnalysisDB::MarkInitEnd(DWORD rva)
{
    if (!db_) return;
    char sql[200];
    snprintf(sql, sizeof(sql),
        "UPDATE dll_instructions SET is_init_end=1"
        " WHERE rva=%u AND is_init_end=0 LIMIT 1;", rva);
    Exec(sql);
}

void AnalysisDB::FlushInstructions(const std::vector<InstructionRecord>& batch)
{
    if (batch.empty() || !db_) return;
    Exec("BEGIN IMMEDIATE;");
    for (const auto& r : batch) {
        sqlite3_reset(stmtInstr_);
        sqlite3_bind_int64(stmtInstr_, 1, static_cast<sqlite3_int64>(r.rva));
        sqlite3_bind_int64(stmtInstr_, 2, static_cast<sqlite3_int64>(r.order));
        sqlite3_bind_int64(stmtInstr_, 3, static_cast<sqlite3_int64>(r.instrSize));
        sqlite3_bind_int  (stmtInstr_, 4, r.isInitEnd    ? 1 : 0);
        sqlite3_bind_int  (stmtInstr_, 5, r.inInitRegion ? 1 : 0);
        sqlite3_step(stmtInstr_);
    }
    Exec("COMMIT;");
}

std::vector<PointInfo> AnalysisDB::QueryAllPoints()
{
    std::vector<PointInfo> result;
    if (!db_) return result;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT id, caller_rva, execution_order FROM points"
            " ORDER BY execution_order ASC;",
            -1, &st, nullptr) != SQLITE_OK)
        return result;
    while (sqlite3_step(st) == SQLITE_ROW) {
        PointInfo pi;
        pi.id             = sqlite3_column_int64(st, 0);
        pi.callerRva      = static_cast<DWORD>(sqlite3_column_int64(st, 1));
        pi.executionOrder = static_cast<DWORD>(sqlite3_column_int64(st, 2));
        result.push_back(pi);
    }
    sqlite3_finalize(st);
    return result;
}

std::vector<std::pair<DWORD,DWORD>> AnalysisDB::QueryDeltaInstructions(DWORD fromOrder, DWORD toOrder)
{
    std::vector<std::pair<DWORD,DWORD>> result;
    if (!db_) return result;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT rva, MAX(instr_size) FROM dll_instructions"
            " WHERE execution_order >= ? AND execution_order < ?"
            " GROUP BY rva ORDER BY rva ASC;",
            -1, &st, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_int64(st, 1, static_cast<sqlite3_int64>(fromOrder));
    sqlite3_bind_int64(st, 2, static_cast<sqlite3_int64>(toOrder));
    while (sqlite3_step(st) == SQLITE_ROW) {
        DWORD rva  = static_cast<DWORD>(sqlite3_column_int64(st, 0));
        DWORD size = static_cast<DWORD>(sqlite3_column_int64(st, 1));
        result.push_back({rva, size});
    }
    sqlite3_finalize(st);
    return result;
}

DWORD AnalysisDB::GetInstrSize(DWORD rva)
{
    if (!db_) return 0;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT instr_size FROM dll_instructions WHERE rva=? AND instr_size>0 LIMIT 1;",
            -1, &st, nullptr) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(st, 1, static_cast<sqlite3_int64>(rva));
    DWORD size = 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        size = static_cast<DWORD>(sqlite3_column_int64(st, 0));
    sqlite3_finalize(st);
    return size;
}

void AnalysisDB::UpdatePointResult(sqlite3_int64 pointId, DWORD blankFoa, DWORD blankRva, DWORD blankSize, int validated)
{
    if (!db_) return;
    char sql[320];
    snprintf(sql, sizeof(sql),
        "UPDATE points SET blank_foa=%u, blank_rva=%u, blank_size=%u, validated=%d WHERE id=%lld;",
        blankFoa, blankRva, blankSize, validated, static_cast<long long>(pointId));
    Exec(sql);
}

void AnalysisDB::FlushPoints(const std::vector<PointRecord>& batch)
{
    if (batch.empty() || !db_) return;
    Exec("BEGIN IMMEDIATE;");
    for (const auto& r : batch) {
        sqlite3_reset(stmtPoint_);
        sqlite3_bind_int64(stmtPoint_, 1, static_cast<sqlite3_int64>(r.rva));
        sqlite3_bind_int64(stmtPoint_, 2, static_cast<sqlite3_int64>(r.callerRva));
        sqlite3_bind_int64(stmtPoint_, 3, static_cast<sqlite3_int64>(r.order));
        sqlite3_step(stmtPoint_);
    }
    Exec("COMMIT;");
}
