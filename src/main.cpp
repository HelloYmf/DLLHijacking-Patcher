#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <filesystem>
#include <iostream>
#include <algorithm>
#include <limits>
#include <cstdio>

#include "pe_parser.h"
#include "database.h"
#include "tracer.h"
#include "debugger.h"
#include "space_calc.h"
#include "validator.h"

namespace fs = std::filesystem;

// ---- string helpers ----

static std::string WStrToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (sz <= 1) return {};
    std::string s(static_cast<size_t>(sz) - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
    return s;
}

static std::wstring Utf8ToWStr(const std::string& s)
{
    if (s.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (sz <= 1) return {};
    std::wstring w(static_cast<size_t>(sz) - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], sz);
    return w;
}

static std::string ToLower(std::string s)
{
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// ---- system metadata ----

static void WriteSystemMeta(AnalysisDB& db)
{
    // Use RtlGetVersion via GetProcAddress to bypass compatibility shims.
    typedef LONG(WINAPI* RtlGetVersionFn)(OSVERSIONINFOW*);
    auto RtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));

    OSVERSIONINFOEXW osvi = {};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (RtlGetVersion)
        RtlGetVersion(reinterpret_cast<OSVERSIONINFOW*>(&osvi));

    char ver[64];
    snprintf(ver, sizeof(ver), "%u.%u.%u",
             osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    db.SetMeta("os_version", ver);

    const char* friendly = "Unknown";
    if      (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber >= 22000) friendly = "Windows 11";
    else if (osvi.dwMajorVersion == 10)                                 friendly = "Windows 10";
    else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 3)     friendly = "Windows 8.1";
    else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 2)     friendly = "Windows 8";
    else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1)     friendly = "Windows 7";
    else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0)     friendly = "Windows Vista";
    else if (osvi.dwMajorVersion == 5)                                  friendly = "Windows XP";
    db.SetMeta("os_name", friendly);

    char sp[128] = {};
    WideCharToMultiByte(CP_UTF8, 0, osvi.szCSDVersion, -1, sp, sizeof(sp), nullptr, nullptr);
    if (sp[0]) db.SetMeta("os_service_pack", sp);

    SYSTEM_INFO si = {};
    GetNativeSystemInfo(&si);
    db.SetMeta("os_arch",
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86");

    char compName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD cnLen = static_cast<DWORD>(sizeof(compName));
    if (GetComputerNameA(compName, &cnLen))
        db.SetMeta("computer_name", compName);

    db.SetMeta("tracer_arch", sizeof(void*) == 8 ? "x64" : "x86");

    SYSTEMTIME st = {};
    GetLocalTime(&st);
    char ts[32];
    snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    db.SetMeta("timestamp", ts);
}

// ---- report ----

static void PrintReport(AnalysisDB& db)
{
    sqlite3* h = db.Handle();
    if (!h) return;

    printf("\n===== Trace Report ============================\n");

    // -- Meta --
    printf("\n[Meta]\n");
    static const char* metaKeys[] = {
        "exe_name", "dll_name", "timestamp",
        "os_name", "os_version", "computer_name",
        "total_instructions", "init_region_size", "total_points"
    };
    for (const char* k : metaKeys) {
        char sql[256];
        snprintf(sql, sizeof(sql),
            "SELECT value FROM analysis_meta WHERE key='%s';", k);
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(h, sql, -1, &st, nullptr) == SQLITE_OK) {
            if (sqlite3_step(st) == SQLITE_ROW)
                printf("  %-24s %s\n", k,
                    reinterpret_cast<const char*>(sqlite3_column_text(st, 0)));
            sqlite3_finalize(st);
        }
    }

    // -- Init Phase --
    {
        sqlite3_stmt* st = nullptr;
        DWORD initCount = 0;
        if (sqlite3_prepare_v2(h,
                "SELECT COUNT(*) FROM dll_instructions WHERE in_init_region=1;",
                -1, &st, nullptr) == SQLITE_OK) {
            if (sqlite3_step(st) == SQLITE_ROW)
                initCount = static_cast<DWORD>(sqlite3_column_int64(st, 0));
            sqlite3_finalize(st);
        }
        if (initCount > 0) {
            DWORD entryRva = 0, exitRva = 0;
            if (sqlite3_prepare_v2(h,
                    "SELECT rva FROM dll_instructions"
                    " WHERE in_init_region=1 ORDER BY execution_order ASC LIMIT 1;",
                    -1, &st, nullptr) == SQLITE_OK) {
                if (sqlite3_step(st) == SQLITE_ROW)
                    entryRva = static_cast<DWORD>(sqlite3_column_int64(st, 0));
                sqlite3_finalize(st);
            }
            if (sqlite3_prepare_v2(h,
                    "SELECT rva FROM dll_instructions WHERE is_init_end=1 LIMIT 1;",
                    -1, &st, nullptr) == SQLITE_OK) {
                if (sqlite3_step(st) == SQLITE_ROW)
                    exitRva = static_cast<DWORD>(sqlite3_column_int64(st, 0));
                sqlite3_finalize(st);
            }
            printf("\n[Init Phase]\n");
            printf("  Instructions : %u\n", initCount);
            printf("  Entry RVA    : 0x%08X\n", entryRva);
            if (exitRva)
                printf("  Exit  RVA    : 0x%08X\n", exitRva);
        }
    }

    // -- Executed Exports --
    {
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(h,
                "SELECT DISTINCT e.name, e.rva FROM exports e"
                " INNER JOIN dll_instructions i ON i.rva = e.rva"
                " WHERE e.name IS NOT NULL ORDER BY e.rva ASC;",
                -1, &st, nullptr) == SQLITE_OK) {
            int count = 0;
            printf("\n[Executed Exports]\n");
            while (sqlite3_step(st) == SQLITE_ROW) {
                const char* name = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
                DWORD rva = static_cast<DWORD>(sqlite3_column_int64(st, 1));
                printf("  0x%08X  %s\n", rva, name ? name : "");
                count++;
            }
            if (count == 0) printf("  (none)\n");
            sqlite3_finalize(st);
        }
    }

    // -- Points (last 5) --
    {
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(h,
                "SELECT caller_rva, rva, blank_foa, blank_rva, blank_size, validated FROM points"
                " ORDER BY execution_order DESC LIMIT 5;",
                -1, &st, nullptr) == SQLITE_OK) {
            int n = 0;
            printf("\n[Points (last 5)]\n");
            while (sqlite3_step(st) == SQLITE_ROW) {
                DWORD callerRva = static_cast<DWORD>(sqlite3_column_int64(st, 0));
                DWORD rva       = static_cast<DWORD>(sqlite3_column_int64(st, 1));
                DWORD blankFoa  = static_cast<DWORD>(sqlite3_column_int64(st, 2));
                DWORD blankRva  = static_cast<DWORD>(sqlite3_column_int64(st, 3));
                DWORD blankSize = static_cast<DWORD>(sqlite3_column_int64(st, 4));
                int   validated = static_cast<int>(sqlite3_column_int64(st, 5));
                const char* valStr = (validated == 1) ? "YES" : (validated == -1) ? "NO" : "TIMEOUT";
                printf("  #%d  caller_rva=0x%08X  rva=0x%08X\n"
                       "       blank=[rva=0x%08X, foa=0x%X, +0x%X]  validated=%s\n",
                    ++n, callerRva, rva, blankRva, blankFoa, blankSize, valStr);
            }
            if (n == 0) printf("  (none)\n");
            sqlite3_finalize(st);
        }
    }

    printf("\n================================================\n");
}

// ---- usage ----

static void Usage(const char* prog)
{
    std::cerr
        << "Usage: " << (prog ? prog : "dll_tracer") << " --sam <dir>"
        << " [--dll <name>] [--max-points <N>] [--validate-timeout <sec>]"
        << " [--shellcode <hex|file>]\n\n"
        << "  --sam <dir>              Directory with exactly 1 .exe (and the target .dll)\n"
        << "  --dll <name>             Target DLL filename (required when >1 DLL present)\n"
        << "  --max-points <N>         Stop after recording N call-site points (0 = unlimited)\n"
        << "  --validate-timeout <sec> Seconds to wait per validation session (default: 5)\n"
        << "  --shellcode <hex|file>   Shellcode as hex string (\"9090CC\") or binary file path\n"
        << "                           Written into blank region of output DLL if size fits\n";
}

// ---- shellcode parser ----

static bool ParseShellcode(const std::wstring& arg, std::vector<BYTE>& out)
{
    out.clear();
    // Try as a file path first
    if (fs::exists(arg)) {
        HANDLE h = CreateFileW(arg.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz = {};
        GetFileSizeEx(h, &sz);
        out.resize(static_cast<size_t>(sz.QuadPart));
        DWORD rd = 0;
        ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &rd, nullptr);
        CloseHandle(h);
        return rd == static_cast<DWORD>(out.size());
    }
    // Parse as hex string: "90 90 CC" or "9090CC" or "90-90-CC"
    std::string hex = WStrToUtf8(arg);
    std::string clean;
    for (unsigned char c : hex)
        if (std::isxdigit(c)) clean += static_cast<char>(c);
    if (clean.empty() || clean.size() % 2 != 0) return false;
    out.reserve(clean.size() / 2);
    for (size_t i = 0; i < clean.size(); i += 2)
        out.push_back(static_cast<BYTE>(std::stoul(clean.substr(i, 2), nullptr, 16)));
    return true;
}

// ---- entry point ----

int wmain(int argc, wchar_t* argv[])
{
    std::wstring samDir;
    std::wstring dllArg;
    std::wstring shellcodeArg;
    DWORD        maxPoints       = 0;
    int          validateTimeout = 5;   // seconds per validation session

    for (int i = 1; i < argc; ++i) {
        std::wstring a(argv[i]);
        if (a == L"--sam"        && i + 1 < argc) { samDir    = argv[++i]; }
        else if (a == L"--dll"   && i + 1 < argc) { dllArg    = argv[++i]; }
        else if (a == L"--max-points" && i + 1 < argc) {
            maxPoints = static_cast<DWORD>(std::wcstoul(argv[++i], nullptr, 10));
        } else if (a == L"--validate-timeout" && i + 1 < argc) {
            validateTimeout = static_cast<int>(std::wcstol(argv[++i], nullptr, 10));
            if (validateTimeout < 1) validateTimeout = 1;
        } else if (a == L"--shellcode" && i + 1 < argc) {
            shellcodeArg = argv[++i];
        } else {
            std::cerr << "Unknown argument: " << WStrToUtf8(a) << "\n";
            Usage(nullptr);
            return 1;
        }
    }

    if (samDir.empty()) { Usage(WStrToUtf8(argv[0]).c_str()); return 1; }

    // Normalise path: strip trailing slashes
    while (!samDir.empty() && (samDir.back() == L'\\' || samDir.back() == L'/'))
        samDir.pop_back();

    // ---- Auto-discover .exe / .dll in the sample directory ----
    std::vector<fs::path> exeFiles, dllFiles;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(samDir, ec)) {
        if (ec || !entry.is_regular_file()) continue;
        std::string ext = ToLower(WStrToUtf8(entry.path().extension().wstring()));
        if      (ext == ".exe") exeFiles.push_back(entry.path());
        else if (ext == ".dll") dllFiles.push_back(entry.path());
    }
    if (ec) {
        std::cerr << "Error reading directory: " << WStrToUtf8(samDir) << "\n";
        return 1;
    }

    if (exeFiles.size() != 1) {
        std::cerr << "Error: expected exactly 1 .exe in --sam dir, found "
                  << exeFiles.size() << "\n";
        return 1;
    }
    const fs::path exePath = exeFiles[0];

    // Resolve target DLL path
    fs::path dllPath;
    if (!dllArg.empty()) {
        std::string wantLower = ToLower(WStrToUtf8(dllArg));
        for (const auto& p : dllFiles) {
            if (ToLower(WStrToUtf8(p.filename().wstring())) == wantLower) {
                dllPath = p;
                break;
            }
        }
        if (dllPath.empty()) {
            std::cerr << "Error: --dll " << WStrToUtf8(dllArg)
                      << " not found in sample directory\n";
            return 1;
        }
    } else {
        if (dllFiles.size() == 1) {
            dllPath = dllFiles[0];
        } else if (dllFiles.empty()) {
            std::cerr << "Error: no .dll found in sample directory\n";
            return 1;
        } else {
            std::cerr << "Error: multiple DLLs found; specify one with --dll\n";
            for (const auto& p : dllFiles)
                std::cerr << "  " << WStrToUtf8(p.wstring()) << "\n";
            return 1;
        }
    }

    const std::string dllNameLower = ToLower(WStrToUtf8(dllPath.filename().wstring()));

    std::cout << "[dll_tracer] EXE : " << WStrToUtf8(exePath.wstring()) << "\n"
              << "[dll_tracer] DLL : " << WStrToUtf8(dllPath.wstring())  << "\n"
              << "[dll_tracer] MaxP: " << maxPoints << " (0=unlimited)\n";

    // ---- Parse DLL exports ----
    std::vector<ExportEntry> exports;
    if (!CollectExports(dllPath.wstring(), exports)) {
        std::cerr << "Error: failed to parse export table from "
                  << WStrToUtf8(dllPath.wstring()) << "\n";
        return 1;
    }
    std::cout << "[dll_tracer] Exports: " << exports.size() << "\n";

    // ---- Build output DB path: {samDir}/{exe_stem}_{dll_stem}_{ts}.db ----
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    char tsBuf[32];
    snprintf(tsBuf, sizeof(tsBuf), "%04d%02d%02d_%02d%02d%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::wstring dbName = exePath.stem().wstring()
                        + L"_" + dllPath.stem().wstring()
                        + L"_" + Utf8ToWStr(tsBuf)
                        + L".db";
    std::wstring dbPath = samDir + L"\\" + dbName;

    // ---- Open database ----
    AnalysisDB db;
    if (!db.Open(dbPath)) {
        std::cerr << "Error: cannot open database: " << WStrToUtf8(dbPath) << "\n";
        return 1;
    }
    std::cout << "[dll_tracer] DB  : " << WStrToUtf8(dbPath) << "\n";

    // Insert export table and system/session metadata before the trace starts.
    for (const auto& e : exports) db.InsertExport(e);
    WriteSystemMeta(db);
    db.SetMeta("exe_name", WStrToUtf8(exePath.filename().wstring()).c_str());
    db.SetMeta("dll_name", WStrToUtf8(dllPath.filename().wstring()).c_str());

    // ---- Set up tracer ----
    DllTracer tracer(exports, maxPoints);
    tracer.SetDB(&db);

    // ---- Configure and run debug session (blocks) ----
    DebugSession::Config cfg;
    cfg.exePath       = exePath.wstring();
    cfg.samDir        = samDir;
    cfg.targetDllName = dllNameLower;
    cfg.maxPoints     = maxPoints;

    DebugSession session;
    session.Init(cfg, &tracer, &db);

    std::cout << "[dll_tracer] Debug session starting...\n";
    session.Run();

    // ---- Finalise trace ----
    tracer.Finish();   // flush residual buffers + write runtime metadata

    // ---- Validate points ----
    TextSectionInfo textInfo;
    if (!GetTextSection(dllPath.wstring(), textInfo)) {
        std::cerr << "[dll_tracer] Warning: cannot locate .text section — skipping validation\n";
    } else {
        std::cout << "[dll_tracer] .text  RVA=0x" << std::hex << textInfo.virtualAddress
                  << "  Size=0x" << textInfo.virtualSize << std::dec << "\n";

        std::wstring tmpRoot    = samDir + L"\\tmp";
        std::wstring outputRoot = samDir + L"\\outputs";
        CreateDirectoryW(tmpRoot.c_str(), nullptr);
        CreateDirectoryW(outputRoot.c_str(), nullptr);

        // Parse shellcode (hex string or binary file)
        std::vector<BYTE> shellcodeBytes;
        if (!shellcodeArg.empty()) {
            if (ParseShellcode(shellcodeArg, shellcodeBytes))
                printf("[dll_tracer] Shellcode: %zu bytes\n", shellcodeBytes.size());
            else
                std::cerr << "[dll_tracer] Warning: cannot parse --shellcode arg, ignoring\n";
        }

        bool dllIs64 = IsPE64(dllPath.wstring());

        PointValidator validator;
        validator.Init(exePath.wstring(), dllPath.wstring(),
                       tmpRoot, outputRoot, dllIs64, shellcodeBytes);

        // Load ALL executed instructions (entire trace) into the context once.
        SpaceCalcContext calcCtx;
        calcCtx.AddInstructions(
            db.QueryDeltaInstructions(0, (std::numeric_limits<DWORD>::max)()));

        auto points = db.QueryAllPoints();
        std::cout << "[dll_tracer] Validating " << points.size() << " point(s)...\n";

        for (const auto& pt : points) {
            DWORD callerSize = db.GetInstrSize(pt.callerRva);
            BlankRegion blank = calcCtx.FindMaxGap(pt.callerRva, callerSize, textInfo);

            ValidationResult res = validator.Validate(pt.callerRva, callerSize, blank, validateTimeout);
            db.UpdatePointResult(pt.id, blank.foa, blank.rva, blank.size, res.validated);
        }

        validator.Cleanup();
    }

    PrintReport(db);

    db.Close();

    std::cout << "[dll_tracer] Finished.\n"
              << "[dll_tracer] Output: " << WStrToUtf8(dbPath) << "\n";
    return 0;
}
