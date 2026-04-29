#include "pe_parser.h"
#include <cstdio>

// Translate a VA-relative RVA to a raw file offset by walking section headers.
static DWORD RvaToFileOffset(IMAGE_SECTION_HEADER* sections,
                              DWORD numSections,
                              DWORD rva)
{
    for (DWORD i = 0; i < numSections; i++) {
        DWORD vstart = sections[i].VirtualAddress;
        DWORD vsize  = sections[i].Misc.VirtualSize
                       ? sections[i].Misc.VirtualSize
                       : sections[i].SizeOfRawData;
        if (rva >= vstart && rva < vstart + vsize)
            return sections[i].PointerToRawData + (rva - vstart);
    }
    return 0;
}

bool IsPE64(const std::wstring& filePath)
{
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    bool is64 = false;
    if (hMap) {
        LPVOID view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (view) {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(view);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
                    reinterpret_cast<BYTE*>(view) + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE)
                    is64 = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
            }
            UnmapViewOfFile(view);
        }
        CloseHandle(hMap);
    }
    CloseHandle(hFile);
    return is64;
}

bool CollectExports(const std::wstring& dllPath, std::vector<ExportEntry>& out)
{
    out.clear();

    HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) { CloseHandle(hFile); return false; }

    LPVOID view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!view) { CloseHandle(hMap); CloseHandle(hFile); return false; }

    bool ok = false;
    do {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(view);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) break;

        auto* nt32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(
            reinterpret_cast<BYTE*>(view) + dos->e_lfanew);
        auto* nt64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(
            reinterpret_cast<BYTE*>(view) + dos->e_lfanew);

        if (nt32->Signature != IMAGE_NT_SIGNATURE) break;

        bool is64 = (nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

        IMAGE_SECTION_HEADER* sections;
        DWORD numSections;
        DWORD exportRva, exportSize;

        if (is64) {
            sections    = IMAGE_FIRST_SECTION(nt64);
            numSections = nt64->FileHeader.NumberOfSections;
            exportRva   = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportSize  = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else {
            sections    = IMAGE_FIRST_SECTION(nt32);
            numSections = nt32->FileHeader.NumberOfSections;
            exportRva   = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportSize  = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }

        if (!exportRva || !exportSize) { ok = true; break; }   // DLL has no exports

        DWORD exportOffset = RvaToFileOffset(sections, numSections, exportRva);
        if (!exportOffset) break;

        auto* expDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
            reinterpret_cast<BYTE*>(view) + exportOffset);

        DWORD numFunctions = expDir->NumberOfFunctions;
        DWORD numNames     = expDir->NumberOfNames;
        DWORD ordinalBase  = expDir->Base;

        DWORD funcOff = RvaToFileOffset(sections, numSections, expDir->AddressOfFunctions);
        DWORD nameOff = RvaToFileOffset(sections, numSections, expDir->AddressOfNames);
        DWORD ordOff  = RvaToFileOffset(sections, numSections, expDir->AddressOfNameOrdinals);
        if (!funcOff) break;

        auto* funcs    = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(view) + funcOff);
        auto* names    = nameOff ? reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(view) + nameOff) : nullptr;
        auto* ordinals = ordOff  ? reinterpret_cast<WORD*> (reinterpret_cast<BYTE*>(view) + ordOff)  : nullptr;

        // Build index: ordinal-slot-index → function name
        std::vector<std::string> slotToName(numFunctions);
        if (names && ordinals) {
            for (DWORD i = 0; i < numNames; i++) {
                DWORD noff = RvaToFileOffset(sections, numSections, names[i]);
                if (!noff) continue;
                WORD slot = ordinals[i];
                if (slot < numFunctions)
                    slotToName[slot] = reinterpret_cast<const char*>(view) + noff;
            }
        }

        for (DWORD i = 0; i < numFunctions; i++) {
            DWORD funcRva = funcs[i];
            if (!funcRva) continue;
            // Skip forwarder entries (RVA falls within the export directory)
            if (funcRva >= exportRva && funcRva < exportRva + exportSize) continue;

            ExportEntry e;
            e.rva     = funcRva;
            e.ordinal = ordinalBase + i;
            e.name    = slotToName[i];
            out.push_back(std::move(e));
        }
        ok = true;

    } while (false);

    UnmapViewOfFile(view);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return ok;
}

// Helper: open a file-mapped view and invoke a callback with (view_ptr, file_size).
// Returns false if the file cannot be mapped.
template<typename Fn>
static bool WithMappedFile(const std::wstring& path, Fn fn)
{
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fs = {};
    GetFileSizeEx(hFile, &fs);

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    bool ok = false;
    if (hMap) {
        LPVOID view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (view) {
            fn(reinterpret_cast<BYTE*>(view), static_cast<DWORD>(fs.LowPart));
            ok = true;
            UnmapViewOfFile(view);
        }
        CloseHandle(hMap);
    }
    CloseHandle(hFile);
    return ok;
}

bool GetTextSection(const std::wstring& dllPath, TextSectionInfo& out)
{
    bool found = false;
    WithMappedFile(dllPath, [&](BYTE* base, DWORD /*fileSize*/) {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        auto* nt32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
        if (nt32->Signature != IMAGE_NT_SIGNATURE) return;

        bool is64 = (nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

        IMAGE_SECTION_HEADER* sections;
        WORD numSections;
        if (is64) {
            auto* nt64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            sections    = IMAGE_FIRST_SECTION(nt64);
            numSections = nt64->FileHeader.NumberOfSections;
        } else {
            sections    = IMAGE_FIRST_SECTION(nt32);
            numSections = nt32->FileHeader.NumberOfSections;
        }

        for (WORD i = 0; i < numSections; i++) {
            IMAGE_SECTION_HEADER& sec = sections[i];
            if (sec.Characteristics & IMAGE_SCN_CNT_CODE) {
                out.virtualAddress    = sec.VirtualAddress;
                out.virtualSize       = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
                out.pointerToRawData  = sec.PointerToRawData;
                out.sizeOfRawData     = sec.SizeOfRawData;
                found = true;
                return;
            }
        }
    });
    return found;
}

BYTE ReadOneByte(const std::wstring& filePath, DWORD fileOffset, bool* ok)
{
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { if (ok) *ok = false; return 0; }
    SetFilePointer(hFile, static_cast<LONG>(fileOffset), nullptr, FILE_BEGIN);
    BYTE b = 0;
    DWORD rd = 0;
    ReadFile(hFile, &b, 1, &rd, nullptr);
    CloseHandle(hFile);
    if (ok) *ok = (rd == 1);
    return (rd == 1) ? b : 0;
}

DWORD RvaToFoa(const std::wstring& dllPath, DWORD rva)
{
    DWORD foa = 0;
    WithMappedFile(dllPath, [&](BYTE* base, DWORD /*fileSize*/) {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        auto* nt32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
        if (nt32->Signature != IMAGE_NT_SIGNATURE) return;

        bool is64 = (nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

        IMAGE_SECTION_HEADER* sections;
        DWORD numSections;
        if (is64) {
            auto* nt64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            sections    = IMAGE_FIRST_SECTION(nt64);
            numSections = nt64->FileHeader.NumberOfSections;
        } else {
            sections    = IMAGE_FIRST_SECTION(nt32);
            numSections = nt32->FileHeader.NumberOfSections;
        }
        foa = RvaToFileOffset(sections, numSections, rva);
    });
    return foa;
}
