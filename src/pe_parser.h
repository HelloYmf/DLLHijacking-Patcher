#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct ExportEntry {
    std::string name;     // empty for unnamed (ordinal-only) exports
    DWORD       ordinal;
    DWORD       rva;
};

// Information about a PE section (typically .text).
struct TextSectionInfo {
    DWORD virtualAddress;    // RVA of section start (relative to image base)
    DWORD virtualSize;       // virtual size of the section
    DWORD pointerToRawData;  // file offset of section data
    DWORD sizeOfRawData;     // on-disk size of section data
};

// Parse the export table of a DLL on disk.
// Returns true on success (even if the DLL has zero exports).
bool CollectExports(const std::wstring& dllPath, std::vector<ExportEntry>& out);

// Returns true if the PE file targets AMD64.
bool IsPE64(const std::wstring& filePath);

// Locate the first executable code section (.text) in the PE file.
// Returns true on success and fills |out|.
bool GetTextSection(const std::wstring& dllPath, TextSectionInfo& out);

// Translate an RVA to a file offset (FOA) by walking the section table.
// Returns 0 if the RVA is not covered by any section.
DWORD RvaToFoa(const std::wstring& dllPath, DWORD rva);

// Read a single byte from a file at the given raw file offset.
// Returns 0 and sets |ok| to false on failure (out parameter is optional).
BYTE ReadOneByte(const std::wstring& filePath, DWORD fileOffset, bool* ok = nullptr);

// In the given DLL file (must be a writable copy, NOT the original), set every
// base-relocation entry whose target RVA falls within [rvaLow, rvaHigh) to
// IMAGE_REL_BASED_ABSOLUTE (type bits = 0).  The loader ignores type-0 entries,
// so bytes in that range will no longer be patched at load time.
// Returns the number of entries neutralised, 0 if none matched, or -1 on I/O error.
int PatchOutRelocEntries(const std::wstring& dllFilePath, DWORD rvaLow, DWORD rvaHigh);
