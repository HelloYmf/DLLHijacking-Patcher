#pragma once
#include <windows.h>
#include <vector>
#include "pe_parser.h"

// Alignment granularity for the blank region start (RVA and FOA).
// 16-byte alignment ensures VA alignment (ImageBase is always page-aligned >= 0x1000)
// and satisfies both x64 function-entry ABI and SSE/AVX data alignment requirements.
constexpr DWORD BLANK_ALIGN = 16;

// A contiguous zero-able region identified within the DLL's .text section.
struct BlankRegion {
    DWORD foa;   // file offset (PointerToRawData-relative)
    DWORD rva;   // corresponding RVA
    DWORD size;  // byte count (0 = no gap found)
};

// Incremental covered-interval tracker.
//
// Points are processed in execution_order.  Each point's executed instruction
// set is a superset of the previous one's, so we only need to insert the
// "delta" instructions into the accumulated covered_ list and re-merge, rather
// than rebuilding from scratch for every point.
class SpaceCalcContext {
public:
    // Insert (rva, instrSize) pairs into the covered interval list and merge.
    // |newEntries| must be sorted by rva ascending (as returned by QueryDeltaInstructions).
    void AddInstructions(const std::vector<std::pair<DWORD,DWORD>>& newEntries);

    // Find the largest contiguous byte range in the .text section that was NOT
    // executed up to (and including) caller_rva + callerInstrSize - 1.
    // Instructions at and after caller_rva + callerInstrSize are treated as
    // unexecuted, so the tail of the section always forms a candidate gap.
    BlankRegion FindMaxGap(DWORD callerRva, DWORD callerInstrSize,
                           const TextSectionInfo& textInfo) const;

    void Clear();

private:
    // Sorted, merged list of covered (start_rva, end_rva_exclusive) intervals.
    std::vector<std::pair<DWORD,DWORD>> covered_;
};
