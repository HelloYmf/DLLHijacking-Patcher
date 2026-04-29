#define NOMINMAX
#include "space_calc.h"
#include <algorithm>

void SpaceCalcContext::Clear()
{
    covered_.clear();
}

void SpaceCalcContext::AddInstructions(const std::vector<std::pair<DWORD,DWORD>>& newEntries)
{
    // Append new intervals (rva, rva+size) from the delta batch, skipping
    // entries with instrSize == 0 (disassembly failed).
    for (const auto& [rva, size] : newEntries) {
        if (size == 0) continue;
        covered_.push_back({rva, rva + size});
    }

    if (covered_.empty()) return;

    // Sort by start RVA then merge overlapping/adjacent intervals.
    std::sort(covered_.begin(), covered_.end());

    std::vector<std::pair<DWORD,DWORD>> merged;
    merged.reserve(covered_.size());
    merged.push_back(covered_[0]);

    for (size_t i = 1; i < covered_.size(); ++i) {
        auto& last = merged.back();
        if (covered_[i].first <= last.second) {
            // Overlaps or adjacent — extend the current segment.
            if (covered_[i].second > last.second)
                last.second = covered_[i].second;
        } else {
            merged.push_back(covered_[i]);
        }
    }

    covered_ = std::move(merged);
}

BlankRegion SpaceCalcContext::FindMaxGap(DWORD /*callerRva*/, DWORD /*callerInstrSize*/,
                                          const TextSectionInfo& textInfo) const
{
    // Search the entire .text section [textStart, textEnd) for the largest
    // contiguous range not covered by any executed instruction.
    //
    // All instructions from the full trace are in covered_ (init phase AND
    // post-init phase, at any RVA).  No callerRva cutoff is applied here:
    // init-phase code can jump forward to high RVAs, and those bytes must
    // remain intact or the DLL will crash before reaching caller_rva.
    const DWORD textStart = textInfo.virtualAddress;
    const DWORD textEnd   = textInfo.virtualAddress + textInfo.virtualSize;

    BlankRegion best = {0, 0, 0};

    auto checkGap = [&](DWORD gStart, DWORD gEnd) {
        if (gStart < textStart) gStart = textStart;
        if (gEnd   > textEnd)   gEnd   = textEnd;
        if (gEnd <= gStart) return;
        DWORD sz = gEnd - gStart;
        if (sz > best.size) {
            best.rva  = gStart;
            best.size = sz;
            best.foa  = textInfo.pointerToRawData + (gStart - textInfo.virtualAddress);
        }
    };

    DWORD prev = textStart;
    for (const auto& [segStart, segEnd] : covered_) {
        if (segStart >= textEnd) break;
        if (segStart > prev)
            checkGap(prev, segStart);
        if (segEnd > prev) prev = segEnd;
    }
    if (prev < textEnd) checkGap(prev, textEnd);

    // Align blank region start to BLANK_ALIGN boundary.
    // This guarantees the shell-code entry VA is aligned (ImageBase is always
    // a multiple of the page size which is >= 0x1000, a multiple of 16).
    if (best.size > 0) {
        DWORD alignedRva = (best.rva + BLANK_ALIGN - 1) & ~(DWORD)(BLANK_ALIGN - 1);
        DWORD adj        = alignedRva - best.rva;
        if (adj < best.size) {
            best.rva  = alignedRva;
            best.foa += adj;
            best.size -= adj;
        } else {
            best = {0, 0, 0};   // gap too small after alignment
        }
    }

    return best;
}
