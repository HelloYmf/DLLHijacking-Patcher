#include "tracer.h"
#include "TitanEngine.h"
#include <algorithm>
#include <string>

DllTracer::DllTracer(const std::vector<ExportEntry>& exports, DWORD maxPoints)
    : maxPoints_(maxPoints)
{
    for (const auto& e : exports) {
        exportRvaSet_.insert(e.rva);
        if (!e.name.empty())
            rvaToName_[e.rva] = e.name;
    }
}

void DllTracer::OnDllLoaded(ULONG_PTR base, DWORD size)
{
    dllBase_ = base;
    dllSize_ = size;
    phase_   = INIT_PHASE;
    execOrder_ = 0;
    prevWasCall_ = false;
    instrBuf_.clear();
    pointBuf_.clear();
    allExecutedRvas_.clear();
    initRegion_.clear();
    initEndRva_     = 0;
    initEndFlushed_ = false;
    totalPoints_    = 0;
}

bool DllTracer::OnInstruction(ULONG_PTR cip, HANDLE hProcess)
{
    const DWORD rva = static_cast<DWORD>(cip - dllBase_);
    execOrder_++;

    // Record instruction. in_init_region is true during INIT_PHASE.
    InstructionRecord rec;
    rec.rva          = rva;
    rec.order        = execOrder_;
    rec.isInitEnd    = false;
    rec.inInitRegion = (phase_ == INIT_PHASE);

    // Compute instruction length using TitanEngine's distorm-backed disassembler.
    long len = LengthDisassembleEx(hProcess, reinterpret_cast<LPVOID>(cip));
    rec.instrSize = (len > 0) ? static_cast<DWORD>(len) : 0;

    instrBuf_.push_back(rec);

    if (phase_ == INIT_PHASE) {
        allExecutedRvas_.insert(rva);

        if (exportRvaSet_.count(rva)) {
            // Phase transition: first execution of an exported function.
            // Every previously executed RVA belongs to the init region.
            initRegion_ = std::move(allExecutedRvas_);
            allExecutedRvas_.clear();   // release memory

            // Mark the instruction just before this one as init_end.
            if (instrBuf_.size() >= 2) {
                size_t prevIdx = instrBuf_.size() - 2;
                initEndRva_ = instrBuf_[prevIdx].rva;
                instrBuf_[prevIdx].isInitEnd = true;
                initEndFlushed_ = false;
            } else {
                // The very first instruction was an export entry — unlikely but
                // handle gracefully: mark the current instruction's predecessor
                // as unknown; initEndRva_ stays 0.
            }

            phase_ = POST_INIT_PHASE;
        }
    } else {
        // POST_INIT_PHASE: if the previous instruction was a CALL and the
        // landing RVA is NOT in the init region, record a "point".
        if (prevWasCall_ && !initRegion_.count(rva)) {
            PointRecord pt;
            pt.rva       = rva;
            pt.callerRva = static_cast<DWORD>(prevCallAddr_ - dllBase_);
            pt.order     = execOrder_;
            pointBuf_.push_back(std::move(pt));
            totalPoints_++;

            if (maxPoints_ > 0 && totalPoints_ >= maxPoints_) {
                MaybeFlush();
                return false;   // signal caller to stop debug session
            }
        }
    }

    // Detect whether the *current* instruction is a CALL.
    // Read 3 bytes to accommodate a potential REX prefix on x64.
    BYTE buf[3] = {};
    ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cip), buf, sizeof(buf), nullptr);

    int off = 0;
#ifdef _WIN64
    if (buf[0] >= 0x40 && buf[0] <= 0x4F)   // REX prefix (x64 only)
        off = 1;
#endif

    prevWasCall_ =
        (buf[off] == 0xE8)                                      // CALL rel32
        || (buf[off] == 0xFF && (buf[off + 1] & 0x38) == 0x10) // CALL r/m
        || (buf[off] == 0x9A);                                  // CALL far (x86 legacy)
    prevCallAddr_ = cip;

    MaybeFlush();
    return true;
}

void DllTracer::MaybeFlush()
{
    if (instrBuf_.size() >= FLUSH_THRESHOLD) {
        // If initEndRva_ is inside the batch being flushed and has already been
        // tagged, it will be written correctly.  If it was in a *previous* flush
        // (initEndFlushed_=true already set), we handle it in Finish() via UPDATE.
        db_->FlushInstructions(instrBuf_);
        instrBuf_.clear();

        // After the first flush in POST_INIT_PHASE, any earlier initEndRva_
        // that was in a previous flushed batch needs an UPDATE.
        if (initEndRva_ != 0 && phase_ == POST_INIT_PHASE)
            initEndFlushed_ = true;
    }
    if (pointBuf_.size() >= 100) {
        db_->FlushPoints(pointBuf_);
        pointBuf_.clear();
    }
}

void DllTracer::Finish()
{
    if (!instrBuf_.empty()) {
        db_->FlushInstructions(instrBuf_);
        instrBuf_.clear();
    }
    if (!pointBuf_.empty()) {
        db_->FlushPoints(pointBuf_);
        pointBuf_.clear();
    }

    // If initEndRva_ was in a batch that was already flushed without the flag
    // set (because the phase transition happened after the flush), correct it now.
    if (initEndRva_ != 0 && initEndFlushed_)
        db_->MarkInitEnd(initEndRva_);

    // Write runtime statistics to analysis_meta.
    db_->SetMeta("total_instructions", std::to_string(execOrder_).c_str());
    db_->SetMeta("init_region_size",   std::to_string(initRegion_.size()).c_str());
    db_->SetMeta("total_points",       std::to_string(totalPoints_).c_str());
    db_->SetMeta("dll_base",           std::to_string(dllBase_).c_str());
    db_->SetMeta("dll_size",           std::to_string(dllSize_).c_str());
}
