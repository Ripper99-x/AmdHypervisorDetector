#include "DetectionTypes.h"

namespace ahd {

const wchar_t* VerdictLabel(const Verdict verdict) noexcept {
    switch (verdict) {
    case Verdict::Pass: return L"PASS";
    case Verdict::Suspicious: return L"SUSPICIOUS";
    case Verdict::Detected: return L"DETECTED";
    case Verdict::Unavailable: return L"UNAVAILABLE";
    case Verdict::Error: return L"ERROR";
    case Verdict::Running: return L"RUNNING";
    }
    return L"UNKNOWN";
}

const wchar_t* SourceLabel(const ObservationSource source) noexcept {
    switch (source) {
    case ObservationSource::UserMode: return L"USER MODE";
    case ObservationSource::KernelMode: return L"KERNEL MODE";
    case ObservationSource::CrossLayer: return L"CROSS-LAYER";
    }
    return L"UNKNOWN";
}

} // namespace ahd

