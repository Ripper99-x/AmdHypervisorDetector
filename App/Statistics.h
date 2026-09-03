#pragma once

#include "DetectionTypes.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ahd {

// A one-sided robust view of timing samples. Raw statistics are always
// preserved. The inlier set only removes isolated high-latency observations,
// which are the direction in which interrupts and scheduler activity normally
// distort a short instruction timing measurement.
struct RobustTimingAnalysis {
    TimingStatistics rawStatistics;
    TimingStatistics inlierStatistics;
    std::vector<std::uint64_t> inlierSamples;
    double medianAbsoluteDeviation{};
    std::uint64_t highTailCutoff{};
    std::size_t retainedCount{};
    std::size_t removedHighTailCount{};
};

TimingStatistics ComputeTimingStatistics(const std::vector<std::uint64_t>& samples);
RobustTimingAnalysis AnalyzeTimingNoise(const std::vector<std::uint64_t>& samples);
std::wstring FormatCycles(double value);
std::wstring FormatFixed(double value, int decimals = 1);

} // namespace ahd
