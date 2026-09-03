#include "Statistics.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iterator>
#include <limits>
#include <numeric>
#include <sstream>

namespace ahd {
namespace {

double Percentile(const std::vector<std::uint64_t>& sorted, const double p) {
    if (sorted.empty()) {
        return 0.0;
    }
    if (sorted.size() == 1) {
        return static_cast<double>(sorted.front());
    }

    const double position = p * static_cast<double>(sorted.size() - 1);
    const auto lower = static_cast<std::size_t>(std::floor(position));
    const auto upper = static_cast<std::size_t>(std::ceil(position));
    const double fraction = position - static_cast<double>(lower);
    return static_cast<double>(sorted[lower]) * (1.0 - fraction) +
           static_cast<double>(sorted[upper]) * fraction;
}

std::uint64_t SaturatingAdd(
    const std::uint64_t left,
    const std::uint64_t right) noexcept {
    constexpr auto maximum = (std::numeric_limits<std::uint64_t>::max)();
    return right > maximum - left ? maximum : left + right;
}

std::uint64_t SaturatingMultiply(
    const std::uint64_t value,
    const std::uint64_t multiplier) noexcept {
    constexpr auto maximum = (std::numeric_limits<std::uint64_t>::max)();
    return value != 0 && multiplier > maximum / value
        ? maximum
        : value * multiplier;
}

std::uint64_t QuarterRoundedUp(const std::uint64_t value) noexcept {
    return value / 4u + (value % 4u != 0u ? 1u : 0u);
}

} // namespace

TimingStatistics ComputeTimingStatistics(const std::vector<std::uint64_t>& samples) {
    TimingStatistics result{};
    result.sampleCount = samples.size();
    if (samples.empty()) {
        return result;
    }

    std::vector<std::uint64_t> sorted = samples;
    std::sort(sorted.begin(), sorted.end());

    const long double sum = std::accumulate(
        samples.begin(), samples.end(), 0.0L,
        [](const long double current, const std::uint64_t value) {
            return current + static_cast<long double>(value);
        });
    const long double mean = sum / static_cast<long double>(samples.size());

    long double squaredError = 0.0L;
    for (const auto value : samples) {
        const long double delta = static_cast<long double>(value) - mean;
        squaredError += delta * delta;
    }

    result.average = static_cast<double>(mean);
    result.median = Percentile(sorted, 0.50);
    result.p95 = Percentile(sorted, 0.95);
    result.maximum = sorted.back();
    result.variance = static_cast<double>(squaredError / static_cast<long double>(samples.size()));
    result.standardDeviation = std::sqrt(result.variance);
    result.q1 = Percentile(sorted, 0.25);
    result.q3 = Percentile(sorted, 0.75);

    const double iqr = result.q3 - result.q1;
    const double lowFence = result.q1 - 1.5 * iqr;
    const double highFence = result.q3 + 1.5 * iqr;
    result.outlierCount = static_cast<std::size_t>(std::count_if(
        samples.begin(), samples.end(), [lowFence, highFence](const std::uint64_t value) {
            const double sample = static_cast<double>(value);
            return sample < lowFence || sample > highFence;
        }));
    return result;
}

RobustTimingAnalysis AnalyzeTimingNoise(
    const std::vector<std::uint64_t>& samples) {
    RobustTimingAnalysis result{};
    result.rawStatistics = ComputeTimingStatistics(samples);
    if (samples.empty()) {
        return result;
    }

    std::vector<std::uint64_t> sorted = samples;
    std::sort(sorted.begin(), sorted.end());

    // An integer median anchor keeps all subtraction and cutoff calculations
    // exact even for values close to UINT64_MAX. Percentile interpolation is
    // still used for the public MAD value.
    const std::uint64_t medianAnchor = sorted[(sorted.size() - 1u) / 2u];
    std::vector<std::uint64_t> deviations;
    deviations.reserve(samples.size());
    for (const auto value : samples) {
        deviations.push_back(value >= medianAnchor
            ? value - medianAnchor
            : medianAnchor - value);
    }
    std::sort(deviations.begin(), deviations.end());
    result.medianAbsoluteDeviation = Percentile(deviations, 0.50);

    // Six scaled MADs are approximately nine unscaled MADs. The 64-tick
    // absolute floor and 25% relative floor deliberately avoid classifying
    // ordinary quantization or low-jitter data as scheduler noise when MAD is
    // zero or very small. The upper median deviation makes an even-sized set
    // slightly more conservative. Small sets are never filtered.
    constexpr std::uint64_t kMinimumAbsoluteTolerance = 64u;
    constexpr std::uint64_t kMadMultiplier = 9u;
    constexpr std::size_t kMinimumFilterSampleCount = 8u;
    const std::uint64_t upperMedianDeviation = deviations[deviations.size() / 2u];
    const std::uint64_t robustTolerance = SaturatingMultiply(
        upperMedianDeviation, kMadMultiplier);
    const std::uint64_t relativeTolerance = QuarterRoundedUp(medianAnchor);
    const std::uint64_t tolerance = (std::max)({
        kMinimumAbsoluteTolerance,
        robustTolerance,
        relativeTolerance});
    result.highTailCutoff = SaturatingAdd(medianAnchor, tolerance);

    result.inlierSamples.reserve(samples.size());
    if (samples.size() < kMinimumFilterSampleCount) {
        result.inlierSamples = samples;
    } else {
        std::copy_if(
            samples.begin(),
            samples.end(),
            std::back_inserter(result.inlierSamples),
            [&](const std::uint64_t value) {
                return value <= result.highTailCutoff;
            });
    }

    result.retainedCount = result.inlierSamples.size();
    result.removedHighTailCount = samples.size() - result.retainedCount;
    result.inlierStatistics = ComputeTimingStatistics(result.inlierSamples);
    return result;
}

std::wstring FormatCycles(const double value) {
    std::wostringstream stream;
    stream << std::fixed << std::setprecision(1) << value << L" TSC ticks";
    return stream.str();
}

std::wstring FormatFixed(const double value, const int decimals) {
    std::wostringstream stream;
    stream << std::fixed << std::setprecision(decimals) << value;
    return stream.str();
}

} // namespace ahd
