#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ahd {

enum class Verdict {
    Pass,
    Suspicious,
    Detected,
    Unavailable,
    Error,
    Running
};

enum class ObservationSource {
    UserMode,
    KernelMode,
    CrossLayer
};

struct TimingStatistics {
    std::size_t sampleCount{};
    double average{};
    double median{};
    double p95{};
    std::uint64_t maximum{};
    double variance{};
    double standardDeviation{};
    double q1{};
    double q3{};
    std::size_t outlierCount{};
};

struct Measurement {
    std::wstring name;
    std::wstring value;
    std::wstring interpretation;
};

struct TimingSeries {
    std::wstring name;
    TimingStatistics statistics;
    std::vector<std::uint64_t> rawSamples;
};

struct TestMetadata {
    std::string id;
    std::wstring title;
    std::wstring category;
    std::wstring description;
    ObservationSource source{ObservationSource::UserMode};
};

struct TestResult {
    TestMetadata metadata;
    Verdict verdict{Verdict::Unavailable};
    int confidenceContribution{};
    double reliability{1.0};
    std::optional<double> anomalyScore;
    std::wstring summary;
    std::wstring explanation;
    std::vector<Measurement> measurements;
    std::optional<TimingStatistics> timing;
    std::vector<std::uint64_t> rawSamples;
    std::vector<TimingSeries> additionalTimingSeries;
    std::chrono::milliseconds duration{};
    std::wstring capturedAtUtc;
};

struct SystemProfile {
    bool isAmd{};
    std::string cpuVendor;
    std::string cpuBrand;
    std::wstring windowsVersion;
    std::uint32_t logicalProcessorCount{};
    std::uint32_t maxBasicLeaf{};
    std::uint32_t maxExtendedLeaf{};
};

struct DetectionSnapshot {
    std::wstring timestampUtc;
    SystemProfile system;
    std::vector<TestResult> results;
    Verdict overallVerdict{Verdict::Unavailable};
    int confidenceScore{};
    std::wstring confidenceExplanation;
    std::wstring reportPath;
    std::wstring reportError;
    bool mixedCaptureTimes{};
};

const wchar_t* VerdictLabel(Verdict verdict) noexcept;
const wchar_t* SourceLabel(ObservationSource source) noexcept;

} // namespace ahd
