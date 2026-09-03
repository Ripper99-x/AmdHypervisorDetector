#include "../App/Statistics.h"
#include "../App/DriverClient.h"
#include "../App/PlatformUtils.h"
#include "../App/ReportWriter.h"
#include "../Shared/DriverProtocol.h"

#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace {

int failures = 0;

void Check(const bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

} // namespace

int main() {
    const std::vector<std::uint64_t> samples{1, 2, 3, 4, 100};
    const auto statistics = ahd::ComputeTimingStatistics(samples);
    Check(statistics.sampleCount == 5, "sample count");
    Check(std::abs(statistics.average - 22.0) < 0.001, "average");
    Check(std::abs(statistics.median - 3.0) < 0.001, "median");
    Check(std::abs(statistics.p95 - 80.8) < 0.001, "P95 interpolation");
    Check(std::abs(statistics.variance - 1522.0) < 0.001, "population variance");
    Check(statistics.maximum == 100, "maximum");
    Check(statistics.outlierCount == 1, "Tukey outlier count");

    const auto robust = ahd::AnalyzeTimingNoise({100, 101, 99, 100, 102, 98, 101, 5000});
    Check(robust.rawStatistics.sampleCount == 8, "robust analysis preserves raw count");
    Check(robust.retainedCount == 7, "robust analysis removes isolated high tail");
    Check(robust.removedHighTailCount == 1, "robust analysis removal count");
    Check(robust.inlierStatistics.p95 < 200.0, "robust inlier P95 excludes scheduler tail");
    Check(std::abs(robust.medianAbsoluteDeviation - 1.0) < 0.001,
          "robust median absolute deviation");
    Check(robust.highTailCutoff == 164, "robust high-tail cutoff");
    Check(robust.inlierSamples == std::vector<std::uint64_t>({100, 101, 99, 100, 102, 98, 101}),
          "robust inliers preserve original order");
    const auto emptyRobust = ahd::AnalyzeTimingNoise({});
    Check(emptyRobust.retainedCount == 0 && emptyRobust.inlierSamples.empty(),
          "empty robust analysis");
    const auto singletonRobust = ahd::AnalyzeTimingNoise({77});
    Check(singletonRobust.retainedCount == 1 &&
          singletonRobust.inlierStatistics.median == 77.0,
          "singleton robust analysis");
    const auto cutoffRobust = ahd::AnalyzeTimingNoise(
        {100, 100, 100, 100, 100, 100, 100, 164});
    Check(cutoffRobust.retainedCount == 8, "sample equal to robust cutoff is retained");
    const auto constantRobust = ahd::AnalyzeTimingNoise(
        {200, 200, 200, 200, 200, 200, 200, 200});
    Check(constantRobust.removedHighTailCount == 0, "constant timing data is retained");
    const auto smallRobust = ahd::AnalyzeTimingNoise({10, 10000});
    Check(smallRobust.retainedCount == 2, "small timing sets are never filtered");
    constexpr auto maximum = (std::numeric_limits<std::uint64_t>::max)();
    const auto largeRobust = ahd::AnalyzeTimingNoise(
        {maximum - 3u, maximum - 2u, maximum - 1u, maximum,
         maximum - 3u, maximum - 2u, maximum - 1u, maximum});
    Check(largeRobust.retainedCount == 8, "robust cutoff saturates near uint64 maximum");
    Check(AHD_PROTOCOL_VERSION == 3u, "protocol version");
    Check(sizeof(AHD_CPUID_RECORD) == 24u, "CPUID record ABI size");
    Check(sizeof(AHD_QUERY_REQUEST) == 16u, "request ABI size");
    Check(sizeof(AHD_CORE_TIMING_RECORD) == 1088u, "per-core timing record ABI size");
    Check(offsetof(AHD_CORE_TIMING_RECORD, CpuidCycles) == 64u,
          "per-core CPUID samples ABI offset");
    Check(offsetof(AHD_CORE_TIMING_RECORD, BaselineCycles) == 576u,
          "per-core baseline samples ABI offset");
    Check(offsetof(AHD_KERNEL_REPORT, Cpuid) == 56u, "CPUID record array ABI offset");
    Check(offsetof(AHD_KERNEL_REPORT, CpuidCycles) == 216u, "timing samples ABI offset");
    Check(offsetof(AHD_KERNEL_REPORT, BaselineCycles) == 4312u, "baseline samples ABI offset");
    Check(offsetof(AHD_KERNEL_REPORT, RdtscpCpuidSampleCount) == 6360u,
          "advanced timing header ABI offset");
    Check(offsetof(AHD_KERNEL_REPORT, RdtscpCpuidCycles) == 6408u,
          "RDTSCP samples ABI offset");
    Check(offsetof(AHD_KERNEL_REPORT, CoreTimings) == 14600u,
          "representative-core records ABI offset");
    Check(sizeof(AHD_KERNEL_REPORT) == 23304u, "kernel report ABI size");
    Check(sizeof(AHD_KERNEL_REPORT) < 65536u, "kernel report remains below 64 KiB");
    Check(sizeof(((AHD_KERNEL_REPORT*)nullptr)->CpuidCycles) / sizeof(std::uint64_t) ==
          AHD_MAX_KERNEL_TIMING_SAMPLES, "kernel timing sample capacity");

    auto reportStorage = std::make_unique<AHD_KERNEL_REPORT>();
    auto& report = *reportStorage;
    report.Size = sizeof(report);
    report.Version = AHD_PROTOCOL_VERSION;
    report.OperationStatus = 0;
    report.CpuFlags = AHD_CPU_FLAG_AMD;
    report.LogicalProcessorCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    report.ProbeFlags = AHD_PROBE_FLAG_MAPPER_SAFE |
                        AHD_PROBE_FLAG_MSR_READS_SKIPPED |
                        AHD_PROBE_FLAG_RDTSC_TIMING;
    const std::uint32_t leaves[AHD_CPUID_RECORD_COUNT]{
        0u, 1u, 0x80000000u, 0x80000001u, 0x8000000Au, 0x40000000u};
    for (std::size_t index = 0; index < AHD_CPUID_RECORD_COUNT; ++index) {
        report.Cpuid[index].Leaf = leaves[index];
    }
    Check(ahd::ValidateKernelReport(report, sizeof(report)), "valid protocol-v3 base report");
    Check(!ahd::ValidateKernelReport(report, sizeof(report) - 1u), "reject truncated report");
    report.Cpuid[4].Leaf = 0x80000009u;
    Check(!ahd::ValidateKernelReport(report, sizeof(report)), "reject unexpected CPUID record");
    report.Cpuid[4].Leaf = 0x8000000Au;
    report.TimingSampleCount = AHD_MAX_KERNEL_TIMING_SAMPLES + 1u;
    Check(!ahd::ValidateKernelReport(report, sizeof(report)), "reject oversized timing count");
    report.TimingSampleCount = 0;
    report.Reserved2 = 1;
    Check(!ahd::ValidateKernelReport(report, sizeof(report)), "reject nonzero reserved field");
    report.Reserved2 = 0;

    report.CpuFlags |= AHD_CPU_FLAG_RDTSCP;
    report.ProbeFlags |= AHD_PROBE_FLAG_RDTSCP_TIMING |
                         AHD_PROBE_FLAG_STRESS_TIMING;
    report.RdtscpCpuidSampleCount = 1;
    report.RdtscpBaselineSampleCount = 1;
    report.StressCpuidSampleCount = 1;
    report.StressBaselineSampleCount = 1;
    Check(ahd::ValidateKernelReport(report, sizeof(report), 1u),
          "valid protocol-v3 RDTSCP report");
    report.RdtscpCpuidSampleCount = 0;
    report.RdtscpBaselineSampleCount = 0;
    report.StressCpuidSampleCount = 0;
    report.StressBaselineSampleCount = 0;
    report.RdtscpCpuidRejectedCount = 1;
    report.RdtscpBaselineRejectedCount = 1;
    report.StressCpuidRejectedCount = 1;
    report.StressBaselineRejectedCount = 1;
    report.RdtscpAuxMismatchCount = 2;
    report.StressAuxMismatchCount = 2;
    Check(ahd::ValidateKernelReport(report, sizeof(report), 1u),
          "all-rejected timing remains structurally valid");
    report.RdtscpCpuidSampleCount = 1;
    report.RdtscpBaselineSampleCount = 1;
    report.StressCpuidSampleCount = 1;
    report.StressBaselineSampleCount = 1;
    report.RdtscpCpuidRejectedCount = 0;
    report.RdtscpBaselineRejectedCount = 0;
    report.StressCpuidRejectedCount = 0;
    report.StressBaselineRejectedCount = 0;
    report.RdtscpAuxMismatchCount = 0;
    report.StressAuxMismatchCount = 0;
    report.StressCpuidSampleCount = AHD_MAX_KERNEL_TIMING_SAMPLES + 1u;
    Check(!ahd::ValidateKernelReport(report, sizeof(report), 1u),
          "reject oversized advanced timing count");
    report.StressCpuidSampleCount = 1;
    report.ProbeFlags &= ~AHD_PROBE_FLAG_STRESS_TIMING;
    Check(!ahd::ValidateKernelReport(report, sizeof(report), 1u),
          "reject RDTSCP report without stress probe flag");
    report.ProbeFlags |= AHD_PROBE_FLAG_STRESS_TIMING;

    report.CoreRecordCount = 1;
    report.ProbeFlags |= AHD_PROBE_FLAG_MULTICORE_TIMING;
    report.CoreTimings[0].ProcessorGroup = 0;
    report.CoreTimings[0].ProcessorNumber = 0;
    report.CoreTimings[0].CoreFlags =
        AHD_CORE_FLAG_AFFINITY_CONFIRMED |
        AHD_CORE_FLAG_RDTSCP_SUPPORTED |
        AHD_CORE_FLAG_AUX_STABLE |
        AHD_CORE_FLAG_STATE_MATCHES_PRIMARY |
        AHD_CORE_FLAG_TIMING_COMPLETE;
    report.CoreTimings[0].CpuFlags = AHD_CPU_FLAG_AMD | AHD_CPU_FLAG_RDTSCP;
    report.CoreTimings[0].CpuidSampleCount = AHD_PER_CORE_TIMING_SAMPLES;
    report.CoreTimings[0].BaselineSampleCount = AHD_PER_CORE_TIMING_SAMPLES;
    Check(ahd::ValidateKernelReport(report, sizeof(report), 1u),
          "valid populated representative-core record");

    report.CoreRecordCount = 2;
    report.CoreTimings[1] = report.CoreTimings[0];
    report.CoreTimings[1].ProcessorGroup = 0;
    report.CoreTimings[1].ProcessorNumber = 0;
    Check(!ahd::ValidateKernelReport(report, sizeof(report), 1u),
          "reject duplicate representative processors");
    report.CoreRecordCount = 1;
    report.CoreTimings[0].CpuidSampleCount = AHD_PER_CORE_TIMING_SAMPLES + 1u;
    Check(!ahd::ValidateKernelReport(report, sizeof(report), 1u),
          "reject oversized per-core sample count");
    report.CoreTimings[0].CpuidSampleCount = AHD_PER_CORE_TIMING_SAMPLES;
    report.CoreRecordCount = 0;
    report.ProbeFlags &= ~AHD_PROBE_FLAG_MULTICORE_TIMING;

    const auto validCpuFlags = report.CpuFlags;
    report.CpuFlags |= 0x80000000u;
    Check(!ahd::ValidateKernelReport(report, sizeof(report), 1u),
          "reject unknown CPU flag");
    report.CpuFlags = validCpuFlags;
    const auto logicalProcessorCount = report.LogicalProcessorCount;
    report.LogicalProcessorCount = 0;
    Check(!ahd::ValidateKernelReport(report, sizeof(report), 1u),
          "reject zero logical processor count");
    report.LogicalProcessorCount = logicalProcessorCount;
    report.RdtscpCpuidSampleCount = 0;
    report.RdtscpCpuidRejectedCount = 2;
    Check(!ahd::ValidateKernelReport(report, sizeof(report), 1u),
          "reject impossible accepted/rejected count");
    report.RdtscpCpuidSampleCount = 1;
    report.RdtscpCpuidRejectedCount = 0;

    report.ProbeFlags = 0;
    Check(!ahd::ValidateKernelReport(report, sizeof(report)), "reject unsafe probe flags");

    ahd::DetectionSnapshot snapshot{};
    snapshot.timestampUtc = L"2026-08-31T00:00:00.000Z";
    snapshot.mixedCaptureTimes = true;
    snapshot.system.isAmd = true;
    snapshot.system.cpuVendor = "AuthenticAMD";
    snapshot.overallVerdict = ahd::Verdict::Suspicious;
    snapshot.confidenceScore = 17;
    snapshot.confidenceExplanation = L"fixture";
    ahd::TestResult result{};
    result.metadata = {"fixture.timing", L"Fixture", L"Tests", L"Serializer fixture", ahd::ObservationSource::UserMode};
    result.verdict = ahd::Verdict::Suspicious;
    result.anomalyScore = 42.5;
    result.capturedAtUtc = L"2026-08-31T00:00:00.001Z";
    result.timing = ahd::ComputeTimingStatistics({10, 20, 30});
    result.rawSamples = {10, 20, 30};
    result.additionalTimingSeries.push_back({
        L"comparison",
        ahd::ComputeTimingStatistics({4, 5, 6}),
        {4, 5, 6}});
    snapshot.results.push_back(std::move(result));
    ahd::TestResult clampedResult{};
    clampedResult.metadata = {"fixture.clamped", L"Clamp", L"Tests", L"Clamp fixture", ahd::ObservationSource::KernelMode};
    clampedResult.anomalyScore = 150.0;
    snapshot.results.push_back(std::move(clampedResult));
    ahd::TestResult nonFiniteResult{};
    nonFiniteResult.metadata = {"fixture.nonfinite", L"Nonfinite", L"Tests", L"Nonfinite fixture", ahd::ObservationSource::KernelMode};
    nonFiniteResult.anomalyScore = (std::numeric_limits<double>::infinity)();
    snapshot.results.push_back(std::move(nonFiniteResult));
    const auto reportPath = std::filesystem::temp_directory_path() /
        (L"amd-hv-detector-test-" + ahd::FileSafeUtcTimestamp() + L".json");
    const auto write = ahd::WriteJsonReport(snapshot, reportPath.wstring());
    Check(write.success, "write JSON report fixture");
    if (write.success) {
        std::ifstream input(reportPath, std::ios::binary);
        const std::string json((std::istreambuf_iterator<char>(input)),
                               std::istreambuf_iterator<char>());
        Check(json.find("amd-hypervisor-detector-report/v3") != std::string::npos,
              "report schema v3");
        Check(json.find("\"mixedCaptureTimes\": true") != std::string::npos,
              "mixed capture marker serialized");
        Check(json.find("\"additionalTimingSeries\"") != std::string::npos,
              "comparison series serialized");
        Check(json.find("\"name\": \"comparison\"") != std::string::npos,
              "comparison series name serialized");
        Check(json.find("\"variance\"") != std::string::npos,
              "timing variance serialized");
        Check(json.find("\"anomalyScore\": 42.5") != std::string::npos,
              "anomaly score serialized");
        Check(json.find("\"anomalyScore\": 100.000") != std::string::npos,
              "anomaly score clamped to 100");
        Check(json.find("\"anomalyScore\": null") != std::string::npos,
              "non-finite anomaly score serialized as null");
    }
    std::error_code removeError;
    std::filesystem::remove(reportPath, removeError);

    if (failures == 0) {
        std::cout << "All statistics, protocol, and report tests passed.\n";
    }
    return failures == 0 ? 0 : 1;
}
