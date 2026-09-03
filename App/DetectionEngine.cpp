#include "DetectionEngine.h"

#include "PlatformUtils.h"
#include "Statistics.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <memory>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace ahd {
namespace {

constexpr std::size_t kTimingSampleCount = 4096;
constexpr std::size_t kSvmTimingSampleCount = 2048;

TestResult Unavailable(const TestMetadata& metadata, const std::wstring& reason) {
    TestResult result{};
    result.metadata = metadata;
    result.verdict = Verdict::Unavailable;
    result.summary = reason;
    result.explanation = L"This result is excluded from the confidence score.";
    result.capturedAtUtc = UtcTimestamp();
    return result;
}

TestResult DriverUnavailable(
    const TestMetadata& metadata,
    const DriverSnapshot& driver) {
    TestResult result{};
    result.metadata = metadata;
    result.verdict = Verdict::Unavailable;
    result.summary = driver.statusText;
    if (driver.win32Error == ERROR_REVISION_MISMATCH) {
        result.explanation = L"The mapped image uses an older protocol and cannot be replaced safely in place because the mapper-oriented driver has no unload path. Reboot, then map AmdHvDetectorDriver.sys from the same Release artifact directory as this app.";
    } else if (driver.win32Error == ERROR_FILE_NOT_FOUND ||
        driver.win32Error == ERROR_PATH_NOT_FOUND) {
        result.explanation = L"The elevated app could not find the driver's DOS device link. Confirm kdmapper reported a successful DriverEntry return and that the current Release .sys was mapped without --free.";
    } else if (driver.win32Error == ERROR_ACCESS_DENIED) {
        result.explanation = L"The device ACL allows administrators and SYSTEM. This build requests administrator elevation automatically; accept the UAC prompt and rerun.";
    } else {
        result.explanation = L"The kernel result is excluded from scoring because the device open, IOCTL, or protocol validation did not complete.";
    }
    result.measurements = {
        {L"Device path", AHD_DEVICE_WIN32_NAME, L"Expected Win32 endpoint created by the mapped probe."},
        {L"Connection status", driver.statusText, L"Exact device-open or IOCTL outcome."},
        {L"Win32 error", std::to_wstring(driver.win32Error) + L" (" + Hex32(driver.win32Error) + L")", L"Zero means no Win32 transport error was recorded."},
        {L"Expected protocol", L"v" + std::to_wstring(AHD_PROTOCOL_VERSION) +
            L", report " + std::to_wstring(sizeof(AHD_KERNEL_REPORT)) + L" bytes", L"App and driver must be from the same build."},
        {L"Returned bytes", std::to_wstring(driver.bytesReturned), L"A valid response must exactly match the report ABI size."},
        {L"Requested timing samples", std::to_wstring(driver.requestedTimingSamples), L"Bounded kernel timing request sent with the read-only IOCTL."},
        {L"Mapped-image lifetime", L"resident until reboot", L"Do not use kdmapper --free or externally unmap while the device can receive IRPs."}
    };
    result.capturedAtUtc = UtcTimestamp();
    return result;
}

template <typename Function>
TestResult TimedRun(const TestMetadata& metadata, Function&& function) {
    const auto begin = std::chrono::steady_clock::now();
    try {
        TestResult result = function();
        result.metadata = metadata;
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - begin);
        result.capturedAtUtc = UtcTimestamp();
        return result;
    } catch (const std::exception& exception) {
        TestResult result{};
        result.metadata = metadata;
        result.verdict = Verdict::Error;
        result.summary = L"Test failed: " + Utf8ToWide(exception.what());
        result.explanation = L"An internal error prevented a reliable observation; this result is not scored.";
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - begin);
        result.capturedAtUtc = UtcTimestamp();
        return result;
    } catch (...) {
        TestResult result{};
        result.metadata = metadata;
        result.verdict = Verdict::Error;
        result.summary = L"Test failed with an unknown exception.";
        result.explanation = L"An internal error prevented a reliable observation; this result is not scored.";
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - begin);
        result.capturedAtUtc = UtcTimestamp();
        return result;
    }
}

std::wstring BooleanText(const bool value) {
    return value ? L"true" : L"false";
}

std::wstring Decimal(const std::uint64_t value) {
    return std::to_wstring(value);
}

void AppendTimingMeasurements(TestResult& result, const TimingStatistics& stats) {
    result.measurements.push_back({L"Samples", std::to_wstring(stats.sampleCount), L"Valid repeated observations."});
    result.measurements.push_back({L"Median", FormatCycles(stats.median), L"Robust center of the distribution."});
    result.measurements.push_back({L"Average", FormatCycles(stats.average), L"Arithmetic mean, sensitive to interruptions."});
    result.measurements.push_back({L"P95", FormatCycles(stats.p95), L"95% of samples were at or below this value."});
    result.measurements.push_back({L"Maximum", FormatCycles(static_cast<double>(stats.maximum)), L"Largest observed sample."});
    result.measurements.push_back({L"Variance", FormatFixed(stats.variance, 1), L"Population variance in squared TSC ticks."});
    result.measurements.push_back({L"Outliers", std::to_wstring(stats.outlierCount), L"Tukey 1.5 x IQR outliers."});
}

std::vector<std::uint64_t> CopyTimingSamples(
    const std::uint64_t* samples,
    const std::size_t count,
    const std::size_t capacity) {
    const std::size_t bounded = std::min(count, capacity);
    return {samples, samples + bounded};
}

std::vector<std::uint64_t> TimingHalf(
    const std::vector<std::uint64_t>& samples,
    const bool secondHalf) {
    const std::size_t middle = samples.size() / 2u;
    const std::size_t begin = secondHalf ? middle : 0u;
    const std::size_t end = secondHalf ? samples.size() : middle;
    return {samples.begin() + static_cast<std::ptrdiff_t>(begin),
            samples.begin() + static_cast<std::ptrdiff_t>(end)};
}

double NetMedian(
    const RobustTimingAnalysis& operation,
    const RobustTimingAnalysis& baseline) noexcept {
    return std::max(
        0.0,
        operation.inlierStatistics.median - baseline.inlierStatistics.median);
}

double SymmetricRatio(const double left, const double right) noexcept {
    const double lower = std::min(left, right);
    const double upper = std::max(left, right);
    if (upper <= 0.0) return 1.0;
    return upper / std::max(1.0, lower);
}

double TailRatio(const TimingStatistics& statistics) noexcept {
    return statistics.median > 0.0
        ? statistics.p95 / statistics.median
        : 0.0;
}

double RetainedFraction(const RobustTimingAnalysis& analysis) noexcept {
    return analysis.rawStatistics.sampleCount == 0
        ? 0.0
        : static_cast<double>(analysis.retainedCount) /
              static_cast<double>(analysis.rawStatistics.sampleCount);
}

std::uint64_t RoundedSample(const double value) noexcept {
    if (!std::isfinite(value) || value <= 0.0) return 0;
    constexpr double maximum = static_cast<double>(
        (std::numeric_limits<std::uint64_t>::max)());
    if (value >= maximum) return (std::numeric_limits<std::uint64_t>::max)();
    return static_cast<std::uint64_t>(std::llround(value));
}

void AppendNoiseAnalysis(
    TestResult& result,
    const std::wstring& label,
    const RobustTimingAnalysis& analysis) {
    result.measurements.push_back({
        label + L" robust retention",
        std::to_wstring(analysis.retainedCount) + L" / " +
            std::to_wstring(analysis.rawStatistics.sampleCount),
        L"Only isolated high-tail latency is excluded from scoring; every raw sample remains in the UI and JSON report."});
    result.measurements.push_back({
        label + L" robust median / P95",
        FormatCycles(analysis.inlierStatistics.median) + L" / " +
            FormatCycles(analysis.inlierStatistics.p95),
        L"Noise-reduced center and tail used for anomaly scoring."});
    result.measurements.push_back({
        label + L" MAD / high-tail cutoff",
        FormatFixed(analysis.medianAbsoluteDeviation, 1) + L" / " +
            FormatCycles(static_cast<double>(analysis.highTailCutoff)),
        L"Conservative one-sided filter for scheduler, interrupt, and SMI latency spikes."});
}

void SetAnomalyScore(
    TestResult& result,
    const double score,
    const std::wstring& interpretation) {
    const double bounded = std::clamp(score, 0.0, 100.0);
    result.anomalyScore = bounded;
    result.measurements.push_back({
        L"Anomaly score",
        FormatFixed(bounded, 1) + L" / 100",
        interpretation});
}

bool KernelCpuidRecordEqual(
    const AHD_CPUID_RECORD& left,
    const AHD_CPUID_RECORD& right) noexcept {
    return left.Leaf == right.Leaf &&
           left.Subleaf == right.Subleaf &&
           left.Eax == right.Eax &&
           left.Ebx == right.Ebx &&
           left.Ecx == right.Ecx &&
           left.Edx == right.Edx;
}

class CpuIdentityTest final : public IDetectionTest {
public:
    CpuIdentityTest() : metadata_{
        "cpu.identity",
        L"AMD processor gate",
        L"Platform",
        L"Confirms that the processor vendor is AuthenticAMD before any AMD-specific interpretation.",
        ObservationSource::UserMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        return TimedRun(metadata_, [&] {
            TestResult result{};
            const auto& profile = context.cpu.Profile();
            result.measurements = {
                {L"CPUID vendor", Utf8ToWide(profile.cpuVendor), L"This tool supports AuthenticAMD only."},
                {L"CPU", Utf8ToWide(profile.cpuBrand), L"Brand string reported by extended CPUID leaves."},
                {L"Maximum basic leaf", Hex32(profile.maxBasicLeaf), L"Highest reported standard CPUID leaf."},
                {L"Maximum extended leaf", Hex32(profile.maxExtendedLeaf), L"Highest reported AMD extended CPUID leaf."},
                {L"Invariant TSC", BooleanText(context.cpu.HasInvariantTsc()), L"Timing thresholds are enabled only when Fn8000_0007 EDX bit 8 is advertised."},
                {L"CPL3 timestamp instructions", context.cpu.TimestampInstructionsUsable() ? L"usable" : L"blocked/unavailable", L"Guarded RDTSC/RDTSCP capability probe; failures disable user timing."},
                {L"Logical processors", std::to_wstring(profile.logicalProcessorCount), L"Current Windows system view."}
            };
            if (!profile.isAmd) {
                result.verdict = Verdict::Unavailable;
                result.summary = L"Unsupported CPU vendor: AMD-specific probes were not run.";
                result.explanation = L"No SVM MSRs or AMD-only leaves are interpreted on non-AMD processors.";
                return result;
            }
            result.verdict = Verdict::Pass;
            result.summary = L"AuthenticAMD processor confirmed.";
            result.explanation = L"The remaining tests are enabled. This gate is not itself a hypervisor test.";
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

class HypervisorBitTest final : public IDetectionTest {
public:
    HypervisorBitTest() : metadata_{
        "cpuid.hypervisor_bit",
        L"CPUID hypervisor-present bit",
        L"CPUID",
        L"Reads CPUID.1:ECX[31], the architectural hypervisor-present indication used by Windows and common VMMs.",
        ObservationSource::UserMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        return TimedRun(metadata_, [&] {
            TestResult result{};
            const auto leaf1 = context.cpu.Cpuid(1);
            const bool present = (static_cast<std::uint32_t>(leaf1.ecx) & (1u << 31)) != 0;
            result.measurements = {
                {L"CPUID.1 ECX", Hex32(static_cast<std::uint32_t>(leaf1.ecx)), L"Raw feature register."},
                {L"Bit 31", BooleanText(present), L"Architectural hypervisor-present flag."}
            };
            if (present) {
                result.verdict = Verdict::Detected;
                result.confidenceContribution = 94;
                result.summary = L"The processor interface reports an active hypervisor.";
                result.explanation = L"This is direct virtualization evidence. It can be expected when Hyper-V, VBS, a VM platform, or another legitimate VMM is active; it does not imply malicious software.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"The architectural hypervisor bit is clear.";
                result.explanation = L"No direct flag was exposed. A VMM can virtualize or clear this bit, so PASS is not proof that no hypervisor exists.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

std::wstring KnownHypervisorName(const std::string& signature) {
    struct KnownSignature { std::string_view signature; const wchar_t* name; };
    static constexpr KnownSignature known[] = {
        {"Microsoft Hv", L"Microsoft Hyper-V"},
        {"KVMKVMKVM", L"KVM"},
        {"VMwareVMware", L"VMware"},
        {"XenVMMXenVMM", L"Xen"},
        {"VBoxVBoxVBox", L"VirtualBox"},
        {"bhyve bhyve ", L"bhyve"},
        {"TCGTCGTCGTCG", L"QEMU TCG"}
    };
    for (const auto& item : known) {
        if (signature.starts_with(item.signature)) {
            return item.name;
        }
    }
    return {};
}

class HypervisorLeafTest final : public IDetectionTest {
public:
    HypervisorLeafTest() : metadata_{
        "cpuid.hypervisor_leaves",
        L"Hypervisor vendor leaves",
        L"CPUID",
        L"Checks the standard and nested-interface CPUID ranges for a coherent hypervisor maximum leaf and vendor signature.",
        ObservationSource::UserMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        return TimedRun(metadata_, [&] {
            TestResult result{};
            constexpr std::array<std::uint32_t, 4> bases{
                0x40000000u, 0x40000100u, 0x40000200u, 0x40001000u};
            bool coherentLeaf = false;
            bool knownSignature = false;
            bool malformedKnownSignature = false;
            std::wstring detectedNames;

            for (const auto base : bases) {
                const auto leaf = context.cpu.Cpuid(base);
                const std::uint32_t maximum = static_cast<std::uint32_t>(leaf.eax);
                const std::string signature = HypervisorVendorString(leaf);
                const bool coherentRange = maximum >= base + 1u && maximum <= base + 0xffu;
                const bool printable = IsPrintableSignature(signature);
                const std::wstring known = KnownHypervisorName(signature);
                const bool valid = coherentRange && printable;
                coherentLeaf = coherentLeaf || valid;
                knownSignature = knownSignature || (valid && !known.empty());
                malformedKnownSignature = malformedKnownSignature ||
                    (printable && !known.empty() && !coherentRange);
                if (valid) {
                    if (!detectedNames.empty()) detectedNames += L", ";
                    detectedNames += known.empty() ? Utf8ToWide(signature) : known;
                }

                result.measurements.push_back({
                    L"Leaf base " + Hex32(base),
                    L"max=" + Hex32(maximum) + L", vendor='" + Utf8ToWide(signature) + L"'",
                    valid ? L"Coherent hypervisor interface range." : L"No coherent interface at this base."});
            }

            const bool bit = context.cpu.HasHypervisorBit();
            if (knownSignature) {
                result.verdict = Verdict::Detected;
                result.confidenceContribution = 95;
                result.summary = L"Recognized hypervisor interface: " + detectedNames + L".";
                result.explanation = bit
                    ? L"The vendor interface agrees with the CPUID hypervisor bit. This may be an expected Windows or VM configuration."
                    : L"A recognized vendor interface is exposed while the architectural bit is clear, which is a strong CPUID inconsistency.";
            } else if (coherentLeaf) {
                result.verdict = bit ? Verdict::Detected : Verdict::Suspicious;
                result.confidenceContribution = bit ? 88 : 42;
                result.summary = L"A coherent but unrecognized hypervisor CPUID range is exposed.";
                result.explanation = L"A valid maximum leaf plus printable signature is virtualization evidence; an unknown string is reported conservatively.";
            } else if (malformedKnownSignature) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = 38;
                result.summary = L"A recognized hypervisor vendor signature is exposed with a malformed or minimal leaf range.";
                result.explanation = L"The signature is virtualization evidence, while the invalid maximum leaf suggests a partial or filtered interface. It is kept below DETECTED without a coherent range.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"No coherent hypervisor vendor range was found.";
                result.explanation = L"Hidden VMMs can suppress these leaves, so absence is not conclusive.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

class SvmCapabilityTest final : public IDetectionTest {
public:
    SvmCapabilityTest() : metadata_{
        "amd.svm_capability",
        L"AMD SVM and NPT capability state",
        L"AMD SVM / NPT",
        L"Cross-checks the SVM feature bit with Fn8000_000A revision, ASID count, and Nested Paging capability.",
        ObservationSource::UserMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        return TimedRun(metadata_, [&] {
            TestResult result{};
            const auto& profile = context.cpu.Profile();
            const bool svm = context.cpu.HasSvm();
            const bool hasSvmLeaf = svm && profile.maxExtendedLeaf >= 0x8000000Au;
            if (!svm) {
                result.measurements = {
                    {L"SVM advertised", L"false", L"CPUID Fn8000_0001 ECX bit 2."},
                    {L"Fn8000_000A interpretation", L"skipped", L"AMD reserves this leaf's meaning when SVM is not advertised."}
                };
                result.verdict = Verdict::Pass;
                result.summary = L"SVM is not advertised; reserved SVM-leaf output was not interpreted.";
                result.explanation = L"Firmware-disabled SVM is a normal platform state and is not hypervisor evidence.";
                return result;
            }
            if (!hasSvmLeaf) {
                result.measurements = {
                    {L"SVM advertised", L"true", L"CPUID Fn8000_0001 ECX bit 2."},
                    {L"Fn8000_000A interpretation", L"skipped", L"The reported maximum extended leaf does not cover the SVM capability leaf."}
                };
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = 24;
                result.summary = L"SVM is advertised without its architectural capability leaf.";
                result.explanation = L"This contradictory CPUID range can indicate filtering or unusual firmware; reserved output was not interpreted.";
                return result;
            }
            const auto svmLeaf = context.cpu.Cpuid(0x8000000Au);
            const std::uint32_t rawEax = static_cast<std::uint32_t>(svmLeaf.eax);
            const std::uint32_t rawEcx = static_cast<std::uint32_t>(svmLeaf.ecx);
            const std::uint32_t revision = rawEax & 0xffu;
            const std::uint32_t asids = static_cast<std::uint32_t>(svmLeaf.ebx);
            const std::uint32_t features = static_cast<std::uint32_t>(svmLeaf.edx);
            const bool npt = hasSvmLeaf && (features & 1u) != 0;

            result.measurements = {
                {L"SVM advertised", BooleanText(svm), L"CPUID Fn8000_0001 ECX bit 2."},
                {L"SVM leaf available", BooleanText(hasSvmLeaf), L"Maximum extended leaf covers Fn8000_000A."},
                {L"SVM raw EAX", Hex32(rawEax), L"Revision is bits 7:0; upper bits are reserved in the interpreted leaf."},
                {L"SVM revision", std::to_wstring(revision), L"Fn8000_000A EAX bits 7:0."},
                {L"ASID count", std::to_wstring(asids), L"Fn8000_000A EBX."},
                {L"SVM raw ECX", Hex32(rawEcx), L"Reserved field expected to read as zero."},
                {L"SVM feature bits", Hex32(features), L"Fn8000_000A EDX."},
                {L"Nested Paging capable", BooleanText(npt), L"Capability only; it does not show that NPT is active."}
            };

            int issues = 0;
            if (revision == 0) ++issues;
            if ((rawEax & 0xffffff00u) != 0) ++issues;
            if (rawEcx != 0) ++issues;
            if (asids == 0) ++issues;

            if (issues != 0) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = 18 + (issues - 1) * 6;
                result.summary = L"AMD SVM CPUID fields contain " + std::to_wstring(issues) + L" internal inconsistency(s).";
                result.explanation = L"These fields are expected to form a coherent capability description. Firmware can disable SVM without implying virtualization, so the test does not penalize SVM being unavailable by itself.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"SVM capability fields are internally consistent.";
                result.explanation = L"NPT and SVM CPUID bits report capability, not whether a hidden hypervisor currently uses them.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

CpuidRegisters NormalizeLeaf1(CpuidRegisters value) {
    value.ebx = static_cast<std::int32_t>(static_cast<std::uint32_t>(value.ebx) & 0x00ffffffu);
    return value;
}

class CpuidConsistencyTest final : public IDetectionTest {
public:
    CpuidConsistencyTest() : metadata_{
        "cpuid.consistency",
        L"Repeated CPUID consistency",
        L"CPUID",
        L"Repeats stable AMD feature leaves and checks maximum-leaf ranges for contradictory or changing results.",
        ObservationSource::UserMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        return TimedRun(metadata_, [&] {
            TestResult result{};
            std::size_t mismatches{};
            const auto leaf1 = NormalizeLeaf1(context.cpu.Cpuid(1));
            const auto extended1 = context.cpu.Cpuid(0x80000001u);
            const bool compareSvmLeaf = context.cpu.HasSvm() &&
                context.cpu.Profile().maxExtendedLeaf >= 0x8000000Au;
            const auto svmLeaf = compareSvmLeaf
                ? context.cpu.Cpuid(0x8000000Au)
                : CpuidRegisters{};
            for (std::size_t iteration = 0; iteration < 256; ++iteration) {
                if (!(NormalizeLeaf1(context.cpu.Cpuid(1)) == leaf1)) ++mismatches;
                if (!(context.cpu.Cpuid(0x80000001u) == extended1)) ++mismatches;
                if (compareSvmLeaf &&
                    !(context.cpu.Cpuid(0x8000000Au) == svmLeaf)) ++mismatches;
            }

            const auto& profile = context.cpu.Profile();
            const bool basicRangeSane = profile.maxBasicLeaf >= 1u && profile.maxBasicLeaf < 0x40000000u;
            const bool extendedRangeSane = profile.maxExtendedLeaf >= 0x80000001u &&
                                           profile.maxExtendedLeaf < 0xc0000000u;
            result.measurements = {
                {L"Repeated reads", L"256 x " + std::to_wstring(compareSvmLeaf ? 3 : 2) + L" leaves", L"Leaf 1 APIC-ID bits are masked before comparison; reserved SVM output is skipped."},
                {L"Mismatched observations", std::to_wstring(mismatches), L"Deterministic feature fields should remain stable."},
                {L"Basic maximum sane", BooleanText(basicRangeSane), Hex32(profile.maxBasicLeaf)},
                {L"Extended maximum sane", BooleanText(extendedRangeSane), Hex32(profile.maxExtendedLeaf)}
            };

            if (mismatches != 0 || !basicRangeSane || !extendedRangeSane) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = std::min(45, 20 + static_cast<int>(mismatches > 3 ? 15 : 0) +
                    (!basicRangeSane || !extendedRangeSane ? 10 : 0));
                result.summary = L"Repeated CPUID observations are not fully self-consistent.";
                result.explanation = L"Feature leaves are expected to be deterministic on a homogeneous AMD system. This can indicate filtering, but firmware and unusual platform topology must be ruled out.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"Repeated CPUID feature leaves remained stable.";
                result.explanation = L"No deterministic-field inconsistency was observed in this sampling window.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

class WindowsHypervisorTest final : public IDetectionTest {
public:
    WindowsHypervisorTest() : metadata_{
        "windows.hypervisor_vbs",
        L"Windows hypervisor and VBS indicators",
        L"Windows / VBS",
        L"Queries Windows Hypervisor Platform capability, active code-integrity flags, and VBS-related configuration.",
        ObservationSource::UserMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        return TimedRun(metadata_, [&] {
            TestResult result{};
            result.measurements = context.windows.measurements;
            const bool direct = context.windows.hypervisorPresent || context.windows.hvciEnabled;
            const bool configured = context.windows.vbsConfigured.value_or(0) != 0 ||
                                    context.windows.hvciConfigured.value_or(0) != 0 ||
                                    context.windows.credentialGuardConfigured.value_or(0) != 0;
            if (direct) {
                result.verdict = Verdict::Detected;
                result.confidenceContribution = 96;
                result.summary = context.windows.hypervisorPresent
                    ? L"Windows reports that a hypervisor is active."
                    : L"Active HVCI flags indicate use of the Windows hypervisor.";
                result.explanation = L"This is normally explained by Hyper-V, Virtual Machine Platform, Windows Sandbox, Credential Guard, or Memory Integrity. It is not evidence of malicious intent.";
            } else if (configured) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = 10;
                result.reliability = 0.7;
                result.summary = L"VBS-related policy is configured, but an active hypervisor was not confirmed.";
                result.explanation = L"Registry configuration can be stale or require a restart, so it is weak supporting evidence only.";
            } else if (!context.windows.hasSuccessfulActiveStateProbe ||
                       context.windows.registryProbeFailures != 0) {
                result.verdict = Verdict::Unavailable;
                result.summary = L"Windows virtualization indicators could only be queried partially.";
                result.explanation = L"Probe failures are reported as unavailable rather than being collapsed into a false PASS.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"Windows did not report an active hypervisor or configured VBS policy.";
                result.explanation = L"A hidden VMM can avoid Windows indicators; this is not proof of bare-metal execution.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

class TscStabilityTest final : public IDetectionTest {
public:
    TscStabilityTest() : metadata_{
        "timing.tsc_stability",
        L"RDTSC / RDTSCP stability",
        L"Timing",
        L"Collects repeated serialized TSC deltas on a pinned thread and checks monotonicity, AUX changes, and distribution shape.",
        ObservationSource::UserMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        if (!context.cpu.HasRdtscp()) return Unavailable(metadata_, L"RDTSCP is not advertised by this processor view.");
        if (!context.cpu.TimestampInstructionsUsable()) return Unavailable(metadata_, L"Windows blocked a guarded CPL3 RDTSC/RDTSCP capability probe.");
        if (!context.cpu.HasInvariantTsc()) return Unavailable(metadata_, L"AMD invariant TSC is not advertised; distribution thresholds are not reliable.");
        return TimedRun(metadata_, [&] {
            TestResult result{};
            auto observations = context.cpu.MeasureTscStability(kTimingSampleCount);
            if (!observations.affinityApplied) {
                return Unavailable(metadata_, L"Windows could not pin the sampling thread to one logical processor.");
            }
            const auto stats = ComputeTimingStatistics(observations.deltas);
            result.timing = stats;
            result.rawSamples = std::move(observations.deltas);
            AppendTimingMeasurements(result, stats);
            result.measurements.push_back({L"Backward TSC reads", std::to_wstring(observations.backwardsCount), L"A stable TSC must not move backward."});
            result.measurements.push_back({L"RDTSCP AUX changes", std::to_wstring(observations.auxChangeCount), L"The sampler requests affinity to one logical processor."});

            if (observations.auxChangeCount != 0) {
                result.verdict = Verdict::Unavailable;
                result.summary = L"The sampler changed RDTSCP AUX domains; the timing window is not comparable.";
                result.explanation = L"Migrated samples are treated as a measurement-quality failure, not as hypervisor evidence.";
            } else if (observations.backwardsCount != 0) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = 35;
                result.summary = L"The timestamp counter moved backward during pinned sampling.";
                result.explanation = L"This is a strong timing anomaly, but power-management, firmware, and platform faults should be excluded before attributing it to a VMM.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"The TSC remained monotonic within one RDTSCP AUX domain.";
                result.explanation = L"Stable time is expected both on bare metal and under well-implemented hypervisors.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

class CpuidTimingTest final : public IDetectionTest {
public:
    CpuidTimingTest() : metadata_{
        "timing.cpuid_distribution",
        L"CPUID timing distribution",
        L"Timing",
        L"Measures thousands of serialized CPUID calls against an RDTSC/RDTSCP baseline and reports robust statistics.",
        ObservationSource::UserMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        if (!context.cpu.HasRdtscp()) return Unavailable(metadata_, L"RDTSCP is not advertised by this processor view.");
        if (!context.cpu.TimestampInstructionsUsable()) return Unavailable(metadata_, L"Windows blocked a guarded CPL3 RDTSC/RDTSCP capability probe.");
        if (!context.cpu.HasInvariantTsc()) return Unavailable(metadata_, L"AMD invariant TSC is not advertised; distribution thresholds are not reliable.");
        return TimedRun(metadata_, [&] {
            TestResult result{};
            auto cpuidBatch = context.cpu.MeasureCpuid(0u, 0u, kTimingSampleCount);
            auto baselineBatch = context.cpu.MeasureTscBaseline(kTimingSampleCount);
            if (!cpuidBatch.affinityApplied || !baselineBatch.affinityApplied) {
                return Unavailable(metadata_, L"Windows could not pin the timing sampler to one logical processor.");
            }
            if (cpuidBatch.values.size() < kTimingSampleCount * 9 / 10 ||
                baselineBatch.values.size() < kTimingSampleCount * 9 / 10) {
                return Unavailable(metadata_, L"Too few valid CPUID/baseline samples were collected for reliable timing.");
            }
            auto cpuidSamples = std::move(cpuidBatch.values);
            auto baselineSamples = std::move(baselineBatch.values);
            const auto cpuidStats = ComputeTimingStatistics(cpuidSamples);
            const auto baselineStats = ComputeTimingStatistics(baselineSamples);
            const double netMedian = std::max(0.0, cpuidStats.median - baselineStats.median);
            const double outlierRate = cpuidStats.sampleCount == 0
                ? 1.0
                : static_cast<double>(cpuidStats.outlierCount) / static_cast<double>(cpuidStats.sampleCount);

            result.timing = cpuidStats;
            result.rawSamples = std::move(cpuidSamples);
            result.additionalTimingSeries.push_back({L"Serialized timer baseline", baselineStats, std::move(baselineSamples)});
            AppendTimingMeasurements(result, cpuidStats);
            result.measurements.push_back({L"Baseline median", FormatCycles(baselineStats.median), L"Serialized timer-pair overhead."});
            result.measurements.push_back({L"Net CPUID median", FormatCycles(netMedian), L"CPUID median minus timer baseline median."});
            result.measurements.push_back({L"Outlier rate", FormatFixed(outlierRate * 100.0, 1) + L"%", L"High rates reduce confidence in timing interpretation."});
            result.measurements.push_back({L"Rejected / migrated samples",
                std::to_wstring(cpuidBatch.rejected + baselineBatch.rejected),
                L"Backward samples and RDTSCP AUX-domain changes were excluded."});

            int contribution = 0;
            if (netMedian >= 4000.0) contribution = 28;
            else if (netMedian >= 1800.0) contribution = 22;
            else if (netMedian >= 900.0) contribution = 14;

            if (contribution != 0) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = contribution;
                result.reliability = outlierRate > 0.20 ? 0.45 : (outlierRate > 0.10 ? 0.7 : 1.0);
                result.summary = L"CPUID latency is elevated relative to the timer baseline.";
                result.explanation = L"CPUID is commonly intercepted by VMMs, but firmware, SMI activity, power state, and background load can produce similar latency. Timing never yields DETECTED by itself.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"CPUID median latency stayed below the conservative anomaly threshold.";
                result.explanation = L"A low latency does not exclude a hypervisor; modern VMMs can optimize or virtualize timing.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

class SvmLeafTimingTest final : public IDetectionTest {
public:
    SvmLeafTimingTest() : metadata_{
        "amd.svm_leaf_timing",
        L"AMD SVM leaf timing differential",
        L"AMD SVM / NPT",
        L"Compares timing of Fn8000_000A with a standard vendor leaf to look for selective SVM CPUID filtering.",
        ObservationSource::UserMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        if (!context.cpu.HasRdtscp()) return Unavailable(metadata_, L"RDTSCP is not advertised by this processor view.");
        if (!context.cpu.TimestampInstructionsUsable()) return Unavailable(metadata_, L"Windows blocked a guarded CPL3 RDTSC/RDTSCP capability probe.");
        if (!context.cpu.HasInvariantTsc()) return Unavailable(metadata_, L"AMD invariant TSC is not advertised; distribution thresholds are not reliable.");
        if (!context.cpu.HasSvm()) {
            return Unavailable(metadata_, L"SVM is not advertised; AMD reserves Fn8000_000A interpretation in this state.");
        }
        if (context.cpu.Profile().maxExtendedLeaf < 0x8000000Au) {
            return Unavailable(metadata_, L"Fn8000_000A is outside the reported extended CPUID range.");
        }
        return TimedRun(metadata_, [&] {
            TestResult result{};
            auto svmBatch = context.cpu.MeasureCpuid(0x8000000Au, 0u, kSvmTimingSampleCount);
            auto baseBatch = context.cpu.MeasureCpuid(0u, 0u, kSvmTimingSampleCount);
            if (!svmBatch.affinityApplied || !baseBatch.affinityApplied) {
                return Unavailable(metadata_, L"Windows could not pin the SVM timing sampler to one logical processor.");
            }
            if (svmBatch.values.size() < kSvmTimingSampleCount * 9 / 10 ||
                baseBatch.values.size() < kSvmTimingSampleCount * 9 / 10) {
                return Unavailable(metadata_, L"Too few valid timing samples were collected for a reliable SVM differential.");
            }
            auto svmSamples = std::move(svmBatch.values);
            auto baseSamples = std::move(baseBatch.values);
            const auto svmStats = ComputeTimingStatistics(svmSamples);
            const auto baseStats = ComputeTimingStatistics(baseSamples);
            const double ratio = baseStats.median > 0.0 ? svmStats.median / baseStats.median : 0.0;
            const double difference = svmStats.median - baseStats.median;
            result.timing = svmStats;
            result.rawSamples = std::move(svmSamples);
            result.additionalTimingSeries.push_back({L"CPUID vendor-leaf baseline", baseStats, std::move(baseSamples)});
            AppendTimingMeasurements(result, svmStats);
            result.measurements.push_back({L"Vendor-leaf median", FormatCycles(baseStats.median), L"Comparison CPUID leaf."});
            result.measurements.push_back({L"SVM/vendor ratio", FormatFixed(ratio, 2) + L"x", L"Selective interception can increase this ratio."});
            result.measurements.push_back({L"Median difference", FormatCycles(difference), L"SVM leaf minus vendor leaf."});
            result.measurements.push_back({L"Rejected / migrated samples",
                std::to_wstring(svmBatch.rejected + baseBatch.rejected),
                L"Backward samples and RDTSCP AUX-domain changes were excluded."});

            if (ratio >= 3.0 && difference >= 700.0) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = 12;
                result.reliability = 0.65;
                result.summary = L"The SVM capability leaf is selectively slower than the vendor leaf.";
                result.explanation = L"Selective CPUID interception is one possible cause, but leaf-specific microcode cost varies. This heuristic is deliberately low-weight and cannot detect a hypervisor by itself.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"No large selective timing penalty was observed for the SVM leaf.";
                result.explanation = L"Timing similarity does not rule out CPUID interception.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

class KernelSvmStateTest final : public IDetectionTest {
public:
    KernelSvmStateTest() : metadata_{
        "kernel.svm_state",
        L"Kernel AMD CPU-state consistency",
        L"Kernel",
        L"Checks the CPL0 SVM/NPT capability view and x64 control-state invariants without exception-dependent MSR probing.",
        ObservationSource::KernelMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        if (!context.driver.available) return DriverUnavailable(metadata_, context.driver);
        return TimedRun(metadata_, [&] {
            TestResult result{};
            const auto& report = *context.driver.report;
            const bool mapperSafe = (report.ProbeFlags & AHD_PROBE_FLAG_MAPPER_SAFE) != 0 &&
                                    (report.ProbeFlags & AHD_PROBE_FLAG_MSR_READS_SKIPPED) != 0;
            const bool kernelSvm = (report.CpuFlags & AHD_CPU_FLAG_SVM) != 0;
            const bool kernelNpt = (report.CpuFlags & AHD_CPU_FLAG_NPT) != 0;
            const bool kernelHypervisor = (report.CpuFlags & AHD_CPU_FLAG_HYPERVISOR) != 0;
            const bool controlStateSane =
                (report.Cr0 & (1ull << 0)) != 0 &&
                (report.Cr0 & (1ull << 31)) != 0 &&
                (report.Cr4 & (1ull << 5)) != 0;
            const bool featureStateSane = !kernelNpt || kernelSvm;

            result.measurements = {
                {L"Driver status", context.driver.statusText, L"Read-only protocol connection."},
                {L"Driver ABI", L"v" + std::to_wstring(report.Version) + L", " +
                    std::to_wstring(context.driver.bytesReturned) + L" bytes", L"Validated exact versioned protocol response."},
                {L"Probe / CPU flags", Hex32(report.ProbeFlags) + L" / " + Hex32(report.CpuFlags), L"Raw protocol capability and observation flags."},
                {L"Mapper-safe mode", BooleanText(mapperSafe), L"No RDMSR or exception-dependent probe is executed."},
                {L"Kernel SVM capability", BooleanText(kernelSvm), L"CPL0 CPUID Fn8000_0001 ECX bit 2."},
                {L"Kernel NPT capability", BooleanText(kernelNpt), L"Interpreted only when SVM is advertised; capability is not active-use proof."},
                {L"Kernel hypervisor bit", BooleanText(kernelHypervisor), L"CPL0 CPUID.1 ECX bit 31."},
                {L"CR0 / CR3 / CR4", Hex64(report.Cr0) + L" / " + Hex64(report.Cr3) + L" / " + Hex64(report.Cr4), L"Raw read-only CPU control state."},
                {L"Control-state invariants", BooleanText(controlStateSane), L"x64 requires CR0.PE/PG and CR4.PAE."},
                {L"SVM/NPT feature invariants", BooleanText(featureStateSane), L"NPT is never interpreted without SVM."},
                {L"Processor", L"group " + std::to_wstring(report.ProcessorGroup) +
                    L", number " + std::to_wstring(static_cast<unsigned int>(report.ProcessorNumber)), L"Pinned kernel observation."}
            };

            if (kernelHypervisor) {
                result.verdict = Verdict::Detected;
                result.confidenceContribution = 94;
                result.summary = L"The CPL0 CPUID view reports an active hypervisor.";
                result.explanation = L"This is direct virtualization evidence and commonly reflects an expected Hyper-V/VBS or virtual-machine configuration.";
            } else if (!mapperSafe || !controlStateSane || !featureStateSane) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = !controlStateSane || !featureStateSane ? 45 : 20;
                result.summary = L"The kernel CPU-state view is not internally consistent.";
                result.explanation = L"Impossible x64 or SVM/NPT combinations can indicate incomplete CPU-state virtualization. Mapper-safe mode itself must also be reported by the current protocol.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"The mapper-safe kernel SVM/NPT capability and control-state view is coherent.";
                result.explanation = L"MSR state is intentionally not fault-probed because manually mapped x64 images lack reliable unwind registration. A lower VMM can still provide a coherent view.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

class KernelTimingTest final : public IDetectionTest {
public:
    KernelTimingTest() : metadata_{
        "kernel.cpuid_timing",
        L"Kernel serialized CPUID timing",
        L"Kernel",
        L"Compares LFENCE/RDTSC and true RDTSCP-ended CPUID paths against matching empty baselines, then scores only repeatable robust latency and tail anomalies.",
        ObservationSource::KernelMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        if (!context.driver.available) return DriverUnavailable(metadata_, context.driver);
        if (!context.cpu.HasInvariantTsc()) return Unavailable(metadata_, L"AMD invariant TSC is not advertised; kernel timing thresholds are not reliable.");
        return TimedRun(metadata_, [&] {
            TestResult result{};
            const auto& report = *context.driver.report;
            if ((report.CpuFlags & AHD_CPU_FLAG_RDTSCP) == 0 ||
                (report.ProbeFlags & AHD_PROBE_FLAG_RDTSCP_TIMING) == 0) {
                return Unavailable(metadata_, L"RDTSCP is not available in the validated kernel CPU view.");
            }
            const std::size_t required = std::max<std::size_t>(
                1u,
                static_cast<std::size_t>(context.driver.requestedTimingSamples) * 9u / 10u);
            const std::size_t legacyCount = std::min<std::size_t>(
                report.TimingSampleCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            const std::size_t rdtscpCount = std::min<std::size_t>(
                report.RdtscpCpuidSampleCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            const std::size_t rdtscpBaselineCount = std::min<std::size_t>(
                report.RdtscpBaselineSampleCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            if (legacyCount < required || rdtscpCount < required ||
                rdtscpBaselineCount < required) {
                return Unavailable(metadata_, L"The driver returned too few valid serialized kernel timing samples.");
            }

            auto legacyCpuid = CopyTimingSamples(
                report.CpuidCycles, legacyCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            auto legacyBaseline = CopyTimingSamples(
                report.BaselineCycles, legacyCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            auto rdtscpCpuid = CopyTimingSamples(
                report.RdtscpCpuidCycles, rdtscpCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            auto rdtscpBaseline = CopyTimingSamples(
                report.RdtscpBaselineCycles,
                rdtscpBaselineCount,
                AHD_MAX_KERNEL_TIMING_SAMPLES);

            const auto legacyAnalysis = AnalyzeTimingNoise(legacyCpuid);
            const auto legacyBaselineAnalysis = AnalyzeTimingNoise(legacyBaseline);
            const auto rdtscpAnalysis = AnalyzeTimingNoise(rdtscpCpuid);
            const auto rdtscpBaselineAnalysis = AnalyzeTimingNoise(rdtscpBaseline);
            const double legacyNet = NetMedian(legacyAnalysis, legacyBaselineAnalysis);
            const double rdtscpNet = NetMedian(rdtscpAnalysis, rdtscpBaselineAnalysis);
            const double methodRatio = SymmetricRatio(legacyNet, rdtscpNet);
            const double methodDelta = std::abs(legacyNet - rdtscpNet);
            const double legacyTail = TailRatio(legacyAnalysis.rawStatistics);
            const double rdtscpTail = TailRatio(rdtscpAnalysis.rawStatistics);

            const std::size_t svmCount = std::min<std::size_t>(
                report.SvmTimingSampleCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            std::vector<std::uint64_t> svm;
            const bool kernelSvmLeaf = (report.CpuFlags & AHD_CPU_FLAG_SVM) != 0;
            if (kernelSvmLeaf) {
                if (svmCount < required) {
                    return Unavailable(metadata_, L"The driver returned too few valid kernel SVM-leaf samples.");
                }
                svm = CopyTimingSamples(
                    report.SvmCpuidCycles, svmCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            }
            const auto svmStats = ComputeTimingStatistics(svm);
            result.timing = rdtscpAnalysis.rawStatistics;
            result.rawSamples = std::move(rdtscpCpuid);
            result.additionalTimingSeries.push_back({
                L"RDTSCP empty baseline",
                rdtscpBaselineAnalysis.rawStatistics,
                std::move(rdtscpBaseline)});
            result.additionalTimingSeries.push_back({
                L"LFENCE/RDTSC CPUID path",
                legacyAnalysis.rawStatistics,
                std::move(legacyCpuid)});
            result.additionalTimingSeries.push_back({
                L"LFENCE/RDTSC empty baseline",
                legacyBaselineAnalysis.rawStatistics,
                std::move(legacyBaseline)});
            if (!svm.empty()) {
                result.additionalTimingSeries.push_back({L"Kernel AMD SVM leaf", svmStats, std::move(svm)});
            }
            AppendTimingMeasurements(result, rdtscpAnalysis.rawStatistics);
            AppendNoiseAnalysis(result, L"RDTSCP CPUID", rdtscpAnalysis);
            AppendNoiseAnalysis(result, L"LFENCE/RDTSC CPUID", legacyAnalysis);
            result.measurements.push_back({
                L"Net serialized medians",
                L"RDTSCP=" + FormatCycles(rdtscpNet) + L", LFENCE/RDTSC=" +
                    FormatCycles(legacyNet),
                L"Each CPUID path has its own equivalently serialized empty baseline removed."});
            result.measurements.push_back({
                L"Execution-path agreement",
                FormatFixed(methodRatio, 2) + L"x, delta " + FormatCycles(methodDelta),
                L"Large disagreement between equivalent serialization paths is scored only with an absolute floor."});
            result.measurements.push_back({
                L"Raw P95 / median tail ratios",
                L"RDTSCP=" + FormatFixed(rdtscpTail, 2) + L"x, LFENCE/RDTSC=" +
                    FormatFixed(legacyTail, 2) + L"x",
                L"The P95 tail is interrupt/SMI sensitive; agreement across both paths is required before it adds evidence."});
            result.measurements.push_back({
                L"Rejected / AUX-migrated samples",
                std::to_wstring(report.TimingRejectedCount +
                    report.RdtscpCpuidRejectedCount + report.RdtscpBaselineRejectedCount) +
                    L" / " + std::to_wstring(report.RdtscpAuxMismatchCount),
                L"Rejected samples reduce reliability and never increase the anomaly score."});
            result.measurements.push_back({L"Driver ABI / processor",
                L"v" + std::to_wstring(report.Version) + L", " +
                std::to_wstring(context.driver.bytesReturned) + L" bytes; group " +
                std::to_wstring(report.ProcessorGroup) + L", CPU " +
                std::to_wstring(static_cast<unsigned int>(report.ProcessorNumber)),
                L"Exact validated kernel response and pinned processor."});

            const double minimumRetention = std::min({
                RetainedFraction(legacyAnalysis),
                RetainedFraction(legacyBaselineAnalysis),
                RetainedFraction(rdtscpAnalysis),
                RetainedFraction(rdtscpBaselineAnalysis)});
            if (minimumRetention < 0.75) {
                result.verdict = Verdict::Unavailable;
                result.reliability = minimumRetention;
                result.summary = L"Too much high-tail noise remained for a reliable serialized-path comparison.";
                result.explanation = L"All raw distributions are preserved, but fewer than 75% of at least one path survived the conservative scoring filter. This is a quality failure, not hypervisor evidence.";
                return result;
            }

            double anomaly = 0.0;
            const double agreedNet = std::min(legacyNet, rdtscpNet);
            if (agreedNet >= 5000.0) anomaly += 50.0;
            else if (agreedNet >= 2500.0) anomaly += 35.0;
            else if (agreedNet >= 1400.0) anomaly += 22.0;
            else if (agreedNet >= 800.0) anomaly += 10.0;
            if (std::min(legacyNet, rdtscpNet) >= 1400.0 && methodRatio <= 1.8) {
                anomaly += 8.0;
            }
            if (methodRatio >= 3.0 && methodDelta >= 1000.0) anomaly += 12.0;
            if (legacyTail >= 5.0 && rdtscpTail >= 5.0) anomaly += 8.0;
            anomaly = std::min(74.0, anomaly);
            SetAnomalyScore(
                result,
                anomaly,
                L"0-100 conservative timing severity. Timing-only evidence is capped below DETECTED.");

            result.reliability = std::clamp(
                minimumRetention *
                    (report.RdtscpAuxMismatchCount == 0 ? 1.0 : 0.75),
                0.45,
                1.0);
            if (anomaly >= 35.0) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = std::min(28, static_cast<int>(std::lround(anomaly * 0.40)));
                result.summary = L"Repeated kernel CPUID latency or serialization-path behavior exceeded conservative thresholds.";
                result.explanation = L"The score requires robust medians, matching timer-only baselines, and absolute as well as relative floors. Interrupts, SMI, firmware, and host load still prevent timing alone from becoming DETECTED.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"Both serialized kernel CPUID paths stayed within the conservative anomaly envelope.";
                result.explanation = L"Isolated high-tail samples were retained in raw evidence but excluded from median scoring. An optimized VMM can still produce low latency.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

class KernelMulticoreTimingTest final : public IDetectionTest {
public:
    KernelMulticoreTimingTest() : metadata_{
        "kernel.timing.multicore",
        L"Kernel cross-core timing consistency",
        L"Kernel",
        L"Samples the same serialized CPUID and empty path on up to eight group-aware representative processors, then compares robust baseline-adjusted medians.",
        ObservationSource::KernelMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        if (!context.driver.available) return DriverUnavailable(metadata_, context.driver);
        if (!context.cpu.HasInvariantTsc()) return Unavailable(metadata_, L"AMD invariant TSC is not advertised; cross-core timing thresholds are not reliable.");
        return TimedRun(metadata_, [&] {
            TestResult result{};
            const auto& report = *context.driver.report;
            if ((report.ProbeFlags & AHD_PROBE_FLAG_MULTICORE_TIMING) == 0) {
                return Unavailable(metadata_, L"The kernel CPU view does not support the RDTSCP multicore timing path.");
            }

            std::vector<std::uint64_t> netMedians;
            double retentionSum = 0.0;
            std::size_t includedCores{};
            std::size_t rejectedSamples{};
            std::size_t auxMismatches{};
            const std::size_t coreCount = std::min<std::size_t>(
                report.CoreRecordCount, AHD_MAX_REPRESENTATIVE_CORES);
            const std::size_t expectedCores = std::min<std::size_t>(
                report.LogicalProcessorCount, AHD_MAX_REPRESENTATIVE_CORES);
            if (expectedCores < 2u) {
                return Unavailable(metadata_, L"At least two logical processors are required for cross-core timing.");
            }
            const std::size_t requiredCores = std::min<std::size_t>(4u, expectedCores);
            const std::size_t minimumSamples =
                static_cast<std::size_t>(AHD_PER_CORE_TIMING_SAMPLES) * 9u / 10u;

            for (std::size_t index = 0; index < coreCount; ++index) {
                const auto& core = report.CoreTimings[index];
                const std::wstring processor = L"Group " +
                    std::to_wstring(core.ProcessorGroup) + L" CPU " +
                    std::to_wstring(static_cast<unsigned int>(core.ProcessorNumber));
                const bool affinityConfirmed =
                    (core.CoreFlags & AHD_CORE_FLAG_AFFINITY_CONFIRMED) != 0;
                const bool rdtscpSupported =
                    (core.CoreFlags & AHD_CORE_FLAG_RDTSCP_SUPPORTED) != 0;
                if (!affinityConfirmed || !rdtscpSupported ||
                    core.CpuidSampleCount < minimumSamples ||
                    core.BaselineSampleCount < minimumSamples) {
                    result.measurements.push_back({
                        processor,
                        L"excluded",
                        L"Affinity, RDTSCP support, or the minimum 90% sample-quality gate was not satisfied."});
                    continue;
                }

                auto cpuid = CopyTimingSamples(
                    core.CpuidCycles,
                    core.CpuidSampleCount,
                    AHD_PER_CORE_TIMING_SAMPLES);
                auto baseline = CopyTimingSamples(
                    core.BaselineCycles,
                    core.BaselineSampleCount,
                    AHD_PER_CORE_TIMING_SAMPLES);
                const auto cpuidAnalysis = AnalyzeTimingNoise(cpuid);
                const auto baselineAnalysis = AnalyzeTimingNoise(baseline);
                const double net = NetMedian(cpuidAnalysis, baselineAnalysis);
                const double retention = std::min(
                    RetainedFraction(cpuidAnalysis),
                    RetainedFraction(baselineAnalysis));
                const auto firstCpuid = AnalyzeTimingNoise(TimingHalf(cpuid, false));
                const auto secondCpuid = AnalyzeTimingNoise(TimingHalf(cpuid, true));
                const auto firstBaseline = AnalyzeTimingNoise(TimingHalf(baseline, false));
                const auto secondBaseline = AnalyzeTimingNoise(TimingHalf(baseline, true));
                const double firstNet = NetMedian(firstCpuid, firstBaseline);
                const double secondNet = NetMedian(secondCpuid, secondBaseline);
                const double halfRatio = SymmetricRatio(firstNet, secondNet);
                const double halfDelta = std::abs(firstNet - secondNet);
                const bool repeatable = halfRatio <= 2.5 || halfDelta < 700.0;
                rejectedSamples += core.CpuidRejectedCount + core.BaselineRejectedCount;
                auxMismatches += core.RdtscpAuxMismatchCount;

                result.measurements.push_back({
                    processor,
                    L"net=" + FormatCycles(net) +
                        L", CPUID median=" + FormatCycles(cpuidAnalysis.rawStatistics.median) +
                        L", baseline=" + FormatCycles(baselineAnalysis.rawStatistics.median),
                    L"P95=" + FormatCycles(cpuidAnalysis.rawStatistics.p95) +
                        L", variance=" + FormatFixed(cpuidAnalysis.rawStatistics.variance, 1) +
                        L", removed high-tail=" +
                        std::to_wstring(cpuidAnalysis.removedHighTailCount) +
                        L", half ratio=" + FormatFixed(halfRatio, 2) + L"x" +
                        L", AUX mismatches=" +
                        std::to_wstring(core.RdtscpAuxMismatchCount) +
                        (repeatable && retention >= 0.75
                            ? L"; included in cross-core scoring."
                            : L"; excluded from scoring by repeatability/retention gate.")});
                result.additionalTimingSeries.push_back({
                    processor + L" serialized CPUID",
                    cpuidAnalysis.rawStatistics,
                    std::move(cpuid)});
                result.additionalTimingSeries.push_back({
                    processor + L" empty baseline",
                    baselineAnalysis.rawStatistics,
                    std::move(baseline)});
                if (repeatable && retention >= 0.75) {
                    netMedians.push_back(RoundedSample(net));
                    retentionSum += retention;
                    ++includedCores;
                }
            }

            if (netMedians.size() < requiredCores) {
                result.verdict = Verdict::Unavailable;
                result.summary = L"Too few representative cores passed the timing repeatability and retention gates.";
                result.explanation = L"At least " + std::to_wstring(requiredCores) +
                    L" stable representative cores are required. Incomplete or noisy sampling is not virtualization evidence.";
                return result;
            }

            const auto netStatistics = ComputeTimingStatistics(netMedians);
            const auto [minimumIterator, maximumIterator] = std::minmax_element(
                netMedians.begin(), netMedians.end());
            const double minimum = static_cast<double>(*minimumIterator);
            const double maximum = static_cast<double>(*maximumIterator);
            const double range = maximum - minimum;
            const double ratio = maximum / std::max(1.0, minimum);
            const double coefficientOfVariation = netStatistics.average > 0.0
                ? netStatistics.standardDeviation / netStatistics.average
                : 0.0;
            const double center = netStatistics.median;
            const std::size_t deviatingCores = static_cast<std::size_t>(std::count_if(
                netMedians.begin(),
                netMedians.end(),
                [center](const std::uint64_t value) {
                    const double sample = static_cast<double>(value);
                    return std::abs(sample - center) >= 900.0 &&
                           SymmetricRatio(sample, center) >= 2.5;
                }));

            result.timing = netStatistics;
            result.rawSamples = std::move(netMedians);
            AppendTimingMeasurements(result, netStatistics);
            result.measurements.push_back({
                L"Representative processors",
                std::to_wstring(includedCores) + L" / " +
                    std::to_wstring(expectedCores) + L" expected (returned " +
                    std::to_wstring(coreCount) + L", system logical processors " +
                    std::to_wstring(report.LogicalProcessorCount) + L")",
                L"The driver selects evenly spaced global processor indices across Windows processor groups."});
            result.measurements.push_back({
                L"Cross-core net range / ratio",
                FormatCycles(range) + L" / " + FormatFixed(ratio, 2) + L"x",
                L"Maximum versus minimum baseline-adjusted CPUID median; both an absolute and relative threshold are required."});
            result.measurements.push_back({
                L"Cross-core coefficient of variation",
                FormatFixed(coefficientOfVariation * 100.0, 1) + L"%",
                L"Spread of representative-core net medians relative to their mean."});
            result.measurements.push_back({
                L"Corroborating deviating cores",
                std::to_wstring(deviatingCores),
                L"SUSPICIOUS requires at least two repeatable cores to differ from the cross-core median by both 900 ticks and 2.5x."});
            result.measurements.push_back({
                L"Rejected / AUX-migrated samples",
                std::to_wstring(rejectedSamples) + L" / " +
                    std::to_wstring(auxMismatches),
                L"Sampling-quality failures reduce reliability and never add evidence."});

            double anomaly = 0.0;
            if (ratio >= 5.0 && range >= 2000.0) anomaly = 65.0;
            else if (ratio >= 3.0 && range >= 1000.0) anomaly = 45.0;
            else if (ratio >= 2.0 && range >= 700.0) anomaly = 28.0;
            if (deviatingCores < 2u) anomaly = std::min(28.0, anomaly);
            if (deviatingCores >= 2u && coefficientOfVariation >= 0.80 &&
                range >= 1000.0) {
                anomaly += 8.0;
            }
            anomaly = std::min(74.0, anomaly);
            SetAnomalyScore(
                result,
                anomaly,
                L"Cross-core timing score requires simultaneous absolute and ratio thresholds; timing alone cannot become DETECTED.");

            const double averageRetention = retentionSum /
                static_cast<double>(includedCores);
            const double coverage = static_cast<double>(includedCores) /
                static_cast<double>(expectedCores);
            result.reliability = std::clamp(
                averageRetention * coverage * (auxMismatches == 0 ? 1.0 : 0.80),
                0.45,
                1.0);
            if (anomaly >= 35.0) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = std::min(
                    24,
                    static_cast<int>(std::lround(anomaly * 0.35)));
                result.summary = L"Baseline-adjusted CPUID timing differs substantially across representative cores.";
                result.explanation = L"A VMM with uneven per-vCPU interception is one explanation. Firmware, topology, thermals, and asymmetric host scheduling must still be excluded, so this remains supporting evidence.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"Representative-core CPUID timing remained mutually consistent.";
                result.explanation = L"Per-core raw distributions are preserved. Similar timing is expected on bare metal but can also be provided by a careful VMM.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

class KernelLoadDifferentialTest final : public IDetectionTest {
public:
    KernelLoadDifferentialTest() : metadata_{
        "kernel.timing.load_differential",
        L"Kernel baseline / local-work differential",
        L"Kernel",
        L"Runs order-balanced, interleaved RDTSCP-ended CPUID/empty reference paths and bounded deterministic-local-work paths, requiring the differential to repeat across both halves.",
        ObservationSource::KernelMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        if (!context.driver.available) return DriverUnavailable(metadata_, context.driver);
        if (!context.cpu.HasInvariantTsc()) return Unavailable(metadata_, L"AMD invariant TSC is not advertised; load-differential timing is not reliable.");
        return TimedRun(metadata_, [&] {
            TestResult result{};
            const auto& report = *context.driver.report;
            if ((report.ProbeFlags & AHD_PROBE_FLAG_STRESS_TIMING) == 0) {
                return Unavailable(metadata_, L"The validated kernel probe did not collect the bounded local-work timing path.");
            }
            const std::size_t required = std::max<std::size_t>(
                1u,
                static_cast<std::size_t>(context.driver.requestedTimingSamples) * 9u / 10u);
            const std::size_t idleCount = std::min<std::size_t>(
                report.RdtscpCpuidSampleCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            const std::size_t idleBaselineCount = std::min<std::size_t>(
                report.RdtscpBaselineSampleCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            const std::size_t stressCount = std::min<std::size_t>(
                report.StressCpuidSampleCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            const std::size_t stressBaselineCount = std::min<std::size_t>(
                report.StressBaselineSampleCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            if (idleCount < required || idleBaselineCount < required ||
                stressCount < required || stressBaselineCount < required) {
                return Unavailable(metadata_, L"Too few valid baseline/local-work samples passed the kernel quality gate.");
            }

            auto idleCpuid = CopyTimingSamples(
                report.RdtscpCpuidCycles, idleCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            auto idleBaseline = CopyTimingSamples(
                report.RdtscpBaselineCycles,
                idleBaselineCount,
                AHD_MAX_KERNEL_TIMING_SAMPLES);
            auto stressCpuid = CopyTimingSamples(
                report.StressCpuidCycles, stressCount, AHD_MAX_KERNEL_TIMING_SAMPLES);
            auto stressBaseline = CopyTimingSamples(
                report.StressBaselineCycles,
                stressBaselineCount,
                AHD_MAX_KERNEL_TIMING_SAMPLES);

            const auto idleAnalysis = AnalyzeTimingNoise(idleCpuid);
            const auto idleBaselineAnalysis = AnalyzeTimingNoise(idleBaseline);
            const auto stressAnalysis = AnalyzeTimingNoise(stressCpuid);
            const auto stressBaselineAnalysis = AnalyzeTimingNoise(stressBaseline);
            const double idleNet = NetMedian(idleAnalysis, idleBaselineAnalysis);
            const double stressNet = NetMedian(stressAnalysis, stressBaselineAnalysis);
            const double fullRatio = SymmetricRatio(idleNet, stressNet);
            const double fullDelta = stressNet - idleNet;

            const auto idleFirst = AnalyzeTimingNoise(TimingHalf(idleCpuid, false));
            const auto idleSecond = AnalyzeTimingNoise(TimingHalf(idleCpuid, true));
            const auto idleBaselineFirst = AnalyzeTimingNoise(TimingHalf(idleBaseline, false));
            const auto idleBaselineSecond = AnalyzeTimingNoise(TimingHalf(idleBaseline, true));
            const auto stressFirst = AnalyzeTimingNoise(TimingHalf(stressCpuid, false));
            const auto stressSecond = AnalyzeTimingNoise(TimingHalf(stressCpuid, true));
            const auto stressBaselineFirst = AnalyzeTimingNoise(TimingHalf(stressBaseline, false));
            const auto stressBaselineSecond = AnalyzeTimingNoise(TimingHalf(stressBaseline, true));
            const double firstDelta = NetMedian(stressFirst, stressBaselineFirst) -
                NetMedian(idleFirst, idleBaselineFirst);
            const double secondDelta = NetMedian(stressSecond, stressBaselineSecond) -
                NetMedian(idleSecond, idleBaselineSecond);
            const bool sameDirection =
                (firstDelta >= 0.0 && secondDelta >= 0.0) ||
                (firstDelta <= 0.0 && secondDelta <= 0.0);
            const double repeatedFloor = std::min(
                std::abs(firstDelta), std::abs(secondDelta));

            result.timing = stressAnalysis.rawStatistics;
            result.rawSamples = std::move(stressCpuid);
            result.additionalTimingSeries.push_back({
                L"Interleaved reference CPUID",
                idleAnalysis.rawStatistics,
                std::move(idleCpuid)});
            result.additionalTimingSeries.push_back({
                L"Interleaved reference empty baseline",
                idleBaselineAnalysis.rawStatistics,
                std::move(idleBaseline)});
            result.additionalTimingSeries.push_back({
                L"Local-work empty baseline",
                stressBaselineAnalysis.rawStatistics,
                std::move(stressBaseline)});
            AppendTimingMeasurements(result, stressAnalysis.rawStatistics);
            AppendNoiseAnalysis(result, L"Local-work CPUID", stressAnalysis);
            AppendNoiseAnalysis(result, L"Interleaved reference CPUID", idleAnalysis);
            result.measurements.push_back({
                L"Baseline-adjusted medians",
                L"reference=" + FormatCycles(idleNet) +
                    L", local-work=" + FormatCycles(stressNet),
                L"Reference and local-work epochs alternate order; deterministic work runs outside the timed path and matching empty-path overhead is removed."});
            result.measurements.push_back({
                L"Differential ratio / signed delta",
                FormatFixed(fullRatio, 2) + L"x / " + FormatCycles(fullDelta),
                L"Both a ratio and an absolute floor are required before this can be suspicious."});
            result.measurements.push_back({
                L"First-half / second-half delta",
                FormatCycles(firstDelta) + L" / " + FormatCycles(secondDelta),
                sameDirection
                    ? L"The two repeated halves move in the same direction."
                    : L"The halves disagree; the anomaly score is gated below SUSPICIOUS."});
            result.measurements.push_back({
                L"Rejected / AUX-migrated samples",
                std::to_wstring(report.RdtscpCpuidRejectedCount +
                    report.RdtscpBaselineRejectedCount +
                    report.StressCpuidRejectedCount +
                    report.StressBaselineRejectedCount) + L" / " +
                    std::to_wstring(report.RdtscpAuxMismatchCount +
                        report.StressAuxMismatchCount),
                L"Quality failures only reduce reliability."});

            const std::size_t rejectedSamples =
                static_cast<std::size_t>(report.RdtscpCpuidRejectedCount) +
                static_cast<std::size_t>(report.RdtscpBaselineRejectedCount) +
                static_cast<std::size_t>(report.StressCpuidRejectedCount) +
                static_cast<std::size_t>(report.StressBaselineRejectedCount);
            const double minimumRetention = std::min({
                RetainedFraction(idleAnalysis),
                RetainedFraction(idleBaselineAnalysis),
                RetainedFraction(stressAnalysis),
                RetainedFraction(stressBaselineAnalysis)});
            if (minimumRetention < 0.75) {
                result.verdict = Verdict::Unavailable;
                result.reliability = minimumRetention;
                result.summary = L"Too much high-tail noise remained for a reliable reference/local-work comparison.";
                result.explanation = L"All raw distributions remain available, but the 75% robust-retention quality gate was not met.";
                return result;
            }

            double candidate = 0.0;
            const double absoluteDelta = std::abs(fullDelta);
            if (fullRatio >= 4.0 && absoluteDelta >= 1800.0) candidate = 55.0;
            else if (fullRatio >= 2.5 && absoluteDelta >= 900.0) candidate = 38.0;
            else if (fullRatio >= 1.75 && absoluteDelta >= 600.0) candidate = 20.0;
            double anomaly = candidate;
            if (candidate >= 35.0) {
                anomaly = sameDirection && repeatedFloor >= 500.0 &&
                          rejectedSamples == 0
                    ? std::min(70.0, candidate + 10.0)
                    : 30.0;
            }
            SetAnomalyScore(
                result,
                anomaly,
                L"A high score requires a large baseline-adjusted differential repeated in the same direction across both halves.");

            const std::size_t auxMismatches = report.RdtscpAuxMismatchCount +
                report.StressAuxMismatchCount;
            result.reliability = std::clamp(
                minimumRetention *
                    (auxMismatches == 0 ? 1.0 : 0.75),
                0.45,
                1.0);
            if (anomaly >= 35.0) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = std::min(
                    24,
                    static_cast<int>(std::lround(anomaly * 0.34)));
                result.summary = L"The CPUID cost changed substantially and repeatably after bounded local work.";
                result.explanation = L"Load-dependent interception or TSC handling is one explanation. Power-state transitions, firmware, thermals, and host activity remain alternatives, so timing alone is never DETECTED.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"Baseline-adjusted CPUID timing remained stable across interleaved reference and local-work phases.";
                result.explanation = L"Non-repeatable half-to-half movement is treated as noise and cannot make this result suspicious.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

class KernelSvmConsistencyTest final : public IDetectionTest {
public:
    KernelSvmConsistencyTest() : metadata_{
        "kernel.svm_consistency",
        L"Kernel AMD SVM/NPT determinism",
        L"Kernel",
        L"Repeats Fn8000_000A thirty-two times on each representative core and compares the SVM/NPT capability tuple across cores and with the primary kernel snapshot.",
        ObservationSource::KernelMode} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        if (!context.driver.available) return DriverUnavailable(metadata_, context.driver);
        const auto& report = *context.driver.report;
        if ((report.CpuFlags & AHD_CPU_FLAG_SVM) == 0 ||
            static_cast<std::uint32_t>(report.Cpuid[2].Eax) < 0x8000000Au) {
            return Unavailable(metadata_, L"SVM or Fn8000_000A is not available in the kernel CPU view.");
        }
        return TimedRun(metadata_, [&] {
            TestResult result{};
            constexpr std::uint32_t comparedCpuFlags =
                AHD_CPU_FLAG_AMD |
                AHD_CPU_FLAG_HYPERVISOR |
                AHD_CPU_FLAG_SVM |
                AHD_CPU_FLAG_NPT |
                AHD_CPU_FLAG_RDTSCP;
            std::size_t confirmedCores{};
            std::size_t repeatMismatchCores{};
            std::size_t crossCoreLeafMismatches{};
            std::size_t cpuFlagMismatches{};
            std::size_t missingSvmLeafCores{};
            bool directHypervisor = (report.CpuFlags & AHD_CPU_FLAG_HYPERVISOR) != 0;
            const std::size_t coreCount = std::min<std::size_t>(
                report.CoreRecordCount, AHD_MAX_REPRESENTATIVE_CORES);

            result.measurements.push_back({
                L"Primary Fn8000_000A",
                L"EAX=" + Hex32(static_cast<std::uint32_t>(report.Cpuid[4].Eax)) +
                    L" EBX=" + Hex32(static_cast<std::uint32_t>(report.Cpuid[4].Ebx)) +
                    L" ECX=" + Hex32(static_cast<std::uint32_t>(report.Cpuid[4].Ecx)) +
                    L" EDX=" + Hex32(static_cast<std::uint32_t>(report.Cpuid[4].Edx)),
                L"Primary kernel SVM revision, ASID count, reserved field, and feature bitmap."});

            for (std::size_t index = 0; index < coreCount; ++index) {
                const auto& core = report.CoreTimings[index];
                if ((core.CoreFlags & AHD_CORE_FLAG_AFFINITY_CONFIRMED) == 0) {
                    continue;
                }
                ++confirmedCores;
                directHypervisor = directHypervisor ||
                    (core.CpuFlags & AHD_CPU_FLAG_HYPERVISOR) != 0;
                const bool svmLeafAvailable =
                    (core.CoreFlags & AHD_CORE_FLAG_SVM_LEAF_AVAILABLE) != 0;
                const bool repeatStable =
                    (core.CoreFlags & AHD_CORE_FLAG_SVM_LEAF_STABLE) != 0 &&
                    core.SvmLeafReadCount == AHD_SVM_STABILITY_READS &&
                    core.SvmLeafMismatchCount == 0;
                const bool leafMatches = svmLeafAvailable &&
                    KernelCpuidRecordEqual(core.SvmLeaf, report.Cpuid[4]);
                const bool flagsMatch =
                    (core.CpuFlags & comparedCpuFlags) ==
                    (report.CpuFlags & comparedCpuFlags);
                if (!svmLeafAvailable) ++missingSvmLeafCores;
                if (svmLeafAvailable && !repeatStable) ++repeatMismatchCores;
                if (svmLeafAvailable && !leafMatches) ++crossCoreLeafMismatches;
                if (!flagsMatch) ++cpuFlagMismatches;

                result.measurements.push_back({
                    L"Group " + std::to_wstring(core.ProcessorGroup) + L" CPU " +
                        std::to_wstring(static_cast<unsigned int>(core.ProcessorNumber)),
                    L"flags=" + Hex32(core.CpuFlags) +
                        L", reads=" + std::to_wstring(core.SvmLeafReadCount) +
                        L", repeat mismatches=" +
                        std::to_wstring(core.SvmLeafMismatchCount) +
                        L", primary match=" + BooleanText(leafMatches),
                    svmLeafAvailable
                        ? L"Fn8000_000A EAX=" +
                            Hex32(static_cast<std::uint32_t>(core.SvmLeaf.Eax)) +
                            L" EBX=" + Hex32(static_cast<std::uint32_t>(core.SvmLeaf.Ebx)) +
                            L" ECX=" + Hex32(static_cast<std::uint32_t>(core.SvmLeaf.Ecx)) +
                            L" EDX=" + Hex32(static_cast<std::uint32_t>(core.SvmLeaf.Edx))
                        : L"The core did not expose an architecturally valid SVM capability leaf."});
            }

            result.measurements.push_back({
                L"Consistency totals",
                L"confirmed=" + std::to_wstring(confirmedCores) +
                    L", repeated=" + std::to_wstring(repeatMismatchCores) +
                    L", cross-core=" + std::to_wstring(crossCoreLeafMismatches) +
                    L", CPU flags=" + std::to_wstring(cpuFlagMismatches) +
                    L", missing leaf=" + std::to_wstring(missingSvmLeafCores),
                L"Deterministic AMD SVM/NPT capability fields should not change between reads or representative cores."});

            if (confirmedCores < 2u && !directHypervisor) {
                result.verdict = Verdict::Unavailable;
                result.summary = L"Fewer than two representative cores completed the SVM consistency probe.";
                result.explanation = L"Incomplete affinity coverage is a quality failure and is not scored as hypervisor evidence.";
                return result;
            }

            double anomaly = 0.0;
            if (repeatMismatchCores != 0) anomaly += 60.0;
            if (crossCoreLeafMismatches != 0) anomaly += 55.0;
            if (cpuFlagMismatches != 0) anomaly += 50.0;
            if (missingSvmLeafCores != 0) anomaly += 40.0;
            anomaly = directHypervisor ? 100.0 : std::min(74.0, anomaly);
            SetAnomalyScore(
                result,
                anomaly,
                directHypervisor
                    ? L"The architectural hypervisor-present bit is direct evidence."
                    : L"Repeated/cross-core deterministic SVM state is strong consistency evidence, capped below DETECTED without a direct indicator.");
            const std::size_t expectedCores = std::min<std::size_t>(
                report.LogicalProcessorCount, AHD_MAX_REPRESENTATIVE_CORES);
            result.reliability = directHypervisor
                ? 1.0
                : std::clamp(
                    static_cast<double>(confirmedCores) /
                        static_cast<double>(std::max<std::size_t>(1u, expectedCores)),
                    0.55,
                    1.0);

            if (directHypervisor) {
                result.verdict = Verdict::Detected;
                result.confidenceContribution = 94;
                result.summary = L"The representative kernel CPU view exposes the architectural hypervisor-present bit.";
                result.explanation = L"This direct indicator can be expected with Hyper-V, VBS, or a virtual machine. The SVM consistency data is reported alongside it but is not needed for DETECTED.";
            } else if (anomaly >= 35.0) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = std::min(
                    55,
                    35 + static_cast<int>(
                        repeatMismatchCores + crossCoreLeafMismatches +
                        cpuFlagMismatches + missingSvmLeafCores) * 4);
                result.summary = L"Deterministic AMD SVM/NPT capability state changed across repeated or cross-core observations.";
                result.explanation = L"Selective or incomplete CPU-state virtualization can cause this pattern. Firmware faults or an unstable platform should still be excluded before attribution.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"AMD SVM/NPT capability fields remained deterministic across repeated and representative-core reads.";
                result.explanation = L"A lower hypervisor can provide a perfectly coherent capability view, so consistency is not proof of bare metal.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

CpuidRegisters RecordRegisters(const AHD_CPUID_RECORD& record) {
    return {record.Eax, record.Ebx, record.Ecx, record.Edx};
}

class CrossLayerTest final : public IDetectionTest {
public:
    CrossLayerTest() : metadata_{
        "cross_layer.cpuid_state",
        L"User / kernel observation parity",
        L"Cross-layer",
        L"Compares deterministic CPUID feature fields observed at CPL3 and CPL0 through the same synchronous device request.",
        ObservationSource::CrossLayer} {}

    const TestMetadata& Metadata() const noexcept override { return metadata_; }

    TestResult Run(const DetectionContext& context) const override {
        if (!context.cpu.Profile().isAmd) return Unavailable(metadata_, L"Requires an AMD processor.");
        if (!context.driver.available) return DriverUnavailable(metadata_, context.driver);
        return TimedRun(metadata_, [&] {
            TestResult result{};
            std::size_t mismatches{};
            const auto& report = *context.driver.report;
            const bool kernelSvmLeaf = (report.CpuFlags & AHD_CPU_FLAG_SVM) != 0 &&
                static_cast<std::uint32_t>(report.Cpuid[2].Eax) >= 0x8000000Au;
            const bool userSvmLeaf = context.cpu.HasSvm() &&
                context.cpu.Profile().maxExtendedLeaf >= 0x8000000Au;
            for (std::size_t index = 0; index < AHD_CPUID_RECORD_COUNT; ++index) {
                const auto& record = report.Cpuid[index];
                const std::uint32_t kernelBasicMaximum =
                    static_cast<std::uint32_t>(report.Cpuid[0].Eax);
                const std::uint32_t kernelExtendedMaximum =
                    static_cast<std::uint32_t>(report.Cpuid[2].Eax);
                const bool reservedByRange =
                    (record.Leaf == 1u &&
                     (kernelBasicMaximum < 1u || context.cpu.Profile().maxBasicLeaf < 1u)) ||
                    (record.Leaf >= 0x80000001u && record.Leaf < 0xC0000000u &&
                     (kernelExtendedMaximum < record.Leaf ||
                      context.cpu.Profile().maxExtendedLeaf < record.Leaf));
                if (reservedByRange) {
                    result.measurements.push_back({
                        L"CPUID " + Hex32(record.Leaf),
                        L"skipped",
                        L"The leaf is outside at least one reported CPUID range."});
                    continue;
                }
                if (record.Leaf == 0x8000000Au && (!kernelSvmLeaf || !userSvmLeaf)) {
                    result.measurements.push_back({
                        L"CPUID " + Hex32(record.Leaf),
                        L"skipped",
                        L"AMD reserves this leaf's interpretation when SVM is not advertised."});
                    continue;
                }
                auto kernel = RecordRegisters(record);
                CpuidRegisters user{};
                if (!context.cpu.TryCpuidOnProcessor(
                        report.ProcessorGroup,
                        report.ProcessorNumber,
                        record.Leaf,
                        record.Subleaf,
                        user)) {
                    return Unavailable(metadata_, L"Windows could not pin the user-mode comparison to the driver's processor.");
                }
                if (record.Leaf == 1u) {
                    kernel = NormalizeLeaf1(kernel);
                    user = NormalizeLeaf1(user);
                }
                const bool equal = kernel == user;
                if (!equal) ++mismatches;
                result.measurements.push_back({
                    L"CPUID " + Hex32(record.Leaf),
                    equal ? L"match" : L"mismatch",
                    L"user [EAX=" + Hex32(static_cast<std::uint32_t>(user.eax)) +
                    L" EBX=" + Hex32(static_cast<std::uint32_t>(user.ebx)) +
                    L" ECX=" + Hex32(static_cast<std::uint32_t>(user.ecx)) +
                    L" EDX=" + Hex32(static_cast<std::uint32_t>(user.edx)) +
                    L"], kernel [EAX=" + Hex32(static_cast<std::uint32_t>(kernel.eax)) +
                    L" EBX=" + Hex32(static_cast<std::uint32_t>(kernel.ebx)) +
                    L" ECX=" + Hex32(static_cast<std::uint32_t>(kernel.ecx)) +
                    L" EDX=" + Hex32(static_cast<std::uint32_t>(kernel.edx)) + L"]"});
            }
            result.measurements.push_back({L"Processor", L"group " + std::to_wstring(report.ProcessorGroup) +
                L", number " + std::to_wstring(report.ProcessorNumber), L"CPU selected for the kernel snapshot."});
            result.measurements.push_back({L"Driver ABI", L"v" + std::to_wstring(report.Version) + L", " +
                std::to_wstring(context.driver.bytesReturned) + L" bytes", L"Validated response used for CPL3/CPL0 parity."});
            result.measurements.push_back({L"Total mismatches", std::to_wstring(mismatches), L"Leaf 1 APIC-ID bits are excluded."});

            if (mismatches != 0) {
                result.verdict = Verdict::Suspicious;
                result.confidenceContribution = std::min(55, 30 + static_cast<int>(mismatches) * 5);
                result.summary = L"CPUID differs between user and kernel observations on " +
                    std::to_wstring(mismatches) + L" leaf/leaves.";
                result.explanation = L"Privilege-dependent CPUID filtering is unusual and can expose an incomplete VMM policy. CPU migration and platform-specific dynamic fields should still be excluded.";
            } else {
                result.verdict = Verdict::Pass;
                result.summary = L"Deterministic CPUID fields match across user and kernel mode.";
                result.explanation = L"A hypervisor can deliberately provide a coherent view at both privilege levels, so matching results are not conclusive.";
            }
            return result;
        });
    }

private:
    TestMetadata metadata_;
};

} // namespace

DetectionContext::DetectionContext()
    : cpu(), windows(QueryWindowsIndicators()) {
    if (cpu.Profile().isAmd) {
        driver = DriverClient{}.Query();
    } else {
        driver.statusText = L"Kernel probe skipped on a non-AMD processor.";
    }
}

DetectionEngine::DetectionEngine() {
    tests_.push_back(std::make_unique<CpuIdentityTest>());
    tests_.push_back(std::make_unique<HypervisorBitTest>());
    tests_.push_back(std::make_unique<HypervisorLeafTest>());
    tests_.push_back(std::make_unique<SvmCapabilityTest>());
    tests_.push_back(std::make_unique<CpuidConsistencyTest>());
    tests_.push_back(std::make_unique<WindowsHypervisorTest>());
    tests_.push_back(std::make_unique<TscStabilityTest>());
    tests_.push_back(std::make_unique<CpuidTimingTest>());
    tests_.push_back(std::make_unique<SvmLeafTimingTest>());
    tests_.push_back(std::make_unique<KernelSvmStateTest>());
    tests_.push_back(std::make_unique<KernelTimingTest>());
    tests_.push_back(std::make_unique<KernelMulticoreTimingTest>());
    tests_.push_back(std::make_unique<KernelLoadDifferentialTest>());
    tests_.push_back(std::make_unique<KernelSvmConsistencyTest>());
    tests_.push_back(std::make_unique<CrossLayerTest>());
}

DetectionSnapshot DetectionEngine::RunAll(const ProgressCallback& progress) const {
    DetectionSnapshot snapshot{};
    DetectionContext context;
    snapshot.timestampUtc = UtcTimestamp();
    snapshot.system = context.cpu.Profile();
    snapshot.system.windowsVersion = QueryWindowsVersion();
    snapshot.results.reserve(tests_.size());

    std::size_t completed{};
    if (progress) progress(completed, tests_.size());
    for (const auto& test : tests_) {
        snapshot.results.push_back(test->Run(context));
        ++completed;
        if (progress) progress(completed, tests_.size());
    }
    RecalculateOverall(snapshot);
    return snapshot;
}

TestResult DetectionEngine::RunOne(const std::string& id) const {
    const auto iterator = std::find_if(tests_.begin(), tests_.end(), [&](const auto& test) {
        return test->Metadata().id == id;
    });
    if (iterator == tests_.end()) {
        throw std::invalid_argument("Unknown test id: " + id);
    }
    DetectionContext context;
    return (*iterator)->Run(context);
}

std::vector<TestMetadata> DetectionEngine::Metadata() const {
    std::vector<TestMetadata> metadata;
    metadata.reserve(tests_.size());
    for (const auto& test : tests_) {
        metadata.push_back(test->Metadata());
    }
    return metadata;
}

void DetectionEngine::RecalculateOverall(DetectionSnapshot& snapshot) {
    if (!snapshot.system.isAmd) {
        snapshot.overallVerdict = Verdict::Unavailable;
        snapshot.confidenceScore = 0;
        snapshot.confidenceExplanation = L"AMD processor required; no AMD hypervisor conclusion was produced.";
        return;
    }

    int strongestDirect{};
    int timingSupport{};
    int cpuidSupport{};
    int stateSupport{};
    int windowsSupport{};
    bool hasDetected{};
    bool hasSuspicious{};
    std::size_t conclusive{};
    for (const auto& result : snapshot.results) {
        if (result.verdict == Verdict::Pass || result.verdict == Verdict::Suspicious ||
            result.verdict == Verdict::Detected) {
            ++conclusive;
        }
        const int weighted = static_cast<int>(std::lround(
            static_cast<double>(result.confidenceContribution) * result.reliability));
        if (result.verdict == Verdict::Detected) {
            hasDetected = true;
            strongestDirect = std::max(strongestDirect, weighted);
        } else if (result.verdict == Verdict::Suspicious) {
            hasSuspicious = true;
            const auto& id = result.metadata.id;
            if (id.starts_with("timing.") || id == "amd.svm_leaf_timing" ||
                id == "kernel.cpuid_timing" || id.starts_with("kernel.timing.")) {
                timingSupport += weighted;
            } else if (id == "cpuid.consistency" || id == "cpuid.hypervisor_leaves" ||
                       id == "cross_layer.cpuid_state") {
                cpuidSupport += weighted;
            } else if (id == "amd.svm_capability" || id == "kernel.svm_state" ||
                       id == "kernel.svm_consistency") {
                stateSupport += weighted;
            } else if (id == "windows.hypervisor_vbs") {
                windowsSupport += weighted;
            } else {
                stateSupport += weighted;
            }
        }
    }

    const int supporting = std::min(30, timingSupport) +
                           std::min(50, cpuidSupport) +
                           std::min(40, stateSupport) +
                           std::min(10, windowsSupport);

    if (conclusive == 0) {
        snapshot.overallVerdict = Verdict::Unavailable;
        snapshot.confidenceScore = 0;
        snapshot.confidenceExplanation = L"No conclusive tests were available.";
    } else if (hasDetected) {
        snapshot.overallVerdict = Verdict::Detected;
        snapshot.confidenceScore = std::clamp(strongestDirect + std::min(5, supporting / 10), 85, 100);
        snapshot.confidenceExplanation = L"At least one direct virtualization indicator is present; supporting heuristics can add at most five points.";
    } else if (hasSuspicious) {
        snapshot.overallVerdict = Verdict::Suspicious;
        snapshot.confidenceScore = std::clamp(supporting, 1, 79);
        snapshot.confidenceExplanation = L"Only indirect or inconsistent observations are present. Timing evidence is deliberately capped below DETECTED.";
    } else {
        snapshot.overallVerdict = Verdict::Pass;
        snapshot.confidenceScore = 0;
        snapshot.confidenceExplanation = L"No evidence was observed in this run. PASS does not prove that no hypervisor exists.";
    }
    if (snapshot.mixedCaptureTimes) {
        snapshot.confidenceExplanation += L" This snapshot combines tests captured at different times; each test records its own UTC capture time.";
    }
}

} // namespace ahd
