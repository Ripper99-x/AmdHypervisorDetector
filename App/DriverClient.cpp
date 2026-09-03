#include "DriverClient.h"

#include <algorithm>
#include <array>
#include <memory>

namespace ahd {
namespace {

struct HandleCloser {
    void operator()(void* value) const noexcept {
        const HANDLE handle = static_cast<HANDLE>(value);
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

using UniqueHandle = std::unique_ptr<void, HandleCloser>;

std::wstring Win32ErrorText(const DWORD error) {
    wchar_t* buffer{};
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<wchar_t*>(&buffer),
        0,
        nullptr);
    std::wstring text = length != 0 && buffer != nullptr
        ? std::wstring(buffer, length)
        : L"Win32 error " + std::to_wstring(error);
    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) {
        text.pop_back();
    }
    return text;
}

} // namespace

bool ValidateKernelReport(
    const AHD_KERNEL_REPORT& report,
    const DWORD returnedBytes,
    const std::uint32_t requestedTimingSamples) noexcept {
    if (requestedTimingSamples == 0 ||
        requestedTimingSamples > AHD_MAX_KERNEL_TIMING_SAMPLES) {
        return false;
    }
    if (returnedBytes != sizeof(AHD_KERNEL_REPORT) ||
        report.Size != sizeof(AHD_KERNEL_REPORT) ||
        report.Version != AHD_PROTOCOL_VERSION ||
        report.OperationStatus != 0 ||
        (report.CpuFlags & AHD_CPU_FLAG_AMD) == 0) {
        return false;
    }

    constexpr std::array<std::uint32_t, AHD_CPUID_RECORD_COUNT> expectedLeaves{
        0u, 1u, 0x80000000u, 0x80000001u, 0x8000000Au, 0x40000000u};
    constexpr std::uint32_t knownCpuFlags =
        AHD_CPU_FLAG_AMD |
        AHD_CPU_FLAG_HYPERVISOR |
        AHD_CPU_FLAG_SVM |
        AHD_CPU_FLAG_NPT |
        AHD_CPU_FLAG_RDTSCP;
    const DWORD activeLogicalProcessors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (report.Reserved0 != 0 || report.Reserved1 != 0 || report.Reserved2 != 0 ||
        (report.CpuFlags & ~knownCpuFlags) != 0 ||
        report.TimingSampleCount > requestedTimingSamples ||
        report.SvmTimingSampleCount > requestedTimingSamples ||
        report.TimingRejectedCount > requestedTimingSamples * 3u ||
        report.RdtscpCpuidSampleCount > requestedTimingSamples ||
        report.RdtscpBaselineSampleCount > requestedTimingSamples ||
        report.StressCpuidSampleCount > requestedTimingSamples ||
        report.StressBaselineSampleCount > requestedTimingSamples ||
        report.CoreRecordCount > AHD_MAX_REPRESENTATIVE_CORES ||
        report.LogicalProcessorCount == 0 ||
        report.LogicalProcessorCount < report.CoreRecordCount ||
        report.CoreRecordCount > std::min<std::uint32_t>(
            report.LogicalProcessorCount, AHD_MAX_REPRESENTATIVE_CORES) ||
        (activeLogicalProcessors != 0 &&
         report.LogicalProcessorCount > activeLogicalProcessors)) {
        return false;
    }
    for (std::size_t index = 0; index < expectedLeaves.size(); ++index) {
        if (report.Cpuid[index].Leaf != expectedLeaves[index] ||
            report.Cpuid[index].Subleaf != 0u) {
            return false;
        }
    }
    if (report.ProcessorGroup >= GetActiveProcessorGroupCount() ||
        report.ProcessorNumber >= GetActiveProcessorCount(report.ProcessorGroup)) {
        return false;
    }
    const std::uint32_t requiredProbeFlags =
        AHD_PROBE_FLAG_MAPPER_SAFE |
        AHD_PROBE_FLAG_MSR_READS_SKIPPED |
        AHD_PROBE_FLAG_RDTSC_TIMING;
    const std::uint32_t knownProbeFlags =
        requiredProbeFlags |
        AHD_PROBE_FLAG_RDTSCP_TIMING |
        AHD_PROBE_FLAG_STRESS_TIMING |
        AHD_PROBE_FLAG_MULTICORE_TIMING |
        AHD_PROBE_FLAG_SVM_STABILITY;
    if ((report.ProbeFlags & requiredProbeFlags) != requiredProbeFlags ||
        (report.ProbeFlags & ~knownProbeFlags) != 0) {
        return false;
    }

    const bool rdtscp = (report.CpuFlags & AHD_CPU_FLAG_RDTSCP) != 0;
    const bool svm = (report.CpuFlags & AHD_CPU_FLAG_SVM) != 0;
    const std::uint32_t rdtscpProbeFlags =
        AHD_PROBE_FLAG_RDTSCP_TIMING | AHD_PROBE_FLAG_STRESS_TIMING;
    if (rdtscp) {
        const std::uint64_t referenceRejected =
            static_cast<std::uint64_t>(report.RdtscpCpuidRejectedCount) +
            report.RdtscpBaselineRejectedCount;
        const std::uint64_t stressRejected =
            static_cast<std::uint64_t>(report.StressCpuidRejectedCount) +
            report.StressBaselineRejectedCount;
        if ((report.ProbeFlags & rdtscpProbeFlags) != rdtscpProbeFlags ||
            static_cast<std::uint64_t>(report.RdtscpCpuidSampleCount) +
                report.RdtscpCpuidRejectedCount !=
                requestedTimingSamples ||
            static_cast<std::uint64_t>(report.RdtscpBaselineSampleCount) +
                report.RdtscpBaselineRejectedCount !=
                requestedTimingSamples ||
            static_cast<std::uint64_t>(report.StressCpuidSampleCount) +
                report.StressCpuidRejectedCount !=
                requestedTimingSamples ||
            static_cast<std::uint64_t>(report.StressBaselineSampleCount) +
                report.StressBaselineRejectedCount !=
                requestedTimingSamples ||
            report.RdtscpAuxMismatchCount > referenceRejected ||
            report.StressAuxMismatchCount > stressRejected) {
            return false;
        }
    } else if ((report.ProbeFlags & rdtscpProbeFlags) != 0 ||
               report.RdtscpCpuidSampleCount != 0 ||
               report.RdtscpBaselineSampleCount != 0 ||
               report.StressCpuidSampleCount != 0 ||
               report.StressBaselineSampleCount != 0 ||
               report.RdtscpCpuidRejectedCount != 0 ||
               report.RdtscpBaselineRejectedCount != 0 ||
               report.StressCpuidRejectedCount != 0 ||
               report.StressBaselineRejectedCount != 0 ||
               report.RdtscpAuxMismatchCount != 0 ||
               report.StressAuxMismatchCount != 0) {
        return false;
    }

    constexpr std::uint32_t knownCoreFlags =
        AHD_CORE_FLAG_AFFINITY_CONFIRMED |
        AHD_CORE_FLAG_RDTSCP_SUPPORTED |
        AHD_CORE_FLAG_AUX_STABLE |
        AHD_CORE_FLAG_SVM_LEAF_AVAILABLE |
        AHD_CORE_FLAG_SVM_LEAF_STABLE |
        AHD_CORE_FLAG_STATE_MATCHES_PRIMARY |
        AHD_CORE_FLAG_TIMING_COMPLETE;
    for (std::size_t index = 0; index < report.CoreRecordCount; ++index) {
        const auto& core = report.CoreTimings[index];
        if ((core.CoreFlags & ~knownCoreFlags) != 0 ||
            (core.CpuFlags & ~knownCpuFlags) != 0 ||
            core.ProcessorGroup >= GetActiveProcessorGroupCount() ||
            core.ProcessorNumber >= GetActiveProcessorCount(core.ProcessorGroup) ||
            core.CpuidSampleCount > AHD_PER_CORE_TIMING_SAMPLES ||
            core.BaselineSampleCount > AHD_PER_CORE_TIMING_SAMPLES ||
            core.SvmLeafReadCount > AHD_SVM_STABILITY_READS ||
            core.SvmLeafMismatchCount > core.SvmLeafReadCount ||
            core.RdtscpAuxMismatchCount > AHD_PER_CORE_TIMING_SAMPLES * 2u) {
            return false;
        }
        for (std::size_t prior = 0; prior < index; ++prior) {
            if (report.CoreTimings[prior].ProcessorGroup == core.ProcessorGroup &&
                report.CoreTimings[prior].ProcessorNumber == core.ProcessorNumber) {
                return false;
            }
        }
        const bool affinityConfirmed =
            (core.CoreFlags & AHD_CORE_FLAG_AFFINITY_CONFIRMED) != 0;
        const bool coreRdtscp = (core.CpuFlags & AHD_CPU_FLAG_RDTSCP) != 0;
        const bool svmLeafAvailable =
            (core.CoreFlags & AHD_CORE_FLAG_SVM_LEAF_AVAILABLE) != 0;
        const bool timingComplete =
            core.CpuidSampleCount == AHD_PER_CORE_TIMING_SAMPLES &&
            core.BaselineSampleCount == AHD_PER_CORE_TIMING_SAMPLES;
        const bool auxStable = core.RdtscpAuxMismatchCount == 0 &&
            core.CpuidSampleCount != 0 && core.BaselineSampleCount != 0;
        const bool svmStable = svmLeafAvailable &&
            core.SvmLeafReadCount == AHD_SVM_STABILITY_READS &&
            core.SvmLeafMismatchCount == 0;
        if (affinityConfirmed && (core.CpuFlags & AHD_CPU_FLAG_AMD) == 0) {
            return false;
        }
        if (((core.CoreFlags & AHD_CORE_FLAG_RDTSCP_SUPPORTED) != 0) != coreRdtscp ||
            (coreRdtscp && affinityConfirmed &&
             (static_cast<std::uint64_t>(core.CpuidSampleCount) +
                  core.CpuidRejectedCount !=
                  AHD_PER_CORE_TIMING_SAMPLES ||
              static_cast<std::uint64_t>(core.BaselineSampleCount) +
                  core.BaselineRejectedCount !=
                  AHD_PER_CORE_TIMING_SAMPLES)) ||
            (!coreRdtscp && (core.CpuidSampleCount != 0 ||
                             core.BaselineSampleCount != 0 ||
                             core.CpuidRejectedCount != 0 ||
                             core.BaselineRejectedCount != 0)) ||
            (((core.CoreFlags & AHD_CORE_FLAG_TIMING_COMPLETE) != 0) != timingComplete) ||
            (((core.CoreFlags & AHD_CORE_FLAG_AUX_STABLE) != 0) != auxStable) ||
            (((core.CoreFlags & AHD_CORE_FLAG_SVM_LEAF_STABLE) != 0) != svmStable) ||
            (svmLeafAvailable && core.SvmLeafReadCount != AHD_SVM_STABILITY_READS) ||
            (!svmLeafAvailable &&
             (core.SvmLeafReadCount != 0 || core.SvmLeafMismatchCount != 0)) ||
            (svmLeafAvailable &&
             (core.SvmLeaf.Leaf != 0x8000000Au || core.SvmLeaf.Subleaf != 0u))) {
            return false;
        }
    }

    if (report.CoreRecordCount != 0) {
        if (rdtscp && (report.ProbeFlags & AHD_PROBE_FLAG_MULTICORE_TIMING) == 0) {
            return false;
        }
        if (svm && (report.ProbeFlags & AHD_PROBE_FLAG_SVM_STABILITY) == 0) {
            return false;
        }
    }
    return true;
}

DriverSnapshot DriverClient::Query(const std::uint32_t timingSamples) const {
    DriverSnapshot result{};
    result.requestedTimingSamples = std::clamp<std::uint32_t>(
        timingSamples, 1u, AHD_MAX_KERNEL_TIMING_SAMPLES);
    UniqueHandle handle(CreateFileW(
        AHD_DEVICE_WIN32_NAME,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (handle.get() == INVALID_HANDLE_VALUE) {
        const DWORD openError = GetLastError();
        handle.release();
        result.win32Error = openError;
        if (result.win32Error == ERROR_FILE_NOT_FOUND || result.win32Error == ERROR_PATH_NOT_FOUND) {
            result.statusText = L"Kernel probe not mapped (device was not found).";
        } else if (result.win32Error == ERROR_ACCESS_DENIED) {
            result.statusText = L"Kernel probe is present but access requires an elevated app.";
        } else {
            result.statusText = L"Kernel probe open failed: " + Win32ErrorText(result.win32Error);
        }
        return result;
    }

    AHD_QUERY_REQUEST request{};
    request.Size = sizeof(request);
    request.Version = AHD_PROTOCOL_VERSION;
    request.RequestedTimingSamples = result.requestedTimingSamples;
    result.report = std::make_unique<AHD_KERNEL_REPORT>();

    DWORD returned{};
    const BOOL success = DeviceIoControl(
        handle.get(),
        AHD_IOCTL_QUERY_REPORT,
        &request,
        sizeof(request),
        result.report.get(),
        sizeof(*result.report),
        &returned,
        nullptr);
    if (success == FALSE) {
        result.win32Error = GetLastError();
        if (result.win32Error == ERROR_REVISION_MISMATCH) {
            result.statusText = L"An older mapped kernel probe is still resident. Reboot, then map the protocol-v" +
                std::to_wstring(AHD_PROTOCOL_VERSION) + L" driver from this build.";
        } else {
            result.statusText = L"Kernel probe query failed: " + Win32ErrorText(result.win32Error);
        }
        return result;
    }
    result.bytesReturned = returned;
    if (!ValidateKernelReport(
            *result.report,
            returned,
            result.requestedTimingSamples)) {
        result.win32Error = ERROR_INVALID_DATA;
        result.statusText = L"Kernel probe returned malformed or incompatible protocol-v" +
            std::to_wstring(AHD_PROTOCOL_VERSION) + L" data.";
        return result;
    }

    result.available = true;
    result.statusText = L"Kernel probe connected (protocol v" +
        std::to_wstring(result.report->Version) + L").";
    return result;
}

} // namespace ahd
