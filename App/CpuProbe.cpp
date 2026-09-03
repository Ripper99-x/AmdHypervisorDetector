#include "CpuProbe.h"

#include <Windows.h>
#include <intrin.h>
#include <immintrin.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace ahd {
namespace {

class SamplingScope final {
public:
    SamplingScope(const WORD group = 0, const BYTE number = 0) noexcept {
        oldPriority_ = GetThreadPriority(GetCurrentThread());
        if (oldPriority_ != THREAD_PRIORITY_ERROR_RETURN) {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
        }

        GROUP_AFFINITY target{};
        if (number >= sizeof(KAFFINITY) * 8u ||
            group >= GetActiveProcessorGroupCount() ||
            number >= GetActiveProcessorCount(group)) {
            return;
        }
        target.Group = group;
        target.Mask = static_cast<KAFFINITY>(1) << number;
        if (GetThreadGroupAffinity(GetCurrentThread(), &previousAffinity_) != FALSE &&
            SetThreadGroupAffinity(GetCurrentThread(), &target, nullptr) != FALSE) {
            affinityChanged_ = true;
        }
    }

    ~SamplingScope() {
        if (affinityChanged_) {
            SetThreadGroupAffinity(GetCurrentThread(), &previousAffinity_, nullptr);
        }
        if (oldPriority_ != THREAD_PRIORITY_ERROR_RETURN) {
            SetThreadPriority(GetCurrentThread(), oldPriority_);
        }
    }

    SamplingScope(const SamplingScope&) = delete;
    SamplingScope& operator=(const SamplingScope&) = delete;
    [[nodiscard]] bool Ready() const noexcept { return affinityChanged_; }

private:
    GROUP_AFFINITY previousAffinity_{};
    int oldPriority_{THREAD_PRIORITY_ERROR_RETURN};
    bool affinityChanged_{};
};

std::uint64_t BeginTsc() noexcept {
    _mm_lfence();
    return __rdtsc();
}

std::uint64_t EndTsc(unsigned int* auxiliary) noexcept {
    const auto value = __rdtscp(auxiliary);
    _mm_lfence();
    return value;
}

__declspec(noinline) bool ProbeTimestampInstructions() noexcept {
    __try {
        unsigned int auxiliary{};
        const volatile std::uint64_t first = __rdtsc();
        const volatile std::uint64_t second = __rdtscp(&auxiliary);
        (void)first;
        (void)second;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::string TrimCpuBrand(std::string value) {
    const auto first = value.find_first_not_of(' ');
    const auto last = value.find_last_not_of(' ');
    if (first == std::string::npos) {
        return {};
    }
    return value.substr(first, last - first + 1);
}

} // namespace

CpuProbe::CpuProbe() {
    const auto leaf0 = Cpuid(0);
    profile_.maxBasicLeaf = static_cast<std::uint32_t>(leaf0.eax);
    profile_.cpuVendor = CpuidVendorString(leaf0);
    profile_.isAmd = profile_.cpuVendor == "AuthenticAMD";

    const auto extendedMax = Cpuid(0x80000000u);
    profile_.maxExtendedLeaf = static_cast<std::uint32_t>(extendedMax.eax);

    if (profile_.maxExtendedLeaf >= 0x80000004u) {
        std::array<char, 49> brand{};
        for (std::uint32_t index = 0; index < 3; ++index) {
            const auto regs = Cpuid(0x80000002u + index);
            std::memcpy(brand.data() + index * 16 + 0, &regs.eax, sizeof(regs.eax));
            std::memcpy(brand.data() + index * 16 + 4, &regs.ebx, sizeof(regs.ebx));
            std::memcpy(brand.data() + index * 16 + 8, &regs.ecx, sizeof(regs.ecx));
            std::memcpy(brand.data() + index * 16 + 12, &regs.edx, sizeof(regs.edx));
        }
        profile_.cpuBrand = TrimCpuBrand(brand.data());
    }

    profile_.logicalProcessorCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    const bool rdtscpAdvertised = profile_.maxExtendedLeaf >= 0x80000001u &&
        (static_cast<std::uint32_t>(Cpuid(0x80000001u).edx) & (1u << 27)) != 0;
    timestampInstructionsUsable_ = rdtscpAdvertised && ProbeTimestampInstructions();
}

CpuidRegisters CpuProbe::Cpuid(const std::uint32_t leaf, const std::uint32_t subleaf) const noexcept {
    int registers[4]{};
    __cpuidex(registers, static_cast<int>(leaf), static_cast<int>(subleaf));
    return {
        registers[0],
        registers[1],
        registers[2],
        registers[3]
    };
}

bool CpuProbe::HasHypervisorBit() const noexcept {
    return profile_.maxBasicLeaf >= 1u &&
           (static_cast<std::uint32_t>(Cpuid(1).ecx) & (1u << 31)) != 0;
}

bool CpuProbe::HasSvm() const noexcept {
    return profile_.maxExtendedLeaf >= 0x80000001u &&
           (static_cast<std::uint32_t>(Cpuid(0x80000001u).ecx) & (1u << 2)) != 0;
}

bool CpuProbe::HasRdtscp() const noexcept {
    return profile_.maxExtendedLeaf >= 0x80000001u &&
           (static_cast<std::uint32_t>(Cpuid(0x80000001u).edx) & (1u << 27)) != 0;
}

bool CpuProbe::HasInvariantTsc() const noexcept {
    return profile_.maxExtendedLeaf >= 0x80000007u &&
           (static_cast<std::uint32_t>(Cpuid(0x80000007u).edx) & (1u << 8)) != 0;
}

bool CpuProbe::HasNpt() const noexcept {
    return HasSvm() && profile_.maxExtendedLeaf >= 0x8000000Au &&
           (static_cast<std::uint32_t>(Cpuid(0x8000000Au).edx) & 1u) != 0;
}

bool CpuProbe::TryCpuidOnProcessor(
    const std::uint16_t group,
    const std::uint8_t number,
    const std::uint32_t leaf,
    const std::uint32_t subleaf,
    CpuidRegisters& value) const noexcept {
    SamplingScope scope(group, number);
    if (!scope.Ready()) {
        return false;
    }
    value = Cpuid(leaf, subleaf);
    return true;
}

TimedSamples CpuProbe::MeasureCpuid(
    const std::uint32_t leaf,
    const std::uint32_t subleaf,
    const std::size_t sampleCount) const {
    TimedSamples result{};
    result.attempted = sampleCount;
    if (!HasRdtscp() || !timestampInstructionsUsable_ || sampleCount == 0) {
        return result;
    }
    result.values.reserve(sampleCount);

    SamplingScope scope;
    result.affinityApplied = scope.Ready();
    if (!result.affinityApplied) {
        return result;
    }
    int registers[4]{};
    for (std::size_t warmup = 0; warmup < 96; ++warmup) {
        __cpuidex(registers, static_cast<int>(leaf), static_cast<int>(subleaf));
    }

    unsigned int expectedAux{};
    (void)__rdtscp(&expectedAux);
    _mm_lfence();
    for (std::size_t sample = 0; sample < sampleCount; ++sample) {
        unsigned int auxiliary{};
        const auto begin = BeginTsc();
        __cpuidex(registers, static_cast<int>(leaf), static_cast<int>(subleaf));
        const auto end = EndTsc(&auxiliary);
        if (auxiliary != expectedAux) {
            ++result.auxChangeCount;
            ++result.rejected;
        } else if (end >= begin) {
            result.values.push_back(end - begin);
        } else {
            ++result.rejected;
        }
        if ((sample & 0xffu) == 0xffu) {
            SwitchToThread();
        }
    }

    volatile int sink = registers[0];
    (void)sink;
    return result;
}

TimedSamples CpuProbe::MeasureTscBaseline(const std::size_t sampleCount) const {
    TimedSamples result{};
    result.attempted = sampleCount;
    if (!HasRdtscp() || !timestampInstructionsUsable_ || sampleCount == 0) {
        return result;
    }
    result.values.reserve(sampleCount);

    SamplingScope scope;
    result.affinityApplied = scope.Ready();
    if (!result.affinityApplied) {
        return result;
    }
    unsigned int expectedAux{};
    (void)__rdtscp(&expectedAux);
    _mm_lfence();
    for (std::size_t sample = 0; sample < sampleCount; ++sample) {
        unsigned int auxiliary{};
        const auto begin = BeginTsc();
        const auto end = EndTsc(&auxiliary);
        if (auxiliary != expectedAux) {
            ++result.auxChangeCount;
            ++result.rejected;
        } else if (end >= begin) {
            result.values.push_back(end - begin);
        } else {
            ++result.rejected;
        }
        if ((sample & 0xffu) == 0xffu) {
            SwitchToThread();
        }
    }
    return result;
}

TscStabilitySamples CpuProbe::MeasureTscStability(const std::size_t sampleCount) const {
    TscStabilitySamples result;
    if (!HasRdtscp() || !timestampInstructionsUsable_ || sampleCount == 0) {
        return result;
    }
    result.deltas.reserve(sampleCount);

    SamplingScope scope;
    result.affinityApplied = scope.Ready();
    if (!result.affinityApplied) {
        return result;
    }
    unsigned int previousAux{};
    auto previous = __rdtscp(&previousAux);
    _mm_lfence();
    for (std::size_t sample = 0; sample < sampleCount; ++sample) {
        unsigned int currentAux{};
        const auto current = __rdtscp(&currentAux);
        _mm_lfence();
        if (currentAux != previousAux) {
            ++result.auxChangeCount;
        } else if (current < previous) {
            ++result.backwardsCount;
        } else {
            result.deltas.push_back(current - previous);
        }
        previous = current;
        previousAux = currentAux;
    }
    return result;
}

std::string CpuidVendorString(const CpuidRegisters& leaf0) {
    std::array<char, 13> vendor{};
    std::memcpy(vendor.data() + 0, &leaf0.ebx, sizeof(leaf0.ebx));
    std::memcpy(vendor.data() + 4, &leaf0.edx, sizeof(leaf0.edx));
    std::memcpy(vendor.data() + 8, &leaf0.ecx, sizeof(leaf0.ecx));
    return vendor.data();
}

std::string HypervisorVendorString(const CpuidRegisters& leaf40000000) {
    std::array<char, 13> vendor{};
    std::memcpy(vendor.data() + 0, &leaf40000000.ebx, sizeof(leaf40000000.ebx));
    std::memcpy(vendor.data() + 4, &leaf40000000.ecx, sizeof(leaf40000000.ecx));
    std::memcpy(vendor.data() + 8, &leaf40000000.edx, sizeof(leaf40000000.edx));
    return vendor.data();
}

std::wstring Hex32(const std::uint32_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0') << value;
    return stream.str();
}

std::wstring Hex64(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(16) << std::setfill(L'0') << value;
    return stream.str();
}

bool IsPrintableSignature(const std::string& signature) noexcept {
    bool hasVisibleCharacter = false;
    for (const unsigned char character : signature) {
        if (character == 0 || character == ' ') {
            continue;
        }
        if (character < 0x20 || character > 0x7e) {
            return false;
        }
        hasVisibleCharacter = true;
    }
    return hasVisibleCharacter;
}

} // namespace ahd
