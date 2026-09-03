#pragma once

#include "DetectionTypes.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ahd {

struct CpuidRegisters {
    std::int32_t eax{};
    std::int32_t ebx{};
    std::int32_t ecx{};
    std::int32_t edx{};

    bool operator==(const CpuidRegisters&) const = default;
};

struct TscStabilitySamples {
    std::vector<std::uint64_t> deltas;
    std::size_t backwardsCount{};
    std::size_t auxChangeCount{};
    bool affinityApplied{};
};

struct TimedSamples {
    std::vector<std::uint64_t> values;
    std::size_t attempted{};
    std::size_t rejected{};
    std::size_t auxChangeCount{};
    bool affinityApplied{};
};

class CpuProbe final {
public:
    CpuProbe();

    [[nodiscard]] const SystemProfile& Profile() const noexcept { return profile_; }
    [[nodiscard]] CpuidRegisters Cpuid(std::uint32_t leaf, std::uint32_t subleaf = 0) const noexcept;
    [[nodiscard]] bool HasHypervisorBit() const noexcept;
    [[nodiscard]] bool HasSvm() const noexcept;
    [[nodiscard]] bool HasRdtscp() const noexcept;
    [[nodiscard]] bool HasInvariantTsc() const noexcept;
    [[nodiscard]] bool TimestampInstructionsUsable() const noexcept {
        return timestampInstructionsUsable_;
    }
    [[nodiscard]] bool HasNpt() const noexcept;
    [[nodiscard]] bool TryCpuidOnProcessor(
        std::uint16_t group,
        std::uint8_t number,
        std::uint32_t leaf,
        std::uint32_t subleaf,
        CpuidRegisters& value) const noexcept;

    [[nodiscard]] TimedSamples MeasureCpuid(
        std::uint32_t leaf,
        std::uint32_t subleaf,
        std::size_t sampleCount) const;
    [[nodiscard]] TimedSamples MeasureTscBaseline(std::size_t sampleCount) const;
    [[nodiscard]] TscStabilitySamples MeasureTscStability(std::size_t sampleCount) const;

private:
    SystemProfile profile_;
    bool timestampInstructionsUsable_{};
};

std::string CpuidVendorString(const CpuidRegisters& leaf0);
std::string HypervisorVendorString(const CpuidRegisters& leaf40000000);
std::wstring Hex32(std::uint32_t value);
std::wstring Hex64(std::uint64_t value);
bool IsPrintableSignature(const std::string& signature) noexcept;

} // namespace ahd
