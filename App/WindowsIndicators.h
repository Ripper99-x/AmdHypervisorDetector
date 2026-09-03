#pragma once

#include "DetectionTypes.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace ahd {

struct WindowsIndicators {
    bool whpApiAvailable{};
    bool whpQuerySucceeded{};
    bool hypervisorPresent{};
    bool virtualizationFirmwareEnabled{};
    bool slatAvailable{};
    bool codeIntegrityQuerySucceeded{};
    std::uint32_t codeIntegrityOptions{};
    bool hvciEnabled{};
    std::optional<std::uint32_t> vbsConfigured;
    std::optional<std::uint32_t> hvciConfigured;
    std::optional<std::uint32_t> credentialGuardConfigured;
    std::uint32_t registryProbeFailures{};
    bool hasSuccessfulActiveStateProbe{};
    std::vector<Measurement> measurements;
};

WindowsIndicators QueryWindowsIndicators();

} // namespace ahd
