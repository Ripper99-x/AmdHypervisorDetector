#pragma once

#include "../Shared/DriverProtocol.h"

#include <Windows.h>

#include <cstdint>
#include <memory>
#include <string>

namespace ahd {

struct DriverSnapshot {
    bool available{};
    DWORD win32Error{};
    DWORD bytesReturned{};
    std::uint32_t requestedTimingSamples{};
    std::wstring statusText;
    std::unique_ptr<AHD_KERNEL_REPORT> report;
};

[[nodiscard]] bool ValidateKernelReport(
    const AHD_KERNEL_REPORT& report,
    DWORD returnedBytes,
    std::uint32_t requestedTimingSamples = AHD_MAX_KERNEL_TIMING_SAMPLES) noexcept;

class DriverClient final {
public:
    [[nodiscard]] DriverSnapshot Query(std::uint32_t timingSamples = AHD_MAX_KERNEL_TIMING_SAMPLES) const;
};

} // namespace ahd
