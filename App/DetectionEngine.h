#pragma once

#include "CpuProbe.h"
#include "DetectionTypes.h"
#include "DriverClient.h"
#include "WindowsIndicators.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ahd {

struct DetectionContext {
    CpuProbe cpu;
    WindowsIndicators windows;
    DriverSnapshot driver;

    DetectionContext();
};

class IDetectionTest {
public:
    virtual ~IDetectionTest() = default;
    [[nodiscard]] virtual const TestMetadata& Metadata() const noexcept = 0;
    [[nodiscard]] virtual TestResult Run(const DetectionContext& context) const = 0;
};

class DetectionEngine final {
public:
    using ProgressCallback = std::function<void(std::size_t completed, std::size_t total)>;

    DetectionEngine();

    [[nodiscard]] DetectionSnapshot RunAll(const ProgressCallback& progress = {}) const;
    [[nodiscard]] TestResult RunOne(const std::string& id) const;
    [[nodiscard]] std::vector<TestMetadata> Metadata() const;

    static void RecalculateOverall(DetectionSnapshot& snapshot);

private:
    std::vector<std::unique_ptr<IDetectionTest>> tests_;
};

} // namespace ahd

