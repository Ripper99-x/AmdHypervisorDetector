#pragma once

#include "DetectionTypes.h"

#include <string>

namespace ahd {

struct ReportWriteResult {
    bool success{};
    std::wstring path;
    std::wstring error;
};

ReportWriteResult WriteJsonReport(const DetectionSnapshot& snapshot, const std::wstring& path);
ReportWriteResult WriteAutomaticReport(const DetectionSnapshot& snapshot);

} // namespace ahd

