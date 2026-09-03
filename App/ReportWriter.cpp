#include "ReportWriter.h"

#include "PlatformUtils.h"

#include <Windows.h>

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>

namespace ahd {
namespace {

std::string JsonEscape(const std::wstring& value) {
    const std::string utf8 = WideToUtf8(value);
    std::ostringstream stream;
    for (const unsigned char character : utf8) {
        switch (character) {
        case '"': stream << "\\\""; break;
        case '\\': stream << "\\\\"; break;
        case '\b': stream << "\\b"; break;
        case '\f': stream << "\\f"; break;
        case '\n': stream << "\\n"; break;
        case '\r': stream << "\\r"; break;
        case '\t': stream << "\\t"; break;
        default:
            if (character < 0x20u) {
                stream << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                       << static_cast<unsigned int>(character) << std::dec;
            } else {
                stream << static_cast<char>(character);
            }
            break;
        }
    }
    return stream.str();
}

std::string JsonEscapeUtf8(const std::string& value) {
    return JsonEscape(Utf8ToWide(value));
}

std::string VerdictUtf8(const Verdict verdict) {
    return WideToUtf8(VerdictLabel(verdict));
}

std::string SourceUtf8(const ObservationSource source) {
    return WideToUtf8(SourceLabel(source));
}

std::string Serialize(const DetectionSnapshot& snapshot) {
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::fixed << std::setprecision(3);
    out << "{\n";
    out << "  \"schema\": \"amd-hypervisor-detector-report/v3\",\n";
    out << "  \"applicationVersion\": \"1.1.0\",\n";
    out << "  \"timestampUtc\": \"" << JsonEscape(snapshot.timestampUtc) << "\",\n";
    out << "  \"mixedCaptureTimes\": " << (snapshot.mixedCaptureTimes ? "true" : "false") << ",\n";
    out << "  \"platform\": {\n";
    out << "    \"amdSupported\": " << (snapshot.system.isAmd ? "true" : "false") << ",\n";
    out << "    \"cpuVendor\": \"" << JsonEscapeUtf8(snapshot.system.cpuVendor) << "\",\n";
    out << "    \"cpuBrand\": \"" << JsonEscapeUtf8(snapshot.system.cpuBrand) << "\",\n";
    out << "    \"windowsVersion\": \"" << JsonEscape(snapshot.system.windowsVersion) << "\",\n";
    out << "    \"logicalProcessorCount\": " << snapshot.system.logicalProcessorCount << ",\n";
    out << "    \"maxBasicCpuidLeaf\": " << snapshot.system.maxBasicLeaf << ",\n";
    out << "    \"maxExtendedCpuidLeaf\": " << snapshot.system.maxExtendedLeaf << "\n";
    out << "  },\n";
    out << "  \"overall\": {\n";
    out << "    \"verdict\": \"" << VerdictUtf8(snapshot.overallVerdict) << "\",\n";
    out << "    \"confidenceScore\": " << snapshot.confidenceScore << ",\n";
    out << "    \"interpretation\": \"" << JsonEscape(snapshot.confidenceExplanation) << "\"\n";
    out << "  },\n";
    out << "  \"tests\": [\n";

    for (std::size_t index = 0; index < snapshot.results.size(); ++index) {
        const auto& result = snapshot.results[index];
        out << "    {\n";
        out << "      \"id\": \"" << JsonEscapeUtf8(result.metadata.id) << "\",\n";
        out << "      \"title\": \"" << JsonEscape(result.metadata.title) << "\",\n";
        out << "      \"category\": \"" << JsonEscape(result.metadata.category) << "\",\n";
        out << "      \"source\": \"" << SourceUtf8(result.metadata.source) << "\",\n";
        out << "      \"description\": \"" << JsonEscape(result.metadata.description) << "\",\n";
        out << "      \"verdict\": \"" << VerdictUtf8(result.verdict) << "\",\n";
        out << "      \"confidenceContribution\": " << result.confidenceContribution << ",\n";
        out << "      \"reliability\": " << result.reliability << ",\n";
        out << "      \"anomalyScore\": ";
        if (result.anomalyScore.has_value() && std::isfinite(*result.anomalyScore)) {
            out << std::clamp(*result.anomalyScore, 0.0, 100.0);
        } else {
            out << "null";
        }
        out << ",\n";
        out << "      \"durationMs\": " << result.duration.count() << ",\n";
        out << "      \"capturedAtUtc\": \"" << JsonEscape(result.capturedAtUtc) << "\",\n";
        out << "      \"summary\": \"" << JsonEscape(result.summary) << "\",\n";
        out << "      \"explanation\": \"" << JsonEscape(result.explanation) << "\",\n";

        out << "      \"measurements\": [";
        if (!result.measurements.empty()) out << '\n';
        for (std::size_t measurementIndex = 0; measurementIndex < result.measurements.size(); ++measurementIndex) {
            const auto& measurement = result.measurements[measurementIndex];
            out << "        {\"name\": \"" << JsonEscape(measurement.name)
                << "\", \"value\": \"" << JsonEscape(measurement.value)
                << "\", \"interpretation\": \"" << JsonEscape(measurement.interpretation) << "\"}";
            out << (measurementIndex + 1 == result.measurements.size() ? "\n" : ",\n");
        }
        out << "      ],\n";

        out << "      \"timing\": ";
        if (!result.timing.has_value()) {
            out << "null,\n";
        } else {
            const auto& timing = *result.timing;
            out << "{\n";
            out << "        \"sampleCount\": " << timing.sampleCount << ",\n";
            out << "        \"average\": " << timing.average << ",\n";
            out << "        \"median\": " << timing.median << ",\n";
            out << "        \"p95\": " << timing.p95 << ",\n";
            out << "        \"maximum\": " << timing.maximum << ",\n";
            out << "        \"variance\": " << timing.variance << ",\n";
            out << "        \"standardDeviation\": " << timing.standardDeviation << ",\n";
            out << "        \"q1\": " << timing.q1 << ",\n";
            out << "        \"q3\": " << timing.q3 << ",\n";
            out << "        \"outlierCount\": " << timing.outlierCount << "\n";
            out << "      },\n";
        }

        out << "      \"additionalTimingSeries\": [";
        if (!result.additionalTimingSeries.empty()) out << '\n';
        for (std::size_t seriesIndex = 0;
             seriesIndex < result.additionalTimingSeries.size();
             ++seriesIndex) {
            const auto& series = result.additionalTimingSeries[seriesIndex];
            const auto& timing = series.statistics;
            out << "        {\n";
            out << "          \"name\": \"" << JsonEscape(series.name) << "\",\n";
            out << "          \"statistics\": {\n";
            out << "            \"sampleCount\": " << timing.sampleCount << ",\n";
            out << "            \"average\": " << timing.average << ",\n";
            out << "            \"median\": " << timing.median << ",\n";
            out << "            \"p95\": " << timing.p95 << ",\n";
            out << "            \"maximum\": " << timing.maximum << ",\n";
            out << "            \"variance\": " << timing.variance << ",\n";
            out << "            \"standardDeviation\": " << timing.standardDeviation << ",\n";
            out << "            \"q1\": " << timing.q1 << ",\n";
            out << "            \"q3\": " << timing.q3 << ",\n";
            out << "            \"outlierCount\": " << timing.outlierCount << "\n";
            out << "          },\n";
            out << "          \"rawSamples\": [";
            for (std::size_t sampleIndex = 0; sampleIndex < series.rawSamples.size(); ++sampleIndex) {
                if (sampleIndex != 0) out << ',';
                if (sampleIndex % 24 == 0) out << "\n            ";
                out << series.rawSamples[sampleIndex];
            }
            if (!series.rawSamples.empty()) out << '\n' << "          ";
            out << "]\n";
            out << "        }" << (seriesIndex + 1 == result.additionalTimingSeries.size() ? "\n" : ",\n");
        }
        out << "      ],\n";

        out << "      \"rawSamples\": [";
        for (std::size_t sampleIndex = 0; sampleIndex < result.rawSamples.size(); ++sampleIndex) {
            if (sampleIndex != 0) out << ',';
            if (sampleIndex % 24 == 0) out << "\n        ";
            out << result.rawSamples[sampleIndex];
        }
        if (!result.rawSamples.empty()) out << '\n' << "      ";
        out << "]\n";
        out << "    }" << (index + 1 == snapshot.results.size() ? "\n" : ",\n");
    }

    out << "  ],\n";
    out << "  \"limitations\": [\n";
    out << "    \"PASS means no evidence was observed; it does not prove the absence of a hypervisor.\",\n";
    out << "    \"Timing is affected by firmware, SMI, power management, interrupts, and system load.\",\n";
    out << "    \"A hypervisor can virtualize CPUID, CPU state, and timestamp counters consistently.\",\n";
    out << "    \"Timing values are TSC ticks and are not assumed to equal core-clock cycles.\",\n";
    out << "    \"The mapper-safe driver intentionally skips potentially faulting MSR probes.\"\n";
    out << "  ]\n";
    out << "}\n";
    return out.str();
}

std::wstring ErrorText(const DWORD error) {
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
        : L"error " + std::to_wstring(error);
    if (buffer != nullptr) LocalFree(buffer);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n')) text.pop_back();
    return text;
}

} // namespace

ReportWriteResult WriteJsonReport(const DetectionSnapshot& snapshot, const std::wstring& path) {
    ReportWriteResult result{};
    result.path = path;
    if (path.empty()) {
        result.error = L"No report path was supplied.";
        return result;
    }

    const std::filesystem::path destination(path);
    const std::filesystem::path temporary = destination.wstring() +
        L".tmp-" + FileSafeUtcTimestamp();
    std::error_code directoryError;
    if (!destination.parent_path().empty()) {
        std::filesystem::create_directories(destination.parent_path(), directoryError);
        if (directoryError) {
            result.error = L"Could not create the report directory: " +
                Utf8ToWide(directoryError.message());
            return result;
        }
    }

    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        if (!file) {
            result.error = L"Could not open the temporary report file.";
            return result;
        }
        const std::string json = Serialize(snapshot);
        file.write(json.data(), static_cast<std::streamsize>(json.size()));
        file.flush();
        if (!file) {
            result.error = L"Writing the report failed.";
            file.close();
            DeleteFileW(temporary.c_str());
            return result;
        }
    }

    if (MoveFileExW(
            temporary.c_str(),
            destination.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
        const DWORD error = GetLastError();
        DeleteFileW(temporary.c_str());
        result.error = L"Could not finalize the report: " + ErrorText(error);
        return result;
    }

    result.success = true;
    return result;
}

ReportWriteResult WriteAutomaticReport(const DetectionSnapshot& snapshot) {
    DWORD required = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
    std::wstring localAppData;
    if (required > 1) {
        localAppData.resize(required);
        const DWORD written = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData.data(), required);
        if (written == 0 || written >= required) {
            return {false, {}, L"Could not resolve LOCALAPPDATA for the automatic report."};
        }
        localAppData.resize(written);
    } else {
        const DWORD requiredPath = GetTempPath2W(0, nullptr);
        if (requiredPath == 0) {
            return {false, {}, L"Could not resolve a temporary directory for the automatic report."};
        }
        std::vector<wchar_t> temporary(static_cast<std::size_t>(requiredPath) + 1u, L'\0');
        const DWORD length = GetTempPath2W(
            static_cast<DWORD>(temporary.size()), temporary.data());
        if (length == 0 || length >= temporary.size()) {
            return {false, {}, L"Could not resolve a temporary directory for the automatic report."};
        }
        localAppData.assign(temporary.data(), length);
    }

    const std::filesystem::path path = std::filesystem::path(localAppData) /
        L"AmdHypervisorDetector" / L"Reports" /
        (L"amd-hv-report-" + FileSafeUtcTimestamp() + L".json");
    return WriteJsonReport(snapshot, path.wstring());
}

} // namespace ahd
