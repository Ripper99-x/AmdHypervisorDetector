#include "WindowsIndicators.h"

#include "CpuProbe.h"

#include <Windows.h>
#include <winternl.h>

#include <string>

namespace ahd {
namespace {

constexpr ULONG kSystemCodeIntegrityInformation = 103u;
constexpr ULONG kCodeIntegrityHvciKmciEnabled = 0x400u;
constexpr ULONG kCodeIntegrityHvciKmciAuditModeEnabled = 0x800u;
constexpr ULONG kCodeIntegrityHvciKmciStrictModeEnabled = 0x1000u;
constexpr ULONG kCodeIntegrityHvciIumEnabled = 0x2000u;

struct SystemCodeIntegrityInformation {
    ULONG Length;
    ULONG CodeIntegrityOptions;
};

using NtQuerySystemInformationFunction = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using WHvGetCapabilityFunction = HRESULT(WINAPI*)(UINT32, PVOID, UINT32, UINT32*);

struct RegistryDwordProbe {
    std::optional<std::uint32_t> value;
    bool completed{};
};

RegistryDwordProbe ReadRegistryDword(
    const wchar_t* subkey,
    const wchar_t* valueName) {
    DWORD value{};
    DWORD valueSize = sizeof(value);
    const LSTATUS status = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        subkey,
        valueName,
        RRF_RT_REG_DWORD,
        nullptr,
        &value,
        &valueSize);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
        return {std::nullopt, true};
    }
    if (status != ERROR_SUCCESS) {
        return {std::nullopt, false};
    }
    return {static_cast<std::uint32_t>(value), true};
}

std::wstring OptionalDwordText(const std::optional<std::uint32_t>& value) {
    return value.has_value() ? std::to_wstring(*value) : L"not configured";
}

} // namespace

WindowsIndicators QueryWindowsIndicators() {
    WindowsIndicators result{};

    result.virtualizationFirmwareEnabled =
        IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED) != FALSE;
    result.slatAvailable =
        IsProcessorFeaturePresent(PF_SECOND_LEVEL_ADDRESS_TRANSLATION) != FALSE;

    if (const HMODULE platform = LoadLibraryExW(
            L"WinHvPlatform.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32); platform != nullptr) {
        result.whpApiAvailable = true;
        const auto queryCapability = reinterpret_cast<WHvGetCapabilityFunction>(
            GetProcAddress(platform, "WHvGetCapability"));
        if (queryCapability != nullptr) {
            BOOL present = FALSE;
            UINT32 written{};
            const HRESULT status = queryCapability(
                0u, // WHvCapabilityCodeHypervisorPresent
                &present,
                static_cast<UINT32>(sizeof(present)),
                &written);
            result.whpQuerySucceeded = SUCCEEDED(status) && written >= sizeof(present);
            result.hypervisorPresent = result.whpQuerySucceeded && present != FALSE;
        }
        FreeLibrary(platform);
    }

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto querySystemInformation = ntdll == nullptr
        ? nullptr
        : reinterpret_cast<NtQuerySystemInformationFunction>(
              GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (querySystemInformation != nullptr) {
        SystemCodeIntegrityInformation information{};
        information.Length = sizeof(information);
        const LONG status = querySystemInformation(
            kSystemCodeIntegrityInformation,
            &information,
            sizeof(information),
            nullptr);
        if (status >= 0) {
            result.codeIntegrityQuerySucceeded = true;
            result.codeIntegrityOptions = information.CodeIntegrityOptions;
            result.hvciEnabled = (information.CodeIntegrityOptions &
                (kCodeIntegrityHvciKmciEnabled |
                 kCodeIntegrityHvciKmciAuditModeEnabled |
                 kCodeIntegrityHvciKmciStrictModeEnabled |
                 kCodeIntegrityHvciIumEnabled)) != 0;
        }
    }

    const auto vbsProbe = ReadRegistryDword(
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        L"EnableVirtualizationBasedSecurity");
    const auto hvciProbe = ReadRegistryDword(
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        L"Enabled");
    const auto credentialGuardProbe = ReadRegistryDword(
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"LsaCfgFlags");
    result.vbsConfigured = vbsProbe.value;
    result.hvciConfigured = hvciProbe.value;
    result.credentialGuardConfigured = credentialGuardProbe.value;
    result.registryProbeFailures = static_cast<std::uint32_t>(!vbsProbe.completed) +
                                   static_cast<std::uint32_t>(!hvciProbe.completed) +
                                   static_cast<std::uint32_t>(!credentialGuardProbe.completed);
    result.hasSuccessfulActiveStateProbe = result.whpQuerySucceeded || result.codeIntegrityQuerySucceeded;

    result.measurements = {
        {L"Windows Hypervisor Platform", result.whpApiAvailable ? L"available" : L"unavailable",
         L"API availability alone does not indicate that a hypervisor is active."},
        {L"WHP hypervisor present", result.whpQuerySucceeded
             ? (result.hypervisorPresent ? L"true" : L"false")
             : L"query unavailable",
         L"A successful true result is direct Windows hypervisor evidence."},
        {L"Virtualization enabled by firmware", result.virtualizationFirmwareEnabled ? L"true" : L"false",
         L"This indicates firmware capability/state, not active virtualization."},
        {L"Second-level address translation", result.slatAvailable ? L"true" : L"false",
         L"SLAT is a hardware capability and is not evidence by itself."},
        {L"Code Integrity options", result.codeIntegrityQuerySucceeded
             ? Hex32(result.codeIntegrityOptions)
             : L"query unavailable",
         L"HVCI-related bits imply that the Windows hypervisor is in use."},
        {L"VBS registry configuration", OptionalDwordText(result.vbsConfigured),
         L"Configuration can remain set even when the hypervisor did not launch."},
        {L"HVCI registry configuration", OptionalDwordText(result.hvciConfigured),
         L"Configuration is supporting context rather than proof of an active hypervisor."},
        {L"Credential Guard configuration", OptionalDwordText(result.credentialGuardConfigured),
         L"A configured value is supporting context rather than direct evidence."},
        {L"Indicator query quality",
         result.hasSuccessfulActiveStateProbe && result.registryProbeFailures == 0
             ? L"complete"
             : L"partial",
         L"PASS requires at least one successful active-state query and no unexpected registry access failures."}
    };
    return result;
}

} // namespace ahd
