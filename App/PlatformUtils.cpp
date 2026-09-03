#include "PlatformUtils.h"

#include <Windows.h>
#include <winternl.h>

#include <atomic>
#include <iomanip>
#include <sstream>

namespace ahd {

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int length = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) {
        return L"<encoding error>";
    }
    std::wstring output(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), output.data(), length);
    return output;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int length = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return "<encoding error>";
    }
    std::string output(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), output.data(), length, nullptr, nullptr);
    return output;
}

std::wstring QueryWindowsVersion() {
    using RtlGetVersionFunction = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto rtlGetVersion = ntdll == nullptr
        ? nullptr
        : reinterpret_cast<RtlGetVersionFunction>(GetProcAddress(ntdll, "RtlGetVersion"));
    if (rtlGetVersion == nullptr) {
        return L"Windows (version unavailable)";
    }

    RTL_OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    if (rtlGetVersion(&version) != 0) {
        return L"Windows (version unavailable)";
    }

    std::wostringstream stream;
    stream << L"Windows " << version.dwMajorVersion << L'.' << version.dwMinorVersion
           << L" build " << version.dwBuildNumber;
    return stream.str();
}

std::wstring UtcTimestamp() {
    SYSTEMTIME time{};
    GetSystemTime(&time);
    std::wostringstream stream;
    stream << std::setfill(L'0')
           << std::setw(4) << time.wYear << L'-'
           << std::setw(2) << time.wMonth << L'-'
           << std::setw(2) << time.wDay << L'T'
           << std::setw(2) << time.wHour << L':'
           << std::setw(2) << time.wMinute << L':'
           << std::setw(2) << time.wSecond << L'.'
           << std::setw(3) << time.wMilliseconds << L'Z';
    return stream.str();
}

std::wstring FileSafeUtcTimestamp() {
    static std::atomic_uint32_t sequence{};
    SYSTEMTIME time{};
    GetSystemTime(&time);
    std::wostringstream stream;
    stream << std::setfill(L'0')
           << std::setw(4) << time.wYear
           << std::setw(2) << time.wMonth
           << std::setw(2) << time.wDay << L'-'
           << std::setw(2) << time.wHour
           << std::setw(2) << time.wMinute
           << std::setw(2) << time.wSecond << L'-'
           << std::setw(3) << time.wMilliseconds << L"-p"
           << GetCurrentProcessId() << L'-'
           << sequence.fetch_add(1, std::memory_order_relaxed);
    return stream.str();
}

} // namespace ahd
