#pragma once

#include <string>

namespace ahd {

std::wstring Utf8ToWide(const std::string& value);
std::string WideToUtf8(const std::wstring& value);
std::wstring QueryWindowsVersion();
std::wstring UtcTimestamp();
std::wstring FileSafeUtcTimestamp();

} // namespace ahd

