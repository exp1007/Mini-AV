#pragma once

#include <string>
#include <vector>

namespace FileIo {

std::wstring NtPathToWin32(const std::wstring& NtPath);
std::wstring ResolveFinalDosPath(const std::wstring& Win32Path);
bool HashFileSha256(const std::wstring& Win32Path, std::string& OutHexLower, size_t MaxBytes);

}
