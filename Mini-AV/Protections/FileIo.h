#pragma once

#include <string>
#include <vector>

namespace FileIo {

std::wstring NtPathToWin32(const std::wstring& NtPath);
std::wstring ResolveFinalDosPath(const std::wstring& Win32Path);
bool ReadFileSample(const std::wstring& Win32Path, std::vector<unsigned char>& OutBuffer, size_t MaxBytes);

}
