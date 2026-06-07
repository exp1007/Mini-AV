#pragma once

#include <string>

namespace HashDatabase {

bool Initialize();
void Shutdown();
bool IsDenied(const std::string& Sha256HexLower);
size_t DenyCount();
std::wstring DatabasePath();

}
