#pragma once
#include <vector>
#include <string>
#include <Windows.h>

namespace Utils {
	std::vector<ProcEntity> GetProcessList();

	// Strings
	std::string StrToLower(std::string str);
	std::string WideToMultiByte(WCHAR* pwstr);
}