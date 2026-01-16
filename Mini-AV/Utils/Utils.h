#pragma once
#include <vector>
#include <string>
#include <Windows.h>

namespace Utils {
	// Process
	std::string GetProcName(DWORD processID);
	std::vector<ProcEntity> GetProcessList();

	// Strings
	std::string StrToLower(std::string str);
	std::string WideToMultiByte(WCHAR* pwstr);
}