#pragma once
#include "../Alerts/Alerts.h"
#include <imgui.h>

#include <Windows.h>
#include <string>
#include <vector>

struct ProcEntity {
	std::string Name{ };
	DWORD PID = (unsigned long)-1;
};

namespace Globals {
	inline WINDOWINFO WindowInfo;
	inline ImVec2 ClientSize;

	inline std::vector<std::string> Logs;
	inline std::vector<AlertEntity> Alerts;
	inline std::vector<std::string> Threats;

	inline int ScanDelay = 1; // 1 sec defautl delay
}