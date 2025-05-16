#pragma once
#include "../Globals.h"

namespace Config {
    struct CFGType {
		// General/UI
		bool DebugWindow = false;
		bool ConfigsWindow = false;
		bool StylesWindow = false;

		bool ViewAlerts = false;
		bool ViewLogs = false;

		// Process
		ProcEntity ProtectedProc = { "" , (unsigned long)0 };
		bool IsProtected = false;
    };

	inline CFGType Data;

	void SaveConfig(const std::string filename);
	void LoadConfig(const std::string filename);
}