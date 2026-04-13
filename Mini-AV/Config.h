#pragma once
#include "../Globals.h"

namespace Config {
    struct CFGType {
		// General/UI
		bool DebugWindow = false;
		bool StylesWindow = false;

		bool ViewAlerts = false;
		bool ViewLogs = false;
		bool ViewConsoleLogs = false;

		// Process
		ProcEntity ProtectedProc = { "" , (unsigned long)0 };
		bool IsProtected = false;
    };

	inline CFGType Data;

	void SaveConfig();
	void LoadConfig();
}