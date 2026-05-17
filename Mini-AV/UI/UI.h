#pragma once
#include "imgui.h"

#include <string>
#include <vector>

namespace UI {
	inline ImFont* FontLogo = nullptr;

	struct StartupState {
		bool ConfigLoaded = false;
		bool ConfigFileFound = false;
		bool DriverConnected = false;
		bool DriverPingOk = false;
		std::vector<std::string> StatusMessages;
	};

	int Run(StartupState StartupDetails);

	namespace Components {
		void TitleBar();
		void MainWindow();
		bool StartupWindow(StartupState& StartupDetails);
	}
}