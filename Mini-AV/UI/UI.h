#pragma once
#include "imgui.h"

#include <string>
#include <cstdint>
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
		enum class NotificationType : std::uint8_t {
			Info,
			Warning,
			Critical
		};

		void TitleBar();
		void MainWindow();
		void DebugPanel();
		bool StartupWindow(StartupState& StartupDetails);
	}
}