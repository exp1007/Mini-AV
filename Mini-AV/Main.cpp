#include <Windows.h>
#include <thread>

#include "Logging/Logging.h"
#include "Config.h"
#include "../UI.h"
#include "Protections/Protections.h"
#include "Utils/Driver/Setup.h"
#include "Utils/Driver/Communication.h"

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
	UI::StartupState StartupDetails;
	StartupDetails.ConfigFileFound = Config::HasConfigFile();
	StartupDetails.ConfigLoaded = Config::LoadConfig();
	if (StartupDetails.ConfigLoaded)
		StartupDetails.StatusMessages.emplace_back("Settings loaded from settings.cfg.");
	else if (StartupDetails.ConfigFileFound)
		StartupDetails.StatusMessages.emplace_back("Failed to parse settings.cfg. Using defaults.");
	else
		StartupDetails.StatusMessages.emplace_back("settings.cfg missing. Using defaults.");

	Driver::SetupResult DriverState = Driver::SetupConnection();
	StartupDetails.DriverConnected = DriverState.Connected;
	StartupDetails.DriverPingOk = DriverState.PingOk;
	StartupDetails.StatusMessages.insert(
	StartupDetails.StatusMessages.end(),
	DriverState.Details.begin(),
	DriverState.Details.end());
	

	std::thread UIThread(UI::Run, StartupDetails);
	std::thread ProtectionsThread(Protections::Manager);

	UIThread.join();
	ProtectionsThread.join();

	Communication::Disconnect();

	return 0;
}