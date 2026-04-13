#include <Windows.h>
#include <thread>

#include "Logging/Logging.h"
#include "Config.h"
#include "../UI.h"
#include "Protections/Protections.h"
#include "Utils/Communication/Communication.h"

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {

	Config::LoadConfig();

	if (Communication::Connect()) {
		if (Communication::Ping()) 
			LOG_INFO("Mini-AV: filter driver ping OK");
		else 
			LOG_WARNING("Mini-AV: filter driver ping failed (port connected)");
	} else 
		LOG_ERROR("Mini-AV: filter driver not reachable (load passThrough.sys / install driver)");
	

	std::thread UIThread(UI::Run);
	std::thread ProtectionsThread(Protections::Manager);

	UIThread.join();
	ProtectionsThread.join();

	Communication::Disconnect();

	return 0;
}