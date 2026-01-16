#include <Windows.h>
#include <thread>

#include "../UI.h"
#include "Protections/Protections.h"

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {

#ifdef _DEBUG
	AllocConsole();
	freopen("conin$", "r", stdin);
	freopen("conout$", "w", stdout);
	freopen("conout$", "w", stderr);
#endif

	std::thread UIThread(UI::Run);
	std::thread ProtectionsThread(Protections::Manager);

	UIThread.join();
	ProtectionsThread.join();

	return 0;
}