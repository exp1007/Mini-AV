#include "Protections.h"
#include "../Globals.h"
#include "../Config.h"
#include "../Utils/Utils.h"

#include <thread>

void Protections::Manager() {
	while (true) {
		long Delay = (long)(Globals::ScanDelay * 1000);
		if (Delay == 0) Delay = 50; // 50 ms delay to avoid CPU burning :)
		std::this_thread::sleep_for(std::chrono::milliseconds(Delay));

		if (Config::Data.ProtectedProc.PID == NULL) continue;

		// Get system processes
		ProcessList = Utils::GetProcessList();
		// 
		// Protections
		CheckHandles(); 
	}
}