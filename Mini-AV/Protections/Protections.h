#pragma once

#include "FileScan.h"
#include "../Globals.h"

#include <Windows.h>

namespace Protections {
	inline std::vector<ProcEntity> ProcessList;

	void Initialize();
	void Shutdown();
	void Manager();
	void CheckHandles();
}