#pragma once
#include "../Globals.h"
#include <Windows.h>

namespace Protections {
	inline std::vector<ProcEntity> ProcessList;

	void Manager();
	
	void CheckHandles();
}