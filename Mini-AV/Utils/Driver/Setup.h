#pragma once

#include <string>
#include <vector>

namespace Driver {
	struct SetupResult {
		bool Connected = false;
		bool PingOk = false;
		std::vector<std::string> Details;
	};

	SetupResult SetupConnection();
	SetupResult RetryConnection();
}
