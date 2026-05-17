#include "Setup.h"
#include "Communication.h"
#include "../../Logging/Logging.h"

namespace Driver {
	SetupResult SetupConnection()
	{
		SetupResult Result;
		Result.Connected = Communication::Connect();
		if (!Result.Connected) {
			Result.Details.emplace_back("Driver not reachable. Ensure passThrough.sys is loaded.");
			LOG_ERROR("Mini-AV: filter driver not reachable (load passThrough.sys / install driver)");
			return Result;
		}

		Result.Details.emplace_back("Driver communication port connected.");
		Result.PingOk = Communication::Ping();
		if (Result.PingOk) {
			Result.Details.emplace_back("Driver ping succeeded.");
			LOG_INFO("Mini-AV: filter driver ping OK");
		} else {
			Result.Details.emplace_back("Driver ping failed after connect.");
			LOG_WARNING("Mini-AV: filter driver ping failed (port connected)");
		}

		return Result;
	}

	SetupResult RetryConnection()
	{
		Communication::Disconnect();
		SetupResult Result = SetupConnection();
		if (Result.Connected) {
			if (Result.PingOk)
				Result.Details.emplace_back("Retry finished: driver communication healthy.");
			else
				Result.Details.emplace_back("Retry finished: connection opened but ping failed.");
		} else {
			Result.Details.emplace_back("Retry finished: driver still unreachable.");
		}
		return Result;
	}
}
