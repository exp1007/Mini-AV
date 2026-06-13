#include "FileScan.h"

#include "Engines/HashDatabase.h"
#include "Engines/CapabilityDatabase.h"
#include "Engines/ScoreConfig.h"
#include "Engines/TlshDatabase.h"
#include "Engines/EngineSettings.h"
#include "FilePolicy.h"
#include "Quarantine.h"

namespace Protections {

void InitializeFileScan()
{
	HashDatabase::Initialize();
	CapabilityDatabase::Initialize();
	ScoreConfig::Initialize();
	TlshDatabase::Initialize();
	Quarantine::Initialize();
}

void ShutdownFileScan()
{
	Quarantine::Shutdown();
	TlshDatabase::Shutdown();
	ScoreConfig::Shutdown();
	CapabilityDatabase::Shutdown();
	HashDatabase::Shutdown();
}

ExecutionScanResult EvaluateExecutionCreate(const MINIAV_CREATE_DECISION_REQUEST& Request)
{
	// Master switch: real-time protection off -> scan nothing, allow everything.
	if (!EngineSettings::Current.RealtimeProtection) {
		ExecutionScanResult allow{};
		allow.Verdict = ScanVerdict::Allow;
		allow.Reason = "protection disabled";
		return allow;
	}

	if (!FilePolicy::ShouldEvaluateCreate(Request)) {
		ExecutionScanResult allow{};
		allow.Verdict = ScanVerdict::Allow;
		allow.Reason = "fast allow";
		return allow;
	}

	return FilePolicy::EvaluateExecutionCreate(Request);
}

}
