#include "FileScan.h"

#include "FilePolicy.h"
#include "Quarantine.h"

namespace Protections {

void InitializeFileScan()
{
	Quarantine::Initialize();
}

void ShutdownFileScan()
{
	Quarantine::Shutdown();
}

ExecutionScanResult EvaluateExecutionCreate(const MINIAV_CREATE_DECISION_REQUEST& Request)
{
	if (!FilePolicy::ShouldEvaluateCreate(Request)) {
		ExecutionScanResult allow{};
		allow.Verdict = ScanVerdict::Allow;
		allow.Reason = "fast allow";
		return allow;
	}

	return FilePolicy::EvaluateExecutionCreate(Request);
}

}
