#pragma once

#include <Windows.h>

#include "MiniAvFilterMessages.h"

#include <string>

namespace FilePolicy {

enum class ScanVerdict {
	Allow,
	Block,
	Error
};

struct ExecutionScanResult {
	ScanVerdict Verdict = ScanVerdict::Allow;
	std::wstring ResolvedPath;
	std::string Reason;
	bool ApplyQuarantine = true;
};

bool ShouldEvaluateCreate(const MINIAV_CREATE_DECISION_REQUEST& Request);
ExecutionScanResult EvaluateExecutionCreate(const MINIAV_CREATE_DECISION_REQUEST& Request);

}
