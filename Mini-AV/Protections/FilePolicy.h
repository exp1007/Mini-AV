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
	std::string Reason;       // full detail (logs / Alerts panel)
	std::string Category;     // short generic category for the toast notification
	bool ApplyQuarantine = true;
	int Score = 0;            // aggregated heuristic score (0 for fast-path verdicts)
	bool Suspicious = false;  // allowed but scored in the suspicious band (30-49)
	bool Dangerous = false;   // allowed but scored in the dangerous band (50-59)
};

bool ShouldEvaluateCreate(const MINIAV_CREATE_DECISION_REQUEST& Request);
ExecutionScanResult EvaluateExecutionCreate(const MINIAV_CREATE_DECISION_REQUEST& Request);

}
