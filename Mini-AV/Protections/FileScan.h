#pragma once

#include <Windows.h>

#include "FilePolicy.h"

namespace Protections {

using ScanVerdict = FilePolicy::ScanVerdict;
using ExecutionScanResult = FilePolicy::ExecutionScanResult;

void InitializeFileScan();
void ShutdownFileScan();
ExecutionScanResult EvaluateExecutionCreate(const MINIAV_CREATE_DECISION_REQUEST& Request);

}
