#pragma once

#include "ScanEngine.h"

namespace CapabilityEngine {

// Evaluates the loaded capability rules against the parsed PE on Context.Pe
// (imports + extracted ASCII/UTF-16 strings) and appends one Signal per fired
// capability. No-op if Context.Pe is null or not a valid PE.
void Collect(ScanEngine::ScanContext& Context);

}
