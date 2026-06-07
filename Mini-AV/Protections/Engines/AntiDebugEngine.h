#pragma once

#include "ScanEngine.h"

namespace AntiDebugEngine {

// Dedicated anti-debug detector. Combines three evidence layers over the parsed
// PE on Context.Pe:
//   1. code byte-patterns - PEB BeingDebugged / NtGlobalFlag reads, int 2Dh,
//      rdtsc timing (catches dynamically-resolved checks imports/strings miss)
//   2. anti-debug imports - the broadened API indicator set
//   3. debugger/analysis tool name strings the sample looks for
// Each technique is a weighted sub-signal; finding several adds a combo
// escalation so multiple weak checks together can reach the Block band while a
// single check stays low. No-op if Context.Pe is null or not a valid PE.
void Collect(ScanEngine::ScanContext& Context);

}
