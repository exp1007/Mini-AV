#pragma once

#include "ScanEngine.h"

namespace ScoreEngine {

// Aggregates the signals accumulated on the context into one final verdict.
// This is the only place that turns evidence into Allow/Block. Called last in
// RunPipeline, after every collector has appended its signals.
ScanEngine::PipelineResult Decide(const ScanEngine::ScanContext& Context);

}
