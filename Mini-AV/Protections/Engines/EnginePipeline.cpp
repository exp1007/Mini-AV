#include "ScanEngine.h"

#include "HashEngine.h"
#include "PeImage.h"
#include "ContextEngine.h"
#include "CapabilityEngine.h"
#include "AntiDebugEngine.h"
#include "ScoreEngine.h"
#include "EngineSettings.h"

namespace {

constexpr size_t kMaxPeBytes = 64u * 1024u * 1024u; // matches the hash cap

}

namespace ScanEngine {

// Hybrid pipeline:
//   1. Definitive verdicts short-circuit  (known-bad hash -> instant Block,
//      I/O / compute errors -> instant Error). Fast, certain path.
//   2. Collectors / heuristic engines run in order and only *append Signals*
//      to the context; none of them returns a final verdict. (Added per phase.)
//   3. ScoreEngine::Decide aggregates the accumulated signals into the final
//      verdict, with the joined signal descriptions as the reason.
PipelineResult RunPipeline(ScanContext& Context)
{
	// Engine knobs (master switch handled upstream in FileScan; here we honour the
	// per-engine toggles so disabled layers are simply skipped).
	const EngineSettings::Settings cfg = EngineSettings::Current;

	// (1) Definitive short-circuit on hash.
	if (cfg.UseHashDenyList) {
		PipelineResult hashResult = HashEngine::Run(Context);
		Context.Sha256Hex = hashResult.Sha256Hex;

		if (hashResult.Verdict == ScanVerdict::Block) {
			hashResult.Category = "Known malware signature";
			return hashResult;
		}
		if (hashResult.Verdict == ScanVerdict::Error) {
			return hashResult;
		}
	}

	// (2) Signal collectors. Parse the PE once; the parsed form (and raw buffer)
	//     lives on this stack frame and is shared via Context.Pe for the whole
	//     evaluation, then detached before returning.
	PeInfo pe;
	PeImage::Parse(Context.ResolvedPath, pe, kMaxPeBytes);
	Context.Pe = &pe;

	if (cfg.UseContextEngine)    ContextEngine::Collect(Context);
	if (cfg.UseCapabilityEngine) CapabilityEngine::Collect(Context);
	if (cfg.UseAntiDebugEngine)  AntiDebugEngine::Collect(Context);
	// Phase 5+: TLSH / IDA-signature collectors append here.

	// (3) Final decision from accumulated signals.
	PipelineResult result = ScoreEngine::Decide(Context);
	Context.Pe = nullptr;
	return result;
}

}
