#pragma once

#include <string>
#include <vector>

namespace ScanEngine {

enum class ScanVerdict {
	Allow,
	Block,
	Error
};

enum class Confidence {
	Low,
	Medium,
	High
};

// One piece of evidence appended by a collector/heuristic engine. The final
// verdict is built from the accumulated signals by ScoreEngine, never by an
// individual collector.
struct Signal {
	std::string Id;          // e.g. "cap.injection", "ctx.motw", "pe.high_entropy"
	std::string Description; // human-readable, surfaced in the alert
	int Score = 0;           // contribution to the risk total
	Confidence Conf = Confidence::Low;
};

// Forward-declared parsed-PE cache (Phase 1). Null until PeImage parses it.
struct PeInfo;

struct ScanContext {
	std::wstring ResolvedPath;
	std::wstring NtPath;
	unsigned long ProcessId = 0;
	unsigned long OperationSubtype = 0;
	std::string Sha256Hex;
	std::string TlshHex;     // TLSH fuzzy digest of the file buffer (Phase 5b), empty if not computed/invalid

	std::vector<Signal> Signals; // appended by collectors, read by ScoreEngine
	PeInfo* Pe = nullptr;        // parsed-PE cache, owned elsewhere (Phase 1)

	void AddSignal(std::string Id, std::string Description, int Score, Confidence Conf)
	{
		Signals.push_back(Signal{ std::move(Id), std::move(Description), Score, Conf });
	}
};

struct PipelineResult {
	ScanVerdict Verdict = ScanVerdict::Allow;
	std::string Reason;       // full joined signal detail (for logs / Alerts panel)
	std::string Category;     // short generic category for the toast (e.g. "Process injection")
	std::string Sha256Hex;
	int Score = 0;            // aggregated risk score from ScoreEngine
	bool Suspicious = false;  // allowed, scored in the suspicious band (30-49)
	bool Dangerous = false;   // allowed, scored in the dangerous band (50-59)
};

PipelineResult RunPipeline(ScanContext& Context);

}
