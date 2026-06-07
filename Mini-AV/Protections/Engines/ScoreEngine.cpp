#include "ScoreEngine.h"

#include "ScoreConfig.h"
#include "EngineSettings.h"
#include "../../Logging/Logging.h"

#include <cstdio>

namespace {

const char* ConfidenceName(ScanEngine::Confidence Conf)
{
	switch (Conf) {
	case ScanEngine::Confidence::High:   return "high";
	case ScanEngine::Confidence::Medium: return "medium";
	case ScanEngine::Confidence::Low:
	default:                             return "low";
	}
}

// True if any accumulated signal's Id begins with Prefix. Combos match by prefix
// so "ad." catches any anti-debug sub-signal and "cap.injection" matches exactly.
bool HasSignalWithPrefix(const std::vector<ScanEngine::Signal>& Signals, const std::string& Prefix)
{
	for (const auto& signal : Signals) {
		if (signal.Id.rfind(Prefix, 0) == 0) {
			return true;
		}
	}
	return false;
}

// Append a synthetic Signal for every combo whose required prefixes are all
// present in Base. Combos are evaluated against the *base* signals only, so one
// combo can never satisfy another. Returns the combined list (base + combos).
std::vector<ScanEngine::Signal> ApplyCombos(const std::vector<ScanEngine::Signal>& Base)
{
	std::vector<ScanEngine::Signal> combined = Base;
	for (const auto& combo : ScoreConfig::Combos()) {
		bool all = true;
		for (const auto& prefix : combo.Requires) {
			if (!HasSignalWithPrefix(Base, prefix)) {
				all = false;
				break;
			}
		}
		if (all) {
			combined.push_back(ScanEngine::Signal{
				combo.Id,
				"Combo: " + combo.Name,
				combo.Bonus,
				ScanEngine::Confidence::High });
		}
	}
	return combined;
}

// Maps the accumulated signals to a single short, generic category for the toast
// notification — so the user gets a one-line "what kind of thing this is" instead
// of the full signal dump (which still goes to the logs / Alerts panel). Returns
// the highest-priority category whose signal-id prefix is present; "" if none.
std::string DeriveCategory(const std::vector<ScanEngine::Signal>& Signals)
{
	// Ordered most- to least-telling. First prefix that matches a fired signal wins.
	static const struct { const char* Prefix; const char* Label; } kCategories[] = {
		{ "cap.ransom",       "Ransomware behaviour" },
		{ "cap.injection",    "Process injection" },
		{ "cap.cred_theft",   "Credential theft" },
		{ "cap.keylogger",    "Keylogging" },
		{ "cap.persistence",  "Persistence / autorun" },
		{ "cap.self_delete",  "Self-deletion" },
		{ "cap.network",      "Network / C2 activity" },
		{ "cap.anti_vm",      "Sandbox / VM evasion" },
		{ "ad.",              "Anti-debugging" },
		{ "cap.dynamic_api",  "Evasive API resolution" },
		{ "sim.",             "Known-malware similarity" },
		{ "ctx.double_ext",   "Disguised executable" },
		{ "pe.packed",        "Packed / obfuscated code" },
		{ "pe.malformed",     "Malformed executable" },
		{ "ctx.motw",         "Downloaded from the internet" },
		{ "ctx.bad_path",     "Runs from a risky location" },
	};

	for (const auto& category : kCategories) {
		if (HasSignalWithPrefix(Signals, category.Prefix)) {
			return category.Label;
		}
	}
	return std::string();
}

std::string JoinDescriptions(const std::vector<ScanEngine::Signal>& Signals)
{
	std::string joined;
	for (const auto& signal : Signals) {
		if (signal.Description.empty()) {
			continue;
		}
		if (!joined.empty()) {
			joined += " + ";
		}
		joined += signal.Description;
	}
	return joined;
}

// Multi-line, itemised scoring breakdown for the terminal log: one line per fired
// signal with its score, id, confidence and description, plus a running subtotal.
std::string BuildBreakdown(
	const std::vector<ScanEngine::Signal>& Signals,
	int Total,
	const ScoreConfig::Thresholds& Bands)
{
	std::string out = "\n  signals (" + std::to_string(Signals.size()) + "):";

	int running = 0;
	for (const auto& signal : Signals) {
		running += signal.Score;
		char line[512];
		std::snprintf(
			line,
			sizeof(line),
			"\n    [+%3d] %-24s %-6s %s  (running %d)",
			signal.Score,
			signal.Id.c_str(),
			ConfidenceName(signal.Conf),
			signal.Description.c_str(),
			running);
		out += line;
	}

	char tail[96];
	std::snprintf(
		tail,
		sizeof(tail),
		"\n  total=%d  (suspicious>=%d, dangerous>=%d, block>=%d)",
		Total,
		Bands.Suspicious,
		Bands.Dangerous,
		Bands.Block);
	out += tail;
	return out;
}

}

namespace ScoreEngine {

ScanEngine::PipelineResult Decide(const ScanEngine::ScanContext& Context)
{
	ScanEngine::PipelineResult result{};
	result.Sha256Hex = Context.Sha256Hex;

	// Thresholds are owned by the dashboard (EngineSettings) so the sensitivity
	// preset / sliders take effect live; combos still come from ScoreConfig.
	ScoreConfig::Thresholds bands;
	bands.Suspicious = EngineSettings::Current.Suspicious;
	bands.Dangerous = EngineSettings::Current.Dangerous;
	bands.Block = EngineSettings::Current.Block;

	// Fold any matching combo bonuses into the working signal list so they appear
	// in the total, the reason and the breakdown like first-class evidence.
	const std::vector<ScanEngine::Signal> signals = ApplyCombos(Context.Signals);

	int total = 0;
	for (const auto& signal : signals) {
		total += signal.Score;
	}

	result.Score = total;
	result.Category = DeriveCategory(signals);
	const std::string detail = JoinDescriptions(signals);

	if (total >= bands.Block) {
		result.Verdict = ScanEngine::ScanVerdict::Block;
		result.Reason = detail.empty()
			? ("heuristic block (score " + std::to_string(total) + ")")
			: (detail + " -> score " + std::to_string(total));
		const std::string breakdown = BuildBreakdown(signals, total, bands);
		LOG_WARNING(
			"ScoreEngine: BLOCK score=%d (>=%d) path=%ls%s",
			total,
			bands.Block,
			Context.ResolvedPath.c_str(),
			breakdown.c_str());
		return result;
	}

	result.Verdict = ScanEngine::ScanVerdict::Allow;

	if (total >= bands.Dangerous) {
		result.Dangerous = true;
		result.Reason = detail.empty()
			? ("dangerous (score " + std::to_string(total) + ")")
			: (detail + " -> dangerous (score " + std::to_string(total) + ")");
		const std::string breakdown = BuildBreakdown(signals, total, bands);
		LOG_WARNING(
			"ScoreEngine: DANGEROUS (allowed) score=%d path=%ls%s",
			total,
			Context.ResolvedPath.c_str(),
			breakdown.c_str());
		return result;
	}

	if (total >= bands.Suspicious) {
		result.Suspicious = true;
		result.Reason = detail.empty()
			? ("suspicious (score " + std::to_string(total) + ")")
			: (detail + " -> suspicious (score " + std::to_string(total) + ")");
		const std::string breakdown = BuildBreakdown(signals, total, bands);
		LOG_INFO(
			"ScoreEngine: SUSPICIOUS (allowed) score=%d path=%ls%s",
			total,
			Context.ResolvedPath.c_str(),
			breakdown.c_str());
		return result;
	}

	result.Reason = detail.empty()
		? "clean (no signals)"
		: (detail + " -> clean (score " + std::to_string(total) + ")");

	// Below the suspicious band: a single terse line (no full breakdown) so weak
	// signals are still visible without flooding the log on every benign binary.
	if (total > 0) {
		LOG_INFO(
			"ScoreEngine: clean score=%d (<%d) path=%ls reason=%s",
			total,
			bands.Suspicious,
			Context.ResolvedPath.c_str(),
			result.Reason.c_str());
	}
	return result;
}

}
