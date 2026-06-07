#pragma once

#include <string>
#include <vector>

// Phase 3 — config-driven scoring. Thresholds and combo bonuses are loaded from
// %ProgramData%\MiniAV\scoring.json (same loader idiom as CapabilityDatabase),
// so the verdict model can be tuned without recompiling. ScoreEngine reads the
// snapshot below; if the file is missing a sensible default is written.
namespace ScoreConfig {

// Score bands. total >= Block -> Block; >= Dangerous / >= Suspicious -> allowed
// but flagged. Kept as plain ints so the file is trivial to hand-edit.
struct Thresholds {
	int Suspicious = 30;
	int Dangerous = 50;
	int Block = 60;
};

// A combo expresses "these behaviors together are worse than their sum". It
// fires when, for every prefix in Requires, at least one accumulated signal's
// Id begins with that prefix (so "ad." matches any anti-debug sub-signal and
// "cap.injection" matches exactly). A firing combo contributes Bonus to the
// total as a synthetic signal in the breakdown.
struct Combo {
	std::string Id;
	std::string Name;
	std::vector<std::string> Requires;
	int Bonus = 0;
};

bool Initialize();
void Shutdown();

// Snapshots, safe to read after Initialize.
Thresholds GetThresholds();
const std::vector<Combo>& Combos();
std::wstring ConfigPath();

}
