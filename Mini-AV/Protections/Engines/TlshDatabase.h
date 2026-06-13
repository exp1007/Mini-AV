#pragma once

#include <string>

// Forward-declared so consumers don't need to pull in the vendored TLSH header.
class Tlsh;

// Blacklist of known-malware TLSH digests, loaded once from
// %ProgramData%\MiniAV\tlsh.json. Mirrors the HashDatabase idiom (default-write-if-
// missing, load-once, mutex-guarded). Each stored digest is pre-parsed into a Tlsh
// object at load, so per-scan matching costs only a totalDiff, never a re-parse.
namespace TlshDatabase {

	struct MatchResult {
		bool Found = false;
		int Distance = 0;       // TLSH distance to the matched entry (0 = identical)
		std::string Name;       // human label of the matched sample
		std::string Family;     // malware family, if recorded
	};

	bool Initialize();
	void Shutdown();

	// Validates a TLSH digest, appends it to the live blacklist, and rewrites
	// tlsh.json. Applies immediately (no restart). Returns false on an invalid
	// digest or if the file couldn't be written (needs write access to
	// %ProgramData%\MiniAV — the elevated service has it; a plain editor does not).
	bool AddEntry(const std::string& TlshStr, const std::string& Name, const std::string& Family, int MaxDistance);

	// Best (smallest-distance) blacklist entry within its allowed distance, or a
	// MatchResult with Found=false. DefaultMaxDistance is used for any entry that did
	// not specify its own max_distance.
	MatchResult Match(const Tlsh& Candidate, int DefaultMaxDistance);

	size_t EntryCount();
	std::wstring DatabasePath();

}
