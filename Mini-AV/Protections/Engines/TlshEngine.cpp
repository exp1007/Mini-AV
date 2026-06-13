#include "TlshEngine.h"

#include "ScanEngine.h"
#include "PeImage.h"
#include "TlshDatabase.h"
#include "EngineSettings.h"
#include "../../Logging/Logging.h"
#include "TLSH/tlsh.h"

#include <climits>
#include <cstdint>
#include <string>
#include <vector>

namespace {

// Distance-banded weighting: a close match is strong evidence, a distant one only
// nudges the score. Even the strongest band stays below the default block threshold
// alone (so TLSH never blocks by itself) — bands/combos with a capability do.
struct Band {
	int MaxDistance;
	int Score;
	ScanEngine::Confidence Conf;
};

constexpr Band kBands[] = {
	{ 30, 45, ScanEngine::Confidence::High },
	{ 50, 30, ScanEngine::Confidence::Medium },
	{ INT_MAX, 18, ScanEngine::Confidence::Low }, // up to the configured threshold
};

}

namespace TlshEngine {

void Collect(ScanEngine::ScanContext& Context)
{
	// Needs the parse-once raw buffer.
	if (Context.Pe == nullptr || !Context.Pe->Read || Context.Pe->Buffer.empty()) {
		return;
	}

	const std::vector<uint8_t>& buffer = Context.Pe->Buffer;
	const size_t bufferSize = buffer.size();

	// Fingerprint the *code*, not the container. Hashing the whole file lets MSVC/CRT
	// boilerplate, the import table, resources and padding dominate the digest, which
	// kills discrimination on small binaries (everything looks similar). Instead we
	// TLSH only the executable sections (.text and friends), concatenated via update().
	// Offsets/sizes come from the PE headers, so clamp every span to the real buffer
	// to stay safe on a malformed/hostile layout.
	Tlsh candidate;
	size_t hashedBytes = 0;
	for (const ScanEngine::PeSection& section : Context.Pe->Sections) {
		if (!section.Executable || section.RawSize == 0 || section.RawOffset >= bufferSize) {
			continue;
		}
		const size_t available = bufferSize - section.RawOffset;
		const size_t length = section.RawSize < available ? section.RawSize : available;
		if (length == 0) {
			continue;
		}
		candidate.update(buffer.data() + section.RawOffset, static_cast<unsigned int>(length));
		hashedBytes += length;
	}

	if (hashedBytes == 0) {
		// No executable section bytes (non-PE / malformed / unusual layout). TLSH over
		// the wrapper wouldn't be meaningful here — leave it to the other engines.
		return;
	}

	candidate.final();
	if (!candidate.isValid()) {
		// Too little code / too low-variance to produce a stable digest — no signal.
		return;
	}

	if (const char* hash = candidate.getHash(1)) {
		Context.TlshHex = hash;
		// Code-section digest. Logged so it can be copied straight into tlsh.json to
		// blacklist the sample's variant family (see the curation workflow in the plan).
		LOG_INFO("TlshEngine: %ls tlsh(text)=%s", Context.ResolvedPath.c_str(), Context.TlshHex.c_str());
	}

	const int maxDistance = EngineSettings::Current.TlshMaxDistance;
	const TlshDatabase::MatchResult match = TlshDatabase::Match(candidate, maxDistance);
	if (!match.Found) {
		return;
	}

	int score = kBands[0].Score;
	ScanEngine::Confidence conf = kBands[0].Conf;
	for (const Band& band : kBands) {
		if (match.Distance <= band.MaxDistance) {
			score = band.Score;
			conf = band.Conf;
			break;
		}
	}

	const std::string label = match.Name.empty() ? std::string("known malware") : match.Name;
	std::string description = "Similar to " + label;
	if (!match.Family.empty()) {
		description += " (" + match.Family + ")";
	}
	description += ", TLSH distance " + std::to_string(match.Distance);

	Context.AddSignal("sim.family", description, score, conf);
}

}
