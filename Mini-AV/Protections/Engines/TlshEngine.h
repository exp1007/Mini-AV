#pragma once

namespace ScanEngine {
	struct ScanContext;
}

// Phase 5b — fuzzy-hash family similarity. Computes the TLSH digest of the binary's
// executable sections (.text etc., from the parse-once Context.Pe — no extra I/O) so
// the fingerprint reflects code rather than MSVC/CRT/container boilerplate, records it
// on the context, and appends a distance-weighted "sim.family" signal when it matches
// a blacklisted digest. A weighted signal, never a lone hard block — combine with
// capabilities.
namespace TlshEngine {

	void Collect(ScanEngine::ScanContext& Context);

}
