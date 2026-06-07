#include "HashEngine.h"

#include "HashDatabase.h"
#include "../FileIo.h"
#include "../../Logging/Logging.h"

#include <mutex>
#include <unordered_map>

namespace {

constexpr size_t kMaxHashFileBytes = 64u * 1024u * 1024u;

std::mutex g_cacheMutex;
std::unordered_map<std::string, ScanEngine::ScanVerdict> g_verdictCache;

bool LookupCachedVerdict(const std::string& Sha256Hex, ScanEngine::ScanVerdict& OutVerdict)
{
	std::lock_guard<std::mutex> lock(g_cacheMutex);
	const auto it = g_verdictCache.find(Sha256Hex);
	if (it == g_verdictCache.end()) {
		return false;
	}
	OutVerdict = it->second;
	return true;
}

void StoreCachedVerdict(const std::string& Sha256Hex, ScanEngine::ScanVerdict Verdict)
{
	std::lock_guard<std::mutex> lock(g_cacheMutex);
	if (g_verdictCache.size() > 4096) {
		g_verdictCache.clear();
	}
	g_verdictCache[Sha256Hex] = Verdict;
}

}

namespace HashEngine {

ScanEngine::PipelineResult Run(const ScanEngine::ScanContext& Context)
{
	ScanEngine::PipelineResult result{};

	if (Context.ResolvedPath.empty()) {
		result.Verdict = ScanEngine::ScanVerdict::Error;
		result.Reason = "hash: empty path";
		return result;
	}

	std::string sha256 = Context.Sha256Hex;
	if (sha256.empty()) {
		if (!FileIo::HashFileSha256(Context.ResolvedPath, sha256, kMaxHashFileBytes)) {
			result.Verdict = ScanEngine::ScanVerdict::Error;
			result.Reason = "hash: compute failed";
			return result;
		}
	}

	result.Sha256Hex = sha256;

	ScanEngine::ScanVerdict cached = ScanEngine::ScanVerdict::Allow;
	if (LookupCachedVerdict(sha256, cached)) {
		result.Verdict = cached;
		result.Reason = (cached == ScanEngine::ScanVerdict::Block) ? "hash deny (cached)" : "hash allow (cached)";
		return result;
	}

	if (HashDatabase::IsDenied(sha256)) {
		result.Verdict = ScanEngine::ScanVerdict::Block;
		result.Reason = "sha256 deny";
		StoreCachedVerdict(sha256, ScanEngine::ScanVerdict::Block);
		LOG_WARNING("HashEngine: deny sha256=%s path=%ls", sha256.c_str(), Context.ResolvedPath.c_str());
		return result;
	}

	result.Verdict = ScanEngine::ScanVerdict::Allow;
	result.Reason = "hash allow";
	StoreCachedVerdict(sha256, ScanEngine::ScanVerdict::Allow);
	return result;
}

}
