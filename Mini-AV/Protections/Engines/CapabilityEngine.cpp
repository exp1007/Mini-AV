#include "CapabilityEngine.h"

#include "CapabilityDatabase.h"
#include "PeImage.h"

#include <string>
#include <unordered_set>

namespace {

bool AllPresent(const std::vector<std::string>& Needles, const std::unordered_set<std::string>& Haystack)
{
	for (const auto& needle : Needles) {
		if (Haystack.find(needle) == Haystack.end()) {
			return false;
		}
	}
	return true;
}

bool AnyPresent(const std::vector<std::string>& Needles, const std::unordered_set<std::string>& Haystack)
{
	for (const auto& needle : Needles) {
		if (Haystack.find(needle) != Haystack.end()) {
			return true;
		}
	}
	return false;
}

bool AnySubstring(const std::vector<std::string>& Needles, const std::string& Blob)
{
	for (const auto& needle : Needles) {
		if (Blob.find(needle) != std::string::npos) {
			return true;
		}
	}
	return false;
}

}

namespace CapabilityEngine {

void Collect(ScanEngine::ScanContext& Context)
{
	ScanEngine::PeInfo* pe = Context.Pe;
	if (pe == nullptr || !pe->Valid) {
		return;
	}

	const auto& rules = CapabilityDatabase::Rules();
	if (rules.empty()) {
		return;
	}

	std::unordered_set<std::string> imports(pe->Imports.begin(), pe->Imports.end());

	// Strings are only needed if some rule actually has a strings_any clause.
	bool needStrings = false;
	for (const auto& rule : rules) {
		if (!rule.StringsAny.empty()) {
			needStrings = true;
			break;
		}
	}
	static const std::string kEmpty;
	const std::string& strings = needStrings ? PeImage::GetStrings(*pe) : kEmpty;

	for (const auto& rule : rules) {
		// Every non-empty clause must be satisfied.
		if (!rule.ImportsAll.empty() && !AllPresent(rule.ImportsAll, imports)) {
			continue;
		}
		if (!rule.ImportsAny.empty() && !AnyPresent(rule.ImportsAny, imports)) {
			continue;
		}
		if (!rule.StringsAny.empty() && !AnySubstring(rule.StringsAny, strings)) {
			continue;
		}

		Context.AddSignal(rule.Id, rule.Name, rule.Score, rule.Conf);
	}
}

}
