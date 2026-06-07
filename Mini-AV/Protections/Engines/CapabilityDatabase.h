#pragma once

#include "ScanEngine.h"

#include <string>
#include <vector>

namespace CapabilityDatabase {

// One capability rule loaded from capabilities.json. A rule fires when every
// non-empty clause it specifies is satisfied:
//   ImportsAll  - all of these imported function names must be present
//   ImportsAny  - at least one must be present
//   StringsAny  - at least one must appear as a substring of the file's strings
// All values are stored lowercased. A rule with no clauses never fires.
struct Capability {
	std::string Id;
	std::string Name;
	int Score = 0;
	ScanEngine::Confidence Conf = ScanEngine::Confidence::Low;
	std::vector<std::string> ImportsAll;
	std::vector<std::string> ImportsAny;
	std::vector<std::string> StringsAny;
};

bool Initialize();
void Shutdown();

// Snapshot of the loaded rules. Safe to read after Initialize.
const std::vector<Capability>& Rules();
size_t RuleCount();
std::wstring DatabasePath();

}
