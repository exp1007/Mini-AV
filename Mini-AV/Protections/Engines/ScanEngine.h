#pragma once

#include <string>
#include <vector>

namespace ScanEngine {

enum class ScanVerdict {
	Allow,
	Block,
	Error
};

struct ScanContext {
	std::wstring ResolvedPath;
	std::wstring NtPath;
	unsigned long ProcessId = 0;
	unsigned long OperationSubtype = 0;
	std::vector<unsigned char> FileSample;
};

ScanVerdict RunPipeline(const ScanContext& Context);

}
