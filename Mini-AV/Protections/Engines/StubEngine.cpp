#include "ScanEngine.h"

namespace {

ScanEngine::ScanVerdict RunStubEngine(const ScanEngine::ScanContext&)
{
	return ScanEngine::ScanVerdict::Allow;
}

}

namespace ScanEngine {

ScanVerdict RunPipeline(const ScanContext& Context)
{
	(void)Context;
	return RunStubEngine(Context);
}

}
