#pragma once

#include "ScanEngine.h"

namespace ContextEngine {

// Cheap, parse-light collectors that append context Signals to the scan:
//   ctx.motw       - Mark-of-the-Web (downloaded from the internet)
//   ctx.double_ext - deceptive double extension (e.g. invoice.pdf.exe)
//   ctx.bad_path   - runs from a risky location (Temp / Downloads / AppData / removable)
//   pe.packed      - an executable section has high Shannon entropy
//   pe.malformed   - claims to be a PE but failed header validation
// Requires Context.Pe to already be parsed (PeImage::Parse) for the pe.* signals.
void Collect(ScanEngine::ScanContext& Context);

}
