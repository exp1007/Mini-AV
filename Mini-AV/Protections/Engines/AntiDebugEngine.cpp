#include "AntiDebugEngine.h"

#include "BytePattern.h"
#include "PeImage.h"

#include <string>
#include <unordered_set>
#include <vector>

namespace {

// ---- Sub-signal weights ---------------------------------------------------
// Anti-debug is an *evasion* indicator, not malice by itself: packers, games,
// DRM and protectors all use it. So weights are deliberately modest — even a
// binary stacking several anti-debug techniques should land in the suspicious
// band rather than Block on anti-debug alone, and only cross the Block threshold
// (60) when combined with a genuinely malicious capability (injection, C2, ...).
constexpr int kScorePebAccess = 5;         // PEB pointer read, no recognized follow-up
constexpr int kScoreBeingDebugged = 10;    // PEB->BeingDebugged byte check
constexpr int kScoreNtGlobalFlag = 10;     // PEB->NtGlobalFlag check
constexpr int kScoreInt2d = 12;            // int 2Dh debugger trap
constexpr int kScoreInt3Long = 12;         // int 3 long form (CD 03), rare/indicative
constexpr int kScoreRdtsc = 4;             // rdtsc timing check (weak: legit uses)
constexpr int kScoreRdtscp = 6;            // rdtscp timing check (rarer than rdtsc)
constexpr int kScoreKUserShared = 10;      // KUSER_SHARED_DATA KdDebuggerEnabled read
constexpr int kScoreStrongImports = 10;    // genuinely anti-debug API imports present
constexpr int kScoreWeakImports = 3;       // CRT-common imports — corroboration only
constexpr int kScoreToolStrings = 12;      // debugger/analysis tool names embedded
constexpr int kScoreComboTwo = 8;          // >= 2 distinct techniques
constexpr int kScoreComboThreePlus = 15;   // >= 3 distinct techniques (replaces above)

// Window (in bytes) within which a PEB-pointer read must be followed by the
// field access to count as a BeingDebugged / NtGlobalFlag check.
constexpr size_t kPebFollowWindow = 48;

struct SectionView {
	const uint8_t* Data = nullptr;
	size_t Len = 0;
};

std::vector<SectionView> ExecutableViews(const ScanEngine::PeInfo& Pe)
{
	std::vector<SectionView> views;
	for (const auto& section : Pe.Sections) {
		if (!section.Executable || section.RawSize == 0) {
			continue;
		}
		const size_t off = section.RawOffset;
		if (off >= Pe.Buffer.size()) {
			continue;
		}
		const size_t avail = Pe.Buffer.size() - off;
		const size_t len = section.RawSize < avail ? section.RawSize : avail;
		views.push_back(SectionView{ Pe.Buffer.data() + off, len });
	}
	return views;
}

bool AnyContains(const std::vector<SectionView>& Views, const BytePattern::Pattern& Pat)
{
	for (const auto& view : Views) {
		if (BytePattern::Contains(view.Data, view.Len, Pat)) {
			return true;
		}
	}
	return false;
}

// True if Anchor appears and at least one of Follows occurs within Window bytes
// after it (in the same section). Used to anchor a field access to a PEB read so
// stray byte sequences don't trigger on their own.
bool AnyContainsNear(
	const std::vector<SectionView>& Views,
	const BytePattern::Pattern& Anchor,
	const std::vector<BytePattern::Pattern>& Follows,
	size_t Window)
{
	for (const auto& view : Views) {
		size_t at = BytePattern::Find(view.Data, view.Len, Anchor, 0);
		while (at != BytePattern::kNoMatch) {
			const size_t regionEnd = (at + Window < view.Len) ? (at + Window) : view.Len;
			for (const auto& follow : Follows) {
				if (BytePattern::Find(view.Data, regionEnd, follow, at) != BytePattern::kNoMatch) {
					return true;
				}
			}
			at = BytePattern::Find(view.Data, view.Len, Anchor, at + 1);
		}
	}
	return false;
}

// Compiled-once pattern bank.
struct Patterns {
	std::vector<BytePattern::Pattern> PebAccessX86;
	std::vector<BytePattern::Pattern> PebAccessX64;
	std::vector<BytePattern::Pattern> BeingDebuggedFollow;
	std::vector<BytePattern::Pattern> NtGlobalFlagFollowX86;
	std::vector<BytePattern::Pattern> NtGlobalFlagFollowX64;
	BytePattern::Pattern Int2d;
	BytePattern::Pattern Int3Long;
	BytePattern::Pattern Rdtsc;
	BytePattern::Pattern Rdtscp;
	BytePattern::Pattern KUserShared;

	Patterns()
	{
		// PEB pointer read. x86: mov r32, fs:[30h]; x64: mov r64, gs:[60h].
		PebAccessX86.push_back(BytePattern::Compile("64 A1 30 00 00 00"));       // mov eax, fs:[30h]
		PebAccessX86.push_back(BytePattern::Compile("64 8B ?? 30 00 00 00"));    // mov r32, fs:[30h]
		PebAccessX64.push_back(BytePattern::Compile("65 48 8B 04 25 60 00 00 00")); // mov rax, gs:[60h]
		PebAccessX64.push_back(BytePattern::Compile("65 48 8B ?? 25 60 00 00 00")); // mov r64, gs:[60h]

		// BeingDebugged is at PEB+0x02 (a single byte) on both architectures.
		BeingDebuggedFollow.push_back(BytePattern::Compile("0F B6 ?? 02"));      // movzx r32, byte[reg+2]
		BeingDebuggedFollow.push_back(BytePattern::Compile("8A ?? 02"));         // mov r8, byte[reg+2]
		BeingDebuggedFollow.push_back(BytePattern::Compile("80 ?? 02"));         // cmp byte[reg+2], imm8

		// NtGlobalFlag: PEB+0x68 (x86) / PEB+0xBC (x64).
		NtGlobalFlagFollowX86.push_back(BytePattern::Compile("8B ?? 68"));       // mov r32, [reg+68h]
		NtGlobalFlagFollowX86.push_back(BytePattern::Compile("0F B6 ?? 68"));    // movzx r32, byte[reg+68h]
		NtGlobalFlagFollowX86.push_back(BytePattern::Compile("F6 ?? 68"));       // test byte[reg+68h], imm8
		NtGlobalFlagFollowX64.push_back(BytePattern::Compile("8B ?? BC 00 00 00"));    // mov r32, [reg+0BCh]
		NtGlobalFlagFollowX64.push_back(BytePattern::Compile("0F B6 ?? BC 00 00 00")); // movzx r32, byte[reg+0BCh]
		NtGlobalFlagFollowX64.push_back(BytePattern::Compile("F6 ?? BC 00 00 00"));    // test byte[reg+0BCh], imm8

		Int2d = BytePattern::Compile("CD 2D");        // int 2Dh
		Int3Long = BytePattern::Compile("CD 03");     // int 3 (long form); 0xCC is too common to scan
		Rdtsc = BytePattern::Compile("0F 31");        // rdtsc
		Rdtscp = BytePattern::Compile("0F 01 F9");    // rdtscp
		// KUSER_SHARED_DATA is fixed at 0x7FFE0000; KdDebuggerEnabled is at +0x2D4.
		// The immediate 0x7FFE02D4 (LE: D4 02 FE 7F) embedded in code reads that byte.
		KUserShared = BytePattern::Compile("D4 02 FE 7F");
	}
};

const Patterns& Bank()
{
	static const Patterns bank;
	return bank;
}

// ---- Import indicators (tiered) -------------------------------------------
// Strong: rarely present in benign binaries; each is a recognized anti-debug
// primitive, so one hit fires a real signal and counts as a technique.
const char* const kStrongImports[] = {
	"checkremotedebuggerpresent",
	"ntqueryinformationprocess",    // ProcessDebugPort/Flags/ObjectHandle
	"ntsetinformationthread",       // ThreadHideFromDebugger
	"ntquerysysteminformation",     // SystemKernelDebuggerInformation
	"ntqueryobject",                // enumerate DebugObject handles
	"debugactiveprocess",
	"debugactiveprocessstop",
	"rtladjustprivilege",           // paired with NtRaiseHardError BSOD trick
	"ntraiseharderror",
	"rtlqueryprocessheapinformation",  // heap-flag debug detection
	"rtlqueryprocessdebuginformation",
	"dbgsetdebugfilterstate",
	"ntsetdebugfilterstate",
	"dbgbreakpoint",                // ntdll patch target
	"dbguiremotebreakin",           // ntdll patch target
	"blockinput",
	"ntyieldexecution",
	"getwritewatch",                // MEM_WRITE_WATCH page-modification check
};

// Weak: technically used by some checks, but also pulled in by the MSVC C
// runtime / common app code (IsDebuggerPresent and SetUnhandledExceptionFilter
// are in essentially every MSVC binary). These NEVER fire on their own — they
// only add a small corroborating score when a real technique already matched,
// so a clean compiler-generated binary is not flagged.
const char* const kWeakImports[] = {
	"isdebuggerpresent",
	"setunhandledexceptionfilter",
	"outputdebugstringa",
	"outputdebugstringw",
	"addvectoredexceptionhandler",
	"removevectoredexceptionhandler",
	"ntclose",                      // invalid-handle anti-debug
	"debugbreak",
	"raiseexception",
	"getthreadcontext",             // hardware-breakpoint (DR0-3) check
	"switchtothread",
	"findwindowa", "findwindoww", "findwindowexa", "findwindowexw",
	"createtoolhelp32snapshot",
};

// ---- Tool name strings ----------------------------------------------------
// Distinctive tokens only (avoid bare "ida" etc. that false-positive on words).
const char* const kToolStrings[] = {
	"ollydbg", "x64dbg", "x32dbg", "x96dbg", "windbg", "idaq", "ida64",
	"immunity debugger", "immunitydebugger", "dnspy", "cheat engine",
	"cheatengine", "process hacker", "processhacker", "procmon", "procexp",
	"x64dbg.exe", "dbgview", "pestudio", "scylla", "pe-sieve", "hollows_hunter",
	"windbgframeclass",
	// Distinctive FindWindow debugger window classes (Check Point "misc"). Only
	// unambiguous ones — generic shared classes like "Qt5QWindowIcon",
	// "SunAwtFrame", "ID" and "ntdll.dll" are intentionally excluded (huge FP risk).
	"antidbg", "obsidiangui", "rock debugger", "zeta debugger",
};

} // namespace

namespace AntiDebugEngine {

void Collect(ScanEngine::ScanContext& Context)
{
	ScanEngine::PeInfo* pe = Context.Pe;
	if (pe == nullptr || !pe->Valid) {
		return;
	}

	const Patterns& bank = Bank();
	const std::vector<SectionView> code = ExecutableViews(*pe);
	const std::vector<BytePattern::Pattern>& pebAccess = pe->Is64 ? bank.PebAccessX64 : bank.PebAccessX86;
	const std::vector<BytePattern::Pattern>& ngfFollow = pe->Is64 ? bank.NtGlobalFlagFollowX64 : bank.NtGlobalFlagFollowX86;

	int techniques = 0;

	// --- Layer 1: code byte-patterns ---
	bool pebAccessed = false;
	for (const auto& pat : pebAccess) {
		if (AnyContains(code, pat)) {
			pebAccessed = true;
			break;
		}
	}

	bool beingDebugged = false;
	bool ntGlobalFlag = false;
	for (const auto& anchor : pebAccess) {
		if (!beingDebugged && AnyContainsNear(code, anchor, bank.BeingDebuggedFollow, kPebFollowWindow)) {
			beingDebugged = true;
		}
		if (!ntGlobalFlag && AnyContainsNear(code, anchor, ngfFollow, kPebFollowWindow)) {
			ntGlobalFlag = true;
		}
	}

	if (beingDebugged) {
		Context.AddSignal("ad.peb_beingdebugged", "Anti-debug: PEB BeingDebugged check",
			kScoreBeingDebugged, ScanEngine::Confidence::High);
		++techniques;
	}
	if (ntGlobalFlag) {
		Context.AddSignal("ad.peb_ntglobalflag", "Anti-debug: PEB NtGlobalFlag check",
			kScoreNtGlobalFlag, ScanEngine::Confidence::High);
		++techniques;
	}
	// Only report the generic PEB access if neither specific check matched, to
	// avoid double-counting the same code.
	if (pebAccessed && !beingDebugged && !ntGlobalFlag) {
		Context.AddSignal("ad.peb_access", "Anti-debug: direct PEB pointer read",
			kScorePebAccess, ScanEngine::Confidence::Medium);
		++techniques;
	}

	if (AnyContains(code, bank.Int2d)) {
		Context.AddSignal("ad.int2d", "Anti-debug: int 2Dh debugger trap",
			kScoreInt2d, ScanEngine::Confidence::High);
		++techniques;
	}
	if (AnyContains(code, bank.Int3Long)) {
		Context.AddSignal("ad.int3_long", "Anti-debug: int 3 (long form) breakpoint trap",
			kScoreInt3Long, ScanEngine::Confidence::High);
		++techniques;
	}
	if (AnyContains(code, bank.Rdtsc)) {
		Context.AddSignal("ad.rdtsc", "Anti-debug: rdtsc timing check",
			kScoreRdtsc, ScanEngine::Confidence::Medium);
		++techniques;
	}
	if (AnyContains(code, bank.Rdtscp)) {
		Context.AddSignal("ad.rdtscp", "Anti-debug: rdtscp timing check",
			kScoreRdtscp, ScanEngine::Confidence::Medium);
		++techniques;
	}
	if (AnyContains(code, bank.KUserShared)) {
		Context.AddSignal("ad.kuser_shared", "Anti-debug: KUSER_SHARED_DATA KdDebuggerEnabled read",
			kScoreKUserShared, ScanEngine::Confidence::High);
		++techniques;
	}

	// --- Layer 2: anti-debug imports (tiered) ---
	std::unordered_set<std::string> imports(pe->Imports.begin(), pe->Imports.end());

	// Strong imports each fire and count as a technique.
	std::string matchedStrong;
	int strongHits = 0;
	for (const char* name : kStrongImports) {
		if (imports.find(name) != imports.end()) {
			if (strongHits < 4) {
				if (!matchedStrong.empty()) matchedStrong += ", ";
				matchedStrong += name;
			}
			++strongHits;
		}
	}
	if (strongHits > 0) {
		std::string desc = "Anti-debug: API imports (" + matchedStrong;
		if (strongHits > 4) desc += ", ...";
		desc += ")";
		Context.AddSignal("ad.imports", desc, kScoreStrongImports, ScanEngine::Confidence::High);
		++techniques;
	}

	// Weak/CRT-common imports are counted but deferred: they only contribute a
	// small corroborating score *after* we know a real technique fired, so a
	// clean compiler-generated binary (which always carries IsDebuggerPresent /
	// SetUnhandledExceptionFilter) is never flagged on imports alone.
	std::string matchedWeak;
	int weakHits = 0;
	for (const char* name : kWeakImports) {
		if (imports.find(name) != imports.end()) {
			if (weakHits < 4) {
				if (!matchedWeak.empty()) matchedWeak += ", ";
				matchedWeak += name;
			}
			++weakHits;
		}
	}

	// --- Layer 3: debugger/analysis tool name strings ---
	const std::string& strings = PeImage::GetStrings(*pe);
	std::string matchedTool;
	for (const char* token : kToolStrings) {
		if (strings.find(token) != std::string::npos) {
			matchedTool = token;
			break;
		}
	}
	if (!matchedTool.empty()) {
		Context.AddSignal("ad.tool_strings",
			"Anti-debug: references analysis tool '" + matchedTool + "'",
			kScoreToolStrings, ScanEngine::Confidence::High);
		++techniques;
	}

	// --- Deferred corroboration: weak imports only count once something real
	// has already fired. They add a small score but do NOT raise the technique
	// count (so they can't, by themselves, trip the combo escalation). ---
	if (weakHits > 0 && techniques > 0) {
		std::string desc = "Anti-debug: corroborating API imports (" + matchedWeak;
		if (weakHits > 4) desc += ", ...";
		desc += ")";
		Context.AddSignal("ad.imports_weak", desc, kScoreWeakImports, ScanEngine::Confidence::Low);
	}

	// --- Escalation: stacking multiple techniques is far more telling ---
	if (techniques >= 3) {
		Context.AddSignal("ad.combo",
			"Anti-debug: multiple techniques combined (" + std::to_string(techniques) + ")",
			kScoreComboThreePlus, ScanEngine::Confidence::High);
	} else if (techniques >= 2) {
		Context.AddSignal("ad.combo",
			"Anti-debug: multiple techniques combined (" + std::to_string(techniques) + ")",
			kScoreComboTwo, ScanEngine::Confidence::Medium);
	}
}

}
