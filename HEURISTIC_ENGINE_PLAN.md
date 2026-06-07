# Mini-AV — Heuristic Engine Integration Plan

## Implementation Log

> Running record of what is actually built, so context survives across sessions.
> Status legend: ☐ not started · ◐ in progress · ☑ done.

| Phase | Item | Status | Notes |
|---|---|---|---|
| 0 | `Signal`/`Confidence` data model in `ScanEngine.h` | ☑ | + `ScanContext.Signals`, `Pe*`, `AddSignal()` |
| 0 | `ScoreEngine` (minimal: sum + thresholds) | ☑ | bands 30/60 hardcoded; enriched in Phase 3 |
| 0 | `RunPipeline` hybrid refactor in `EnginePipeline.cpp` | ☑ | stub removed; hash short-circuit -> ScoreEngine |
| 1 | `PeImage` parse-once + `ScanContext.Pe` | ☑ | bounds-checked parser; sections+entropy+imports |
| 1 | Context signals: motw / double_ext / bad_path / packed | ☑ | `ContextEngine`; `fake_ext` → `double_ext` (see note) |
| 2 | `CapabilityEngine` + `capabilities.json` loader | ☑ | `CapabilityDatabase` loader + 10-rule default catalog |
| 3 | `ScoreEngine` combos + config-driven thresholds | ☑ | `ScoreConfig` loads `scoring.json` (thresholds + combos) |
| 4 | UI surfacing of signal list | ☑ | toast shows generic **category**; full detail in Alerts/Logs panel |
| 5a | Byte-pattern matcher (`BytePattern`) | ☑ | matcher + dedicated `AntiDebugEngine` already built |
| 5b | TLSH fuzzy hashing (`TlshEngine`) | ☐ | |
| 5c | IDA-style specimen signatures | ☐ | reuses 5a matcher |

**Session notes**

- 2026-06-05: Started Phase 0. Read current pipeline (`HashEngine` → stub in
  `EnginePipeline.cpp`, called from `FilePolicy.cpp:168`). Thresholds hardcoded as
  named constants in `ScoreEngine` for now; config wiring deferred to Phase 3.
- 2026-06-05: **Phase 0 complete, builds clean** (x64 Debug, 0 warnings). Added
  `Confidence`/`Signal` + `Signals`/`Pe`/`AddSignal()` to `ScanEngine.h`; created
  `ScoreEngine.cpp/.h` (sum signals → bands <30 clean / 30–59 suspicious-but-allow
  / ≥60 block, reason = joined descriptions); rewrote `RunPipeline` to short-circuit
  on hash then call `ScoreEngine::Decide`; removed the always-Allow stub. Registered
  `ScoreEngine.cpp` + engine headers in `.vcxproj`/`.filters`. No signals exist yet,
  so behavior is unchanged (everything past hash → Allow) — exactly the intended
  no-op foundation. Next: Phase 1 (`PeImage` + context signals).
- 2026-06-05: **Phase 1 complete, builds clean** (x64 Debug, 0 warnings). New
  `PeImage.cpp/.h`: reads file once (64 MB cap), parses DOS/NT/optional headers,
  section table (+ per-section Shannon entropy), and the import table (ILT/IAT,
  PE32 & PE32+), all through a single bounds-checked `At()` view so a hostile PE
  can't read past the buffer. `PeInfo` defined in `ScanEngine` namespace (matches
  the Phase-0 forward decl); buffer/imports reused by later phases. New
  `ContextEngine.cpp/.h` appends: `ctx.motw` (Zone.Identifier ADS, ZoneId 3/4, +10),
  `ctx.double_ext` (+35,High), `ctx.bad_path` (Temp/Downloads/AppData/removable/
  network, +10), `pe.packed` (exec section entropy >7.2, +20), `pe.malformed`
  (+15). `RunPipeline` now parses the PE onto its stack, sets `Context.Pe`, runs
  `ContextEngine::Collect`, then detaches `Context.Pe` before returning.
  **Deviation:** plan's `ctx.fake_ext` ("MZ bytes but document extension") is
  *unreachable* — `FilePolicy.cpp:157` allows non-executable extensions before the
  pipeline runs, so a `.pdf` never gets scanned. Implemented the reachable variant
  `ctx.double_ext` (e.g. `invoice.pdf.exe`) instead. To get true fake-extension
  detection later we'd have to relax FilePolicy to scan all creates (bigger change,
  out of scope now). Next: Phase 2 (`CapabilityEngine` + `capabilities.json`).
- 2026-06-05: **Phase 2 complete, builds clean** (x64 Debug, 0 warnings). New
  `CapabilityDatabase.cpp/.h` mirrors the `HashDatabase` pattern: loads
  `%ProgramData%\MiniAV\capabilities.json`, writes a default 10-rule catalog if
  missing (injection, keylogger, ransom, persistence, anti-debug, anti-vm, network,
  cred-theft, dynamic-api, self-delete). Rule = `imports_all`/`imports_any`/
  `strings_any`, all lowercased; fires when every non-empty clause passes. New
  `CapabilityEngine.cpp/.h` builds an import set from `PeInfo.Imports`, extracts
  ASCII+UTF-16LE string runs (>=4 chars, only if any rule needs strings) into one
  lowercased blob, evaluates rules, appends one Signal per hit. Wired
  `CapabilityDatabase::Initialize/Shutdown` into `FileScan.cpp` next to
  `HashDatabase`, and `CapabilityEngine::Collect` after `ContextEngine` in
  `RunPipeline`. Note: low-score weak caps (dynamic_api/network +15) intentionally
  don't block alone at the 60 threshold — combos do (e.g. injection 40 + dynamic_api
  15 + network 15 = 70 → Block). Next: Phase 3 (combos + config-driven thresholds).
- 2026-06-06: **Anti-debug detector retune (FP fix).** `Tests.exe` (a clean MSVC
  POC) was flagging anti-debug. Root cause was the import layer, not byte
  patterns: `kAntiDebugImports` treated every API equally and fired on a single
  hit, and `IsDebuggerPresent` + `SetUnhandledExceptionFilter` are CRT-universal
  (present in essentially every MSVC binary). Split into **strong** imports (fire
  alone, count as a technique) and **weak/CRT-common** imports (deferred — only add
  a small corroborating score *after* a real technique already fired, never on
  their own). Added Check Point (anti-debug.checkpoint.com) techniques: strong
  imports `NtQueryObject`, `RtlQueryProcessHeapInformation`,
  `RtlQueryProcessDebugInformation`, `Dbg/NtSetDebugFilterState`, `GetWriteWatch`,
  `DbgBreakPoint`, `DbgUiRemoteBreakin`; new byte patterns `CD 03` (int3 long),
  `0F 01 F9` (rdtscp), `D4 02 FE 7F` (KUSER_SHARED_DATA KdDebuggerEnabled); and
  distinctive debugger window-class strings (antidbg/obsidiangui/rock debugger/
  zeta debugger — generic Qt/AWT classes deliberately excluded). Added an
  anti-debug specimen to `Tests/Main.cpp` (menu option 1) using intrinsics
  (`__readgsqword(0x60)` PEB+BeingDebugged, `__rdtsc`/`__rdtscp`, fixed-address
  KUSER read) + static imports (`CheckRemoteDebuggerPresent`, `FindWindow`
  "OLLYDBG", `OutputDebugString`) so it compiles into a real true-positive sample.
- 2026-06-06: **Phase 3 complete.** New `ScoreConfig.cpp/.h` mirrors the
  `CapabilityDatabase` loader: reads `%ProgramData%\MiniAV\scoring.json`, writing a
  default if missing, holding the verdict `thresholds` (suspicious/dangerous/block)
  and a list of `combos`. A combo fires when, for every prefix in its `requires`,
  at least one accumulated signal Id has that prefix (`ad.` matches any anti-debug
  sub-signal, `cap.injection` matches exactly); a firing combo adds its `bonus` to
  the total as a synthetic signal in the breakdown. `ScoreEngine::Decide` now pulls
  thresholds from `ScoreConfig`, folds combos in via `ApplyCombos`, and the
  hardcoded band constants are gone. Wired `ScoreConfig::Initialize/Shutdown` into
  `FileScan.cpp` and registered the files in `.vcxproj`/`.filters`. Default combos:
  injection+anti-debug+C2 (+25), injection+dynamic_api (+15), ransom+anti-analysis
  (+15), packed+anti-debug (+10). **Not yet built/verified in this session.** Next:
  Phase 4 (UI surfacing of the signal list).
- 2026-06-06: **Phase 4 complete (with a notification redesign).** The toast no
  longer dumps the whole joined signal list — it shows a single **generic
  category** so the user gets a one-line "what kind of thing this is", while the
  full breakdown still goes to the Alerts panel + Logs panel. `ScoreEngine` now
  derives `PipelineResult.Category` via `DeriveCategory` (priority-ordered map of
  signal-id prefix → label: e.g. `cap.ransom`→"Ransomware behaviour",
  `cap.injection`→"Process injection", `ad.`→"Anti-debugging", `pe.packed`→"Packed
  / obfuscated code", `ctx.motw`→"Downloaded from the internet"). A hash short-
  circuit block sets category "Known malware signature"; the direct FilePolicy
  verdicts set "Quarantine access" / "Test rule" / "Scan error". `Category` flows
  `PipelineResult` → `ExecutionScanResult` → `Communication`. `Alerts::Add` gained
  optional `toastTitle`/`toastBody` params: the toast keeps its severity-derived
  title ("Threat blocked" / "Warning" / "Notice") and shows the **category** as
  the body (replacing the old full-detail body); panel + logs keep the full
  `details`. Backward compatible — `DebugPanel` 2-arg calls still show their full
  example text. Next: Phase 5b (TLSH) or 5c (specimen sigs), both optional.

---

## Goal

Evolve the scan pipeline from a single "first engine to Block wins" model into a
**hybrid scoring system**: definitive verdicts still short-circuit, but everything
else contributes weighted *signals* (capabilities + context) that a final
`ScoreEngine` aggregates into one explainable verdict.

The headline feature is **capability detection** — deriving *what a binary can do*
(inject code, log keys, encrypt files, talk to a C2, ...) from its imports,
strings, and code-section byte patterns, then feeding those capabilities into the
heuristic score. The verdict becomes a human-readable list of behaviors, which is
both stronger detection and far easier to present.

Everything here is **user-mode only** and slots into the existing pipeline after
`HashEngine::Run` in `EnginePipeline.cpp`, reusing `ScanContext`.

---

## Architectural shift: definitive short-circuit + accumulate-then-decide

Today `RunPipeline` returns on the first `Block`/`Error`. That is correct for a
known-bad hash but wrong for heuristics — a single weak signal must not block, yet
several weak signals together should.

New model:

1. **Definitive verdicts short-circuit** (unchanged behavior)
   - known-bad SHA-256 → instant `Block`
   - (future) trusted signed publisher → instant `Allow`
2. **Everything else accumulates signals** — collectors/heuristic engines append
   `Signal`s to `ScanContext`, none of them returns a final verdict.
3. **`ScoreEngine` decides last** — sums signal scores, applies thresholds and a
   few combo bonuses, and builds the final `PipelineResult` whose reason is the
   joined signal descriptions.

This keeps the fast, certain path intact and adds the heuristic brain underneath.

---

## Data model changes (`Engines/ScanEngine.h`)

```cpp
enum class Confidence { Low, Medium, High };

struct Signal {                 // one piece of evidence
    std::string Id;             // "cap.injection", "ctx.motw", "pe.high_entropy"
    std::string Description;    // human-readable, shown in the alert
    int Score;                  // contribution to risk
    Confidence Conf;
};

struct ScanContext {
    // ...existing fields (ResolvedPath, NtPath, ProcessId, OperationSubtype, Sha256Hex)...

    std::vector<Signal> Signals; // appended by collectors, read by ScoreEngine
    struct PeInfo* Pe = nullptr; // parsed-PE cache (Phase 1), null until parsed
};
```

`PipelineResult` keeps its current shape; `Reason` is populated by `ScoreEngine`
from the fired signals.

---

## Phase 0 — Pipeline refactor to scoring (foundation)

Enabling change; do this before any detection work.

`RunPipeline` becomes:

1. `HashEngine::Run` → if `Block`/`Error`, return immediately (definitive).
2. Run collectors/heuristic engines in order → each **appends `Signal`s**, returns
   no verdict.
3. `ScoreEngine::Decide(Context)` → sums `Signals`, applies thresholds → final
   `PipelineResult` (verdict + signal list as the reason).

**Why first:** every later phase only adds `Signal`s; the decision logic is written
once and never touched again.

**Effort:** ~0.5 day. **Required.**

---

## Phase 1 — Parse the PE once + cheap context signals

### `Engines/PeImage.cpp/.h`

- Read the file into a buffer **once** here; collectors reuse the buffer + parsed
  form via `ScanContext.Pe`.
- Parse DOS/NT headers, section table, import directory (and export/resource
  directories if cheap).
- **Validate every offset/RVA against file size before dereferencing.** Malformed
  PEs are hostile input, not an edge case — bail out to a `pe.malformed` signal
  rather than crashing.
- Respect the existing 64 MB cap and the 2s driver timeout budget.

### Context collectors (no parsing needed — instant wins for the demo)

| Signal id | Detection | How |
|---|---|---|
| `ctx.motw` | Downloaded from the internet | Read `path:Zone.Identifier` ADS, parse `ZoneId=3` |
| `ctx.fake_ext` | Disguised executable | First bytes `MZ` but extension is a document/image |
| `ctx.bad_path` | Runs from a risky location | `ResolvedPath` under `\Temp\`, `\Downloads\`, `\AppData\`, removable drive |
| `pe.packed` | Packed / encrypted | Shannon entropy per section; > ~7.2 in a code section |

These four alone make the scoring feel real and each is one sentence to explain.

**Effort:** ~1–1.5 days. **Required.**

---

## Phase 2 — CapabilityEngine (the core feature)

### `Engines/CapabilityEngine.cpp/.h`

Evidence sources (all from the buffer / `PeInfo`):

- **Imports** — flatten the import table to a lowercased `set<string>`.
- **Strings** — extract ASCII + UTF-16LE runs (>= 4 chars) once into a blob.
- **Byte patterns** — see Phase 5 (optional, same `Signal` output).

### Rules live in an external file

`%ProgramData%\MiniAV\capabilities.json` — same loader pattern as `hashes.json`,
so it hot-reloads and a new capability can be written **live during the demo**.

```json
{
  "capabilities": [
    {
      "id": "cap.injection",
      "name": "Process injection",
      "score": 40, "confidence": "high",
      "imports_all": ["virtualallocex", "writeprocessmemory"],
      "imports_any": ["createremotethread", "queueuserapc", "ntmapviewofsection"]
    },
    {
      "id": "cap.keylogger",
      "name": "Keylogging",
      "score": 30, "confidence": "medium",
      "imports_all": ["setwindowshookex"],
      "imports_any": ["getasynckeystate", "getkeyboardstate"]
    },
    {
      "id": "cap.persistence",
      "name": "Persistence (autorun)",
      "score": 25, "confidence": "medium",
      "imports_any": ["regsetvalueexa", "regsetvalueexw"],
      "strings_any": ["\\currentversion\\run", "appinit_dlls", "schtasks"]
    }
  ]
}
```

Rule logic: fire if `imports_all` is a subset of the import set **and** every
specified `*_any` list has at least one hit. Each fired capability appends one
`Signal`.

### Starter capability catalog (~10 rules)

| Capability | Evidence (imports / strings / bytes) |
|---|---|
| **Process injection** | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`/`QueueUserAPC`/`NtMapViewOfSection` |
| **Keylogging** | `SetWindowsHookEx` + `GetAsyncKeyState`/`GetKeyboardState`, or raw-input APIs |
| **Ransomware / crypto** | `CryptEncrypt`/`BCryptEncrypt` + file-enum (`FindFirstFile`/`FindNextFile`) + `MoveFile`/`DeleteFile`; strings `.locked`, ransom-note names |
| **Persistence** | `RegSetValueEx` + strings `\CurrentVersion\Run`, `services`, IFEO, `schtasks`, `AppInit_DLLs` |
| **Anti-debug** | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`; byte patterns `rdtsc`, `int 3`, PEB `BeingDebugged` |
| **Anti-VM / sandbox** | strings `VBOX`, `VMWARE`, `vmtoolsd`, `SbieDll.dll`; `cpuid` patterns |
| **Network / C2** | `WinHttp*`/`InternetOpen*`/`socket`/`connect`; embedded URLs, IPs, user-agent strings |
| **Credential theft** | strings/paths to browser cred stores, `lsass`, `vaultcli.dll`, `CredEnumerate` |
| **Dynamic API resolution (evasion)** | thin IAT + `LoadLibrary`+`GetProcAddress` + API names present only as *strings* |
| **Self-deletion** | strings `cmd /c del`, `ping -n ... & del`, move-self patterns |

**Demo payoff:** the alert reads *"Blocked: Process injection + Anti-debug +
Network C2 -> HIGH."*

**Effort:** ~1.5–2 days. **Core feature.**

---

## Phase 3 — ScoreEngine + thresholds

### `Engines/ScoreEngine.cpp/.h`

- Sum `Signal.Score` over all appended signals.
- Map total to bands (config-driven, tunable without recompile):
  - `< 30` → Allow
  - `30–59` → Allow but log (suspicious)
  - `>= 60` → Block
- **Combo bonuses** — certain combinations are worse than the sum, e.g.
  `cap.injection` + `cap.anti_debug` + `cap.network_c2` adds an extra penalty.
- `PipelineResult.Reason` = joined signal descriptions, which flows straight into
  the existing `Alerts::Add` and logging.

Keep thresholds, weights, and combos in config so the model can be tuned without
recompiling.

**Effort:** ~0.5 day. **Required.**

---

## Phase 4 — Surface it in the UI

- `Alerts::Add` already takes a string; pass the capability/signal list so the
  toast and the Alerts terminal show *why* something was blocked.
- Optional: a small "last scan detail" panel (reuse the `DebugPanel` pattern)
  listing capabilities + score for the most recent block. Very presentable.

**Effort:** ~0.5 day. **Demo polish.**

---

## Phase 5 — Byte-pattern capabilities + family/specimen matching (optional advanced depth)

Two complementary detection layers that target what imports and strings miss.
Both emit the same `Signal` shape, so **no scoring changes are needed**. Neither
uses YARA — the goal is detection a reverse engineer can drive directly, with no
external rule-engine dependency.

### 5a — Capability byte patterns (behavior from code)

Some behaviors never show up as clean imports — dynamic API resolution,
position-independent shellcode stubs, packed code that imports almost nothing.
These are caught by scanning the **code sections** for short byte/mask patterns.

Extend `capabilities.json` rules with a `bytes_any` field of hex patterns with
wildcards, matched against each executable section:

```json
{
  "id": "cap.peb_walk",
  "name": "PEB access / dynamic resolution",
  "score": 25, "confidence": "medium",
  "bytes_any": [
    "64 A1 30 00 00 00",        // mov eax, fs:[30h]   (PEB, x86)
    "65 48 8B 04 25 60 00 00 00" // mov rax, gs:[60h]  (PEB, x64)
  ]
}
```

Matcher: for each pattern, parse hex bytes + `??` wildcards into a byte+mask
array, then sliding-window compare against each section's raw bytes. A few hundred
lines, no dependencies. These are *generic capability* patterns — the same XOR
loop or PEB walk shape appears across many unrelated binaries.

| Capability | Pattern intent |
|---|---|
| **PEB walk / dynamic resolution** | `fs:[30h]` / `gs:[60h]` access prologues |
| **Direct syscall stubs** | `mov r10, rcx; mov eax, <num>; syscall` sequences |
| **Anti-debug timing** | `rdtsc` near compare/branch |
| **Shellcode decryption loop** | common XOR-decrypt-in-place loop shapes |
| **Stack-string construction** | runs of `mov byte ptr [...], <imm>` building strings in memory |

### 5b — TLSH fuzzy hashing (family similarity)

Exact SHA-256 in `HashEngine` only catches a byte-identical file; flip one byte
and it misses. **TLSH (Trend Micro Locality Sensitive Hash)** produces a digest
where *similar* files yield *close* digests, so a known-malware variant still
scores near a blacklisted sample.

- Compute the TLSH digest of the file buffer (Phase 1 already has it in memory).
- Keep a blacklist of digests in `%ProgramData%\MiniAV\tlsh.json` (same loader
  pattern as `hashes.json`), each with a name and family.
- For each blacklist entry, compute TLSH distance. Distance is a small integer
  where **0 = identical, lower = more similar**; a threshold (~tunable, ~40–70
  depending on tolerance) decides a hit.
- A hit appends a `Signal` like `sim.family` with the matched family name and the
  distance, e.g. *"Similar to Emotet variant (TLSH distance 31)."*

Why TLSH over `ssdeep`: a fixed-length digest, robust against small edits and
padding, and a single well-defined distance function — clean to embed and to
explain in the thesis. It is **fuzzy/probabilistic**, so it feeds the score as a
weighted signal rather than a hard block on its own (combine with capabilities).

### 5c — IDA-style specimen signatures (analyst blacklisting)

This is the layer for an actual reverse engineer. After analyzing a sample in
IDA/Ghidra, the analyst picks a stable, discriminating code region — a function
prologue, an unpacking routine, a unique constant table — and writes it as an
**IDA-style signature**: a hex byte sequence with wildcards for the parts that
vary (relocated addresses, immediates), exactly like an IDA `0F B6 ?? 8B` pattern.

`%ProgramData%\MiniAV\signatures.json`:

```json
{
  "signatures": [
    {
      "id": "sig.redline.stub",
      "name": "RedLine Stealer — config decrypt stub",
      "family": "RedLine",
      "score": 80, "confidence": "high",
      "pattern": "55 8B EC 83 EC ?? 53 56 57 8B ?? ?? E8 ?? ?? ?? ?? 33"
    }
  ]
}
```

Reuses the **same byte+mask matcher built in 5a** — the only addition is loading
a second rule file scoped to *named specimens* rather than generic capabilities.
A specimen signature is high-confidence and high-score (it identifies *this*
malware, not a behavior), so a match can push straight into Block on its own,
unlike the generic capability patterns and the fuzzy TLSH signal.

**Division of labor across the three hash/pattern layers:**

| Layer | Catches | Authored by | Verdict weight |
|---|---|---|---|
| SHA-256 (`HashEngine`) | byte-identical known-bad | anyone, automatic | hard block |
| TLSH (5b) | *variants* of a known family | sample collection | weighted signal |
| IDA-style signature (5c) | a *specific* analyzed specimen | reverse engineer | high / can block |
| Capability bytes (5a) | a *behavior*, family-agnostic | rule author | weighted signal |

> Note: byte patterns over packed code will mostly hit the *packer stub*, not the
> real payload — which is itself a useful signal (combine with `pe.packed`). TLSH
> over a packed file likewise characterizes the packer; for packed specimens the
> analyst signs the stub or an unpacked dump. True unpacking is out of scope (that
> would need execution/emulation, which this project intentionally avoids).

**Effort:** ~+1 day (5a matcher) + ~1 day (TLSH integration) + ~0.5 day (5c reuses
the matcher). **Optional, but 5c is the headline "for real analysts" feature.**

---

## Order & effort summary

| Phase | What | Effort | Status |
|---|---|---|---|
| 0 | Scoring refactor (`Signal`, hybrid `RunPipeline`) | 0.5 day | required |
| 1 | `PeImage` parse + 4 context signals | 1–1.5 days | required |
| 2 | `CapabilityEngine` + `capabilities.json` | 1.5–2 days | core feature |
| 3 | `ScoreEngine` + thresholds + combos | 0.5 day | required |
| 4 | UI surfacing of signals | 0.5 day | demo polish |
| 5a | Capability byte patterns (hex+mask matcher) | +1 day | optional |
| 5b | TLSH fuzzy hashing + blacklist | +1 day | optional |
| 5c | IDA-style specimen signatures (reuses 5a matcher) | +0.5 day | optional |

Phases 0–4 deliver a real multi-signal heuristic AV with explainable verdicts in
roughly a week. Phase 5 adds the genuinely-advanced layers if time allows: generic
code-pattern capabilities (5a), TLSH family similarity (5b), and analyst-authored
specimen signatures (5c) — the last being the standout "real reverse engineers can
blacklist a specific malware" feature.

---

## New files

```
Mini-AV/Protections/Engines/
├── PeImage.cpp / .h            # Phase 1 — parse-once PE, stored in ScanContext.Pe
├── CapabilityEngine.cpp / .h   # Phase 2 — imports/strings/bytes -> capabilities
├── ScoreEngine.cpp / .h        # Phase 3 — aggregate signals -> verdict
├── BytePattern.cpp / .h        # Phase 5a — hex+mask matcher (shared by 5a & 5c)
├── TlshEngine.cpp / .h         # Phase 5b — fuzzy digest + distance vs blacklist
└── (capabilities.json, tlsh.json, signatures.json live under %ProgramData%\MiniAV\)
```

Touched existing files: `ScanEngine.h` (Signal/ScanContext), `EnginePipeline.cpp`
(new pipeline order), `Alerts`/UI (Phase 4 surfacing), `HashDatabase`-style loader
reused for `capabilities.json` hot-reload.
