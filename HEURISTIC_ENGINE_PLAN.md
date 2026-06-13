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
| 5b | TLSH fuzzy hashing (`TlshEngine`) | ☑ | `TlshEngine` + `TlshDatabase` built & wired into pipeline/config/UI/scoring |
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
- 2026-06-12: **Phase 5b planning.** TLSH library vendored under
  `Protections/Engines/TLSH/` and confirmed compiling, built statically into the exe
  with `TLSH_LIB` defined (no `.lib`/`.dll`, matching the json.hpp/ImGui vendoring;
  the export macros are gated on `TLSH_EXPORTS`/`dllimport`, which we avoid). API
  confirmed from the vendored `simple_unittest.cpp` (`final` / `isValid` / `getHash` /
  `fromTlshStr` / `totalDiff`). Wrote the detailed implementation plan (see the
  expanded **Phase 5b** section): a `TlshEngine` collector that hashes the existing
  `Context.Pe->Buffer` (zero extra I/O, runs at the `EnginePipeline.cpp:56`
  placeholder) + a `TlshDatabase` mirroring `HashDatabase` (loads
  `%ProgramData%\MiniAV\tlsh.json`, pre-parses each blacklist digest once), a
  distance-banded weighted `sim.family` signal, a `UseTlshEngine`/`TlshMaxDistance`
  knob, and `DeriveCategory` + combo surfacing. Not yet implemented. Next: build
  `TlshDatabase` + `TlshEngine` per the checklist.
- 2026-06-12: **Phase 5b — `TlshDatabase` + `TlshEngine` built** (not yet wired into
  the pipeline). `TlshDatabase` mirrors `HashDatabase`: loads
  `%ProgramData%\MiniAV\tlsh.json` (`tlsh_deny` array of
  `{tlsh,name,family,max_distance}`), default-write-if-missing, load-once,
  mutex-guarded; pre-parses each digest via `fromTlshStr` and drops invalid ones;
  `Match()` returns the smallest-distance entry within its limit. `TlshEngine::Collect`
  digests `Context.Pe->Buffer` (zero extra I/O), skips on `!isValid()`, records
  `Context.TlshHex = getHash(1)`, and on a match appends one distance-banded
  `sim.family` signal (≤30→45/High, ≤50→30/Med, else 18/Low). Added supporting fields
  `ScanContext.TlshHex` and `EngineSettings.UseTlshEngine`/`TlshMaxDistance` (default
  70). Registered all four files in `.vcxproj`/`.filters`. **Remaining wiring:**
  `FileScan` Initialize/Shutdown, the `EnginePipeline.cpp:56` collector call,
  `Config` persistence, the `MainWindow` toggle, and `ScoreEngine::DeriveCategory` +
  combo. **Heads-up:** the Debug config defines `TLSH_LIB` but not `WINDOWS`, which
  the TLSH header needs on MSVC — currently only Release defines both.
- 2026-06-12: **Phase 5b wired & complete** (`WINDOWS` now defined in Debug too).
  `TlshDatabase::Initialize/Shutdown` added to `FileScan.cpp`; the collector runs as
  `if (cfg.UseTlshEngine) TlshEngine::Collect(Context)` after AntiDebug in
  `EnginePipeline`; `Config` persists `Engine.UseTlshEngine` + `Engine.TlshMaxDistance`;
  `MainWindow` got a TLSH checkbox + a "match distance" slider (gated on the toggle);
  `DeriveCategory` ranks `sim.` first ("Known-malware similarity"); a default
  `sim.`+`cap.` combo (+20) was added to `scoring.json`. `TlshEngine` also `LOG_INFO`s
  each file's computed digest so a sample's `T1...` can be copied straight into
  `tlsh.json`. Note: `scoring.json` is load-once, so the new combo only appears on a
  fresh install (delete the file to regenerate). Not yet built/verified this session.
- 2026-06-12: **TLSH switched to code-section (.text) hashing + Debug Panel add form.**
  Whole-file TLSH was dominated by MSVC/CRT/import/resource boilerplate, so small
  binaries all looked similar (poor sensitivity *and* specificity). `TlshEngine::Collect`
  now `update()`s the digest over the executable sections only (from
  `Context.Pe->Sections`, each span clamped to the buffer) then `final()`s —
  fingerprinting code, not the PE wrapper. Files with no exec-section bytes or too
  little code (`!isValid()`) get no signal. **Consequence:** digests previously
  curated as whole-file hashes won't match the new `.text` digests — re-add samples
  from the updated `tlsh(text)=` log line. Also added the Debug Panel "TLSH blacklist"
  form (`TlshDatabase::AddEntry`) for validated, live, no-restart additions to
  `tlsh.json` (the elevated service can write the restricted ProgramData path).

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

### 5b — TLSH fuzzy hashing (family similarity) — detailed implementation plan

Exact SHA-256 in `HashEngine` only catches a byte-identical file; flip one byte
and it misses. **TLSH (Trend Micro Locality Sensitive Hash)** produces a digest
where *similar* files yield *close* digests, so a known-malware variant still
scores near a blacklisted sample. It is **fuzzy/probabilistic**, so it feeds the
score as a weighted signal, never a lone hard block (combine with capabilities).

Why TLSH over `ssdeep`: a fixed-length digest, robust against small edits and
padding, and a single well-defined distance function — clean to embed and to
explain in the thesis.

**Status:** library vendored under `Protections/Engines/TLSH/`, compiles
statically into `Mini-AV.exe` with `TLSH_LIB` defined (no `.lib`/`.dll`, matching
how `json.hpp`/ImGui are vendored — and avoiding a DLL-hijack surface on an AV).

#### TLSH API surface we use (confirmed from `TLSH/simple_unittest.cpp`)

- `Tlsh t; t.final(const unsigned char* data, unsigned int len);` — one-shot digest
  over a buffer.
- `bool t.isValid();` — false when the input was too small / too low-variance to
  digest (TLSH needs ≳50 bytes and enough byte diversity). **Must check before use.**
- `const char* t.getHash(1);` — digest string, version-prefixed (`T1...`).
- `t.fromTlshStr(const char* s);` — rebuild a `Tlsh` from a stored digest string
  (accepts the `T1` prefix).
- `int a.totalDiff(&b, /*lenDiff=*/true);` — distance; **0 = identical, larger =
  less similar**. Use the length-aware form for files.

#### Integration reuses what already exists (no second file read)

`EnginePipeline.cpp` already parses the PE once and exposes the **raw file bytes**
as `Context.Pe->Buffer` (capped at 64 MB). TLSH hashes that buffer directly, so the
collector runs in step (2) of `RunPipeline`, after `PeImage::Parse`, exactly like
`ContextEngine`/`CapabilityEngine` — the placeholder comment is already at
`EnginePipeline.cpp:56`. Add `std::string TlshHex;` to `ScanContext` (beside
`Sha256Hex`) so the digest flows into logs and `PipelineResult`, and so a sample's
digest is trivial to read off when curating the blacklist.

#### New files (mirror the `HashEngine` + `HashDatabase` split)

**`TlshDatabase.cpp/.h`** — same ProgramData-JSON idiom as `HashDatabase` /
`CapabilityDatabase`:
- Loads `%ProgramData%\MiniAV\tlsh.json`, writes a default (empty list) if missing,
  mutex-guarded, **load-once** (no hot-reload, matching the others).
- Schema:
  ```json
  {
    "tlsh_deny": [
      { "tlsh": "T1A1B2...", "name": "Emotet loader", "family": "Emotet", "max_distance": 70 }
    ]
  }
  ```
- At load, each entry's `tlsh` string is parsed **once** via `fromTlshStr` into an
  in-memory `Tlsh` (skip + log entries that fail validation), so per-scan matching
  costs only `totalDiff`, never a re-parse. `max_distance` is optional per entry
  (falls back to the global threshold).
- API: `Initialize()`, `Shutdown()`, `size_t EntryCount()`, `std::wstring
  DatabasePath()`, and `Match(const Tlsh& candidate)` returning the best
  (smallest-distance) entry within threshold plus its distance.

**`TlshEngine.cpp/.h`** — the collector `Collect(ScanContext&)`:
1. Guard on `Context.Pe && Context.Pe->Read && !Context.Pe->Buffer.empty()`.
2. `Tlsh t; t.final(Buffer.data(), (unsigned)Buffer.size());` → if `!t.isValid()`
   return (tiny/low-variance file — just no signal).
3. Store `t.getHash(1)` into `Context.TlshHex`.
4. `TlshDatabase::Match(t)` → on a hit, `AddSignal("sim.family", "Similar to <name>
   (<family>), TLSH distance <d>", score, conf)`.
5. **Score/confidence by distance band** (closer = stronger), tunable constants:

   | distance | score | confidence |
   |---|---|---|
   | ≤ 30 | 45 | High |
   | ≤ 50 | 30 | Medium |
   | ≤ threshold (default 70) | 18 | Low |

   Only the **best** match emits a signal (don't stack near-duplicates of one
   family). The weighting lets a *single distant* hit only nudge the score, while a
   *close* hit — or a close hit plus a capability — reaches Block via bands/combos.

#### Settings / config

- Add `bool UseTlshEngine = true;` and `int TlshMaxDistance = 70;` to
  `EngineSettings::Settings`.
- Persist both in `Config.cpp` (`Engine.UseTlshEngine`, `Engine.TlshMaxDistance`)
  via the existing `j.value(...)` pattern.
- Gate the collector with `if (cfg.UseTlshEngine)` in `RunPipeline`.
- Add a checkbox to `MainWindow.cpp`'s per-engine section, like the others.

#### Score / category surfacing

- Extend `ScoreEngine::DeriveCategory` with `sim.` → "Known malware family
  (similarity)" (priority just under the definitive hash block, above generic
  capabilities).
- Optional `scoring.json` combo: `sim.family` + `cap.*` (e.g. similarity +
  injection) for an extra bonus — a fuzzy family hit *and* a malicious capability
  together is much stronger than either alone.

#### Wiring checklist

- `FileScan.cpp`: `TlshDatabase::Initialize()` / `Shutdown()` next to `HashDatabase`.
- `EnginePipeline.cpp:56`: `if (cfg.UseTlshEngine) TlshEngine::Collect(Context);`.
- `ScanEngine.h`: add `TlshHex`.
- `Mini-AV.vcxproj` + `.filters`: register `TlshEngine.*`, `TlshDatabase.*` (the
  TLSH library `.cpp`s are already in the project; define `TLSH_LIB` project-wide).
- `EngineSettings.h`, `Config.cpp`, `MainWindow.cpp`, `ScoreEngine.cpp`, default
  `scoring.json`: as above.

#### Curating the blacklist (demo workflow)

`Context.TlshHex` is logged on every scan, so: run a known sample through Mini-AV,
copy its `T1...` digest from the logs into `tlsh.json` with a name/family, restart,
and every near-variant of that sample now matches. (A future convenience would be a
one-shot "compute TLSH of file X" path, but reading it from the log is enough for
the demo.)

#### Edge cases for the write-up

- TLSH refuses tiny/low-entropy inputs (`isValid()==false`) → those files get no
  `sim` signal; the other engines still run (this layer fails open).
- Packed files: TLSH characterizes the *packer*, not the payload (same caveat as the
  byte patterns below) — sign the stub or an unpacked dump.
- Distance is not a probability; the threshold is empirical. 70 is a common
  "same family" cutoff; lower toward 30–50 for fewer false matches.

**Effort:** ~1 day (library already integrated).

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
├── TlshEngine.cpp / .h         # Phase 5b — collector: digest Context.Pe->Buffer, match vs blacklist
├── TlshDatabase.cpp / .h       # Phase 5b — tlsh.json loader (HashDatabase idiom), pre-parsed digests
├── TLSH/                       # Phase 5b — vendored Trend Micro TLSH source (compiled with TLSH_LIB)
└── (capabilities.json, tlsh.json, signatures.json live under %ProgramData%\MiniAV\)
```

Touched existing files: `ScanEngine.h` (Signal/ScanContext), `EnginePipeline.cpp`
(new pipeline order), `Alerts`/UI (Phase 4 surfacing), `HashDatabase`-style loader
reused for `capabilities.json` hot-reload.
