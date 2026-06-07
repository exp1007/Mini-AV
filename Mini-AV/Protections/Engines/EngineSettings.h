#pragma once

// Runtime-tunable engine knobs, edited from the dashboard and persisted by Config.
// Deliberately dependency-free: the scan-engine core (EnginePipeline, ScoreEngine,
// FileScan, FilePolicy) reads EngineSettings::Current without ever pulling in UI or
// Config headers. The UI writes Current and asks Config to persist it.
namespace EngineSettings {

	// Sensitivity preset. Anything but Custom drives the threshold triple below via
	// ApplyPreset(); Custom hands ownership of the thresholds to the UI sliders.
	enum class Sensitivity : int {
		Low = 0,        // fewer detections, higher bar to block
		Balanced = 1,   // default (matches the historical scoring.json defaults)
		Aggressive = 2, // more detections, lower bar to block
		Custom = 3,
	};

	struct Settings {
		// Master switch. When false, file-create scanning is bypassed entirely
		// (everything is allowed) — the whole real-time engine is off.
		bool RealtimeProtection = true;

		// Per-engine toggles: the definitive SHA-256 deny-list plus the three
		// heuristic signal collectors. Disabling one simply skips it in the pipeline.
		bool UseHashDenyList = true;
		bool UseContextEngine = true;
		bool UseCapabilityEngine = true;
		bool UseAntiDebugEngine = true;

		// Block action: move the offending file to quarantine (true) or merely deny
		// the create (false). Applies to heuristic/engine blocks.
		bool ApplyQuarantine = true;

		// Score bands consumed by ScoreEngine. Owned by the preset unless Custom.
		Sensitivity Preset = Sensitivity::Balanced;
		int Suspicious = 30;
		int Dangerous = 50;
		int Block = 60;
	};

	inline Settings Current;

	// Overwrite the threshold triple from a preset. No-op for Custom so the UI
	// sliders are preserved.
	inline void ApplyPreset(Sensitivity Preset)
	{
		switch (Preset) {
		case Sensitivity::Low:        Current.Suspicious = 45; Current.Dangerous = 65; Current.Block = 80; break;
		case Sensitivity::Balanced:   Current.Suspicious = 30; Current.Dangerous = 50; Current.Block = 60; break;
		case Sensitivity::Aggressive: Current.Suspicious = 20; Current.Dangerous = 35; Current.Block = 45; break;
		case Sensitivity::Custom:
		default:
			break;
		}
	}
}
