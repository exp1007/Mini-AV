#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Lightweight hex byte-pattern matcher with wildcards, used by code-level
// detectors (anti-debug now; capability byte rules / IDA-style signatures later).
// Pattern syntax is a hex string with optional spaces; "??" (or "?") is a
// single-byte wildcard, e.g. "0F B6 ?? 02" or "65 48 8B ?? 25 60 00 00 00".
namespace BytePattern {

constexpr size_t kNoMatch = static_cast<size_t>(-1);

struct Pattern {
	std::vector<uint8_t> Bytes; // expected byte values (0 where wildcard)
	std::vector<uint8_t> Mask;  // 0xFF = must match, 0x00 = wildcard
	bool Valid = false;

	size_t Size() const { return Bytes.size(); }
};

// Compile a pattern spec. Returns Valid == false on malformed input.
Pattern Compile(const std::string& Spec);

// First match offset at or after Start, or kNoMatch.
size_t Find(const uint8_t* Data, size_t Len, const Pattern& Pat, size_t Start = 0);

inline bool Contains(const uint8_t* Data, size_t Len, const Pattern& Pat)
{
	return Find(Data, Len, Pat) != kNoMatch;
}

}
