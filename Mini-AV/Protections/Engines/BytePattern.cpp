#include "BytePattern.h"

#include <cctype>

namespace {

int HexNibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

}

namespace BytePattern {

Pattern Compile(const std::string& Spec)
{
	Pattern pat;

	// Collapse to a sequence of non-space tokens of 2 chars each ("0F", "??").
	std::string compact;
	compact.reserve(Spec.size());
	for (char c : Spec) {
		if (!std::isspace(static_cast<unsigned char>(c))) {
			compact.push_back(c);
		}
	}

	// A single '?' is treated as a full-byte wildcard too; normalize to pairs.
	if (compact.size() % 2 != 0) {
		return pat; // invalid: odd nibble count
	}

	for (size_t i = 0; i < compact.size(); i += 2) {
		const char hi = compact[i];
		const char lo = compact[i + 1];

		if (hi == '?' || lo == '?') {
			pat.Bytes.push_back(0);
			pat.Mask.push_back(0x00);
			continue;
		}

		const int h = HexNibble(hi);
		const int l = HexNibble(lo);
		if (h < 0 || l < 0) {
			return Pattern{}; // invalid hex
		}
		pat.Bytes.push_back(static_cast<uint8_t>((h << 4) | l));
		pat.Mask.push_back(0xFF);
	}

	pat.Valid = !pat.Bytes.empty();
	return pat;
}

size_t Find(const uint8_t* Data, size_t Len, const Pattern& Pat, size_t Start)
{
	if (!Pat.Valid || Data == nullptr) {
		return kNoMatch;
	}
	const size_t m = Pat.Bytes.size();
	if (m == 0 || m > Len) {
		return kNoMatch;
	}

	const size_t last = Len - m;
	for (size_t i = Start; i <= last; ++i) {
		bool ok = true;
		for (size_t j = 0; j < m; ++j) {
			if (Pat.Mask[j] && Data[i + j] != Pat.Bytes[j]) {
				ok = false;
				break;
			}
		}
		if (ok) {
			return i;
		}
	}
	return kNoMatch;
}

}
