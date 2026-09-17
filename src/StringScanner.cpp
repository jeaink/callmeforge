#include "../include/forge/StringScanner.hpp"

#include <cctype>
#include <unordered_set>

namespace forge {

static bool isPrintableAscii(unsigned char c) {
    return c >= 0x20 && c <= 0x7E;
}

static bool looksLikeUtf8(const std::vector<std::uint8_t>& data, std::size_t start, std::size_t length) {
    // Simple UTF-8 validation for the segment
    std::size_t i = start;
    const std::size_t end = start + length;
    while (i < end) {
        unsigned char c = data[i];
        if (c < 0x80) { // ASCII
            ++i;
            continue;
        } else if ((c & 0xE0) == 0xC0) { // 2-byte
            if (i + 1 >= end) return false;
            unsigned char c1 = data[i+1];
            if ((c1 & 0xC0) != 0x80) return false;
            i += 2;
        } else if ((c & 0xF0) == 0xE0) { // 3-byte
            if (i + 2 >= end) return false;
            unsigned char c1 = data[i+1], c2 = data[i+2];
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80) return false;
            i += 3;
        } else if ((c & 0xF8) == 0xF0) { // 4-byte
            if (i + 3 >= end) return false;
            unsigned char c1 = data[i+1], c2 = data[i+2], c3 = data[i+3];
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

std::vector<StringHit> StringScanner::scan(
    const std::vector<std::uint8_t>& data,
    std::size_t minimumLength,
    bool detectUtf8,
    bool detectUtf16le,
    bool detectUtf16be,
    bool unique
) const {
    std::vector<StringHit> result;
    if (minimumLength == 0) minimumLength = 1;

    std::unordered_set<std::string> seen;

    // ASCII run detection
    for (std::size_t i = 0; i < data.size();) {
        const auto start = i;
        while (i < data.size() && isPrintableAscii(data[i])) ++i;
        const auto len = i - start;
        if (len >= minimumLength) {
            std::string s(reinterpret_cast<const char*>(data.data() + start), len);
            if (!unique || seen.insert(s).second) {
                result.push_back({start, s, false, "ASCII"});
            }
        }
        if (i == start) ++i;
    }

    // UTF-16LE detection (ASCII-range low bytes with zero high bytes)
    if (detectUtf16le) {
        for (std::size_t i = 0; i + 1 < data.size();) {
            const auto start = i;
            std::string value;
            while (i + 1 < data.size()) {
                unsigned char lo = data[i];
                unsigned char hi = data[i+1];
                if (hi != 0 || !isPrintableAscii(lo)) break;
                value.push_back(static_cast<char>(lo));
                i += 2;
            }
            if (value.size() >= minimumLength) {
                if (!unique || seen.insert(value).second) {
                    result.push_back({start, value, true, "UTF-16LE"});
                }
            }
            if (i == start) i += 2;
        }
    }

    // UTF-16BE detection
    if (detectUtf16be) {
        for (std::size_t i = 0; i + 1 < data.size();) {
            const auto start = i;
            std::string value;
            while (i + 1 < data.size()) {
                unsigned char hi = data[i];
                unsigned char lo = data[i+1];
                if (hi != 0 || !isPrintableAscii(lo)) break;
                value.push_back(static_cast<char>(lo));
                i += 2;
            }
            if (value.size() >= minimumLength) {
                if (!unique || seen.insert(value).second) {
                    result.push_back({start, value, true, "UTF-16BE"});
                }
            }
            if (i == start) i += 2;
        }
    }

    // UTF-8 detection (best-effort)
    if (detectUtf8) {
        for (std::size_t i = 0; i < data.size();) {
            const auto start = i;
            // find a candidate window up to a length where bytes aren't control chars
            std::size_t j = i;
            while (j < data.size()) {
                unsigned char c = data[j];
                // treat printable ascii or multi-byte leading bytes as valid
                if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') break;
                ++j;
            }
            const auto len = j - start;
            if (len >= minimumLength && looksLikeUtf8(data, start, len)) {
                std::string s(reinterpret_cast<const char*>(data.data() + start), len);
                if (!unique || seen.insert(s).second) {
                    result.push_back({start, s, true, "UTF-8"});
                }
            }
            if (j == start) ++i; else i = j;
        }
    }

    // Optionally sort by offset
    std::sort(result.begin(), result.end(), [](const StringHit& a, const StringHit& b) { return a.offset < b.offset; });
    return result;
}

} // namespace forge
