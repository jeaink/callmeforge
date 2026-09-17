#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace forge {

struct StringHit {
    std::size_t offset{};
    std::string value;
    bool unicode{false}; // true for UTF-16/UTF-8 non-ASCII hits
    std::string encoding; // e.g. "ASCII", "UTF-8", "UTF-16LE", "UTF-16BE"
};

class StringScanner {
public:
    // Scan data for strings.
    // minimumLength: minimum number of characters (codepoints) to report
    // detectUtf8: detect UTF-8 encoded strings
    // detectUtf16le: detect UTF-16LE encoded ASCII-range strings
    // detectUtf16be: detect UTF-16BE encoded ASCII-range strings
    // unique: if true, remove duplicate string values
    std::vector<StringHit> scan(
        const std::vector<std::uint8_t>& data,
        std::size_t minimumLength = 5,
        bool detectUtf8 = true,
        bool detectUtf16le = true,
        bool detectUtf16be = false,
        bool unique = false
    ) const;
};

} // namespace forge
