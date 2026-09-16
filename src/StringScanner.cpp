#include "../include/forge/StringScanner.hpp"

#include <cctype>

namespace forge {

std::vector<StringHit> StringScanner::scan(
    const std::vector<std::uint8_t>& data,
    std::size_t minimumLength
) const {
    std::vector<StringHit> result;
    if (minimumLength == 0) minimumLength = 1;

    // ASCII
    for (std::size_t i = 0; i < data.size();) {
        const auto start = i;
        while (i < data.size()) {
            const auto c = data[i];
            const bool printable = c >= 0x20 && c <= 0x7E;
            if (!printable) break;
            ++i;
        }

        if (i - start >= minimumLength) {
            result.push_back({start, std::string(reinterpret_cast<const char*>(data.data() + start), i - start), false});
        }

        if (i == start) ++i;
    }

    // UTF-16LE-ish ASCII strings.
    for (std::size_t i = 0; i + 1 < data.size();) {
        const auto start = i;
        std::string value;

        while (i + 1 < data.size()) {
            const auto c = data[i];
            const auto high = data[i + 1];
            if (high != 0 || c < 0x20 || c > 0x7E) break;
            value.push_back(static_cast<char>(c));
            i += 2;
        }

        if (value.size() >= minimumLength) {
            result.push_back({start, std::move(value), true});
        }

        if (i == start) i += 2;
    }

    return result;
}

} // namespace forge
