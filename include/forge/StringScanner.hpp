#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace forge {

struct StringHit {
    std::size_t offset{};
    std::string value;
    bool unicode{false};
};

class StringScanner {
public:
    [[nodiscard]] std::vector<StringHit> scan(
        const std::vector<std::uint8_t>& data,
        std::size_t minimumLength = 5
    ) const;
};

} // namespace forge
