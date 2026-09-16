#include "../include/forge/PEParser.hpp"

namespace forge {

std::string architectureName(Architecture architecture) {
    switch (architecture) {
        case Architecture::X86: return "x86";
        case Architecture::X64: return "x64";
        case Architecture::ARM64: return "ARM64";
        default: return "unknown";
    }
}

std::string sectionCharacteristics(std::uint32_t characteristics) {
    std::string result;
    auto add = [&](char c) {
        if (!result.empty()) result += '-';
        result += c;
    };

    if (characteristics & 0x40000000u) add('R');
    if (characteristics & 0x80000000u) add('W');
    if (characteristics & 0x20000000u) add('X');
    if (characteristics & 0x02000000u) add('C');
    if (characteristics & 0x00000020u) add('C');
    if (characteristics & 0x00000040u) add('D');

    return result.empty() ? "-" : result;
}

} // namespace forge
