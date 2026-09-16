#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace forge {

enum class Architecture {
    Unknown,
    X86,
    X64,
    ARM64
};

struct Section {
    std::string name;
    std::uint32_t virtualAddress{};
    std::uint32_t virtualSize{};
    std::uint32_t rawAddress{};
    std::uint32_t rawSize{};
    std::uint32_t characteristics{};
};

struct ImportSymbol {
    std::string module;
    std::string name;
    std::uint16_t ordinal{};
    bool byOrdinal{false};
};

struct PEInfo {
    Architecture architecture{Architecture::Unknown};
    std::uint32_t entryPointRva{};
    std::uint64_t imageBase{};
    std::uint32_t imageSize{};
    std::uint32_t sectionAlignment{};
    std::uint32_t fileAlignment{};
};

class PEImage {
public:
    // Load from path string. Error message returned in 'error' on failure.
    bool load(const std::string& path, std::string& error);

    const std::string& path() const noexcept { return path_; }
    const std::vector<std::uint8_t>& data() const noexcept { return data_; }
    const PEInfo& info() const noexcept { return info_; }
    const std::vector<Section>& sections() const noexcept { return sections_; }
    const std::vector<ImportSymbol>& imports() const noexcept { return imports_; }

    // Map an RVA to a file offset. Returns true and sets 'out' on success.
    bool rvaToOffset(std::uint32_t rva, std::size_t& out) const;

private:
    bool parse(std::string& error);
    bool parseHeaders(std::string& error);
    bool parseSections(std::string& error);
    bool parseImports(std::string& error);

    template <typename T>
    const T* ptrAt(std::size_t offset) const;

    std::string path_;
    std::vector<std::uint8_t> data_;
    PEInfo info_{};
    std::vector<Section> sections_;
    std::vector<ImportSymbol> imports_;

    std::uint32_t importDirectoryRva_{0};
    std::uint32_t importDirectorySize_{0};
};

} // namespace forge
