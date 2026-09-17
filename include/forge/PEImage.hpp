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

struct ExportSymbol {
    std::string name;     // may be empty for unnamed exports
    std::uint32_t ordinal; // actual export ordinal
    std::uint32_t rva;     // address RVA of the export
};

struct RelocationEntry {
    std::uint32_t rva; // rva of relocated address
    std::uint16_t type; // relocation type (IMAGE_REL_BASED_*)
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

    // Phase 2 additions
    const std::vector<ExportSymbol>& exports() const noexcept { return exports_; }
    const std::vector<RelocationEntry>& relocations() const noexcept { return relocations_; }

    // Map an RVA to a file offset. Returns true and sets 'out' on success.
    bool rvaToOffset(std::uint32_t rva, std::size_t& out) const;

    // Low-level access helpers
    // Read a 32-bit little-endian value from file offset. Returns false if out of range.
    bool readUInt32AtOffset(std::size_t offset, std::uint32_t& out) const;
    // Read bytes at file offset into "out". Returns false if out of range.
    bool readBytes(std::size_t offset, std::size_t length, std::vector<std::uint8_t>& out) const;

private:
    bool parse(std::string& error);
    bool parseHeaders(std::string& error);
    bool parseSections(std::string& error);
    bool parseImports(std::string& error);
    bool parseExports(std::string& error);
    bool parseRelocations(std::string& error);

    template <typename T>
    const T* ptrAt(std::size_t offset) const;

    std::string path_;
    std::vector<std::uint8_t> data_;
    PEInfo info_{};
    std::vector<Section> sections_;
    std::vector<ImportSymbol> imports_;
    std::vector<ExportSymbol> exports_;
    std::vector<RelocationEntry> relocations_;

    std::uint32_t importDirectoryRva_{0};
    std::uint32_t importDirectorySize_{0};
    std::uint32_t exportDirectoryRva_{0};
    std::uint32_t exportDirectorySize_{0};
    std::uint32_t relocationDirectoryRva_{0};
    std::uint32_t relocationDirectorySize_{0};
};

} // namespace forge
