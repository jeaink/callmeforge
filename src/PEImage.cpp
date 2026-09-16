#include "../include/forge/PEImage.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>

namespace forge { namespace internal {

std::size_t boundedLength(const char* value, std::size_t maxLength) {
    std::size_t length = 0;
    while (length < maxLength && value[length] != '\0') {
        ++length;
    }
    return length;
}

} /* namespace internal */ }

namespace forge {
namespace {

#pragma pack(push, 1)
struct DOSHeader {
    std::uint16_t e_magic;
    std::uint8_t pad[58];
    std::int32_t e_lfanew;
};

struct FileHeader {
    std::uint16_t machine;
    std::uint16_t numberOfSections;
    std::uint32_t timeDateStamp;
    std::uint32_t pointerToSymbolTable;
    std::uint32_t numberOfSymbols;
    std::uint16_t sizeOfOptionalHeader;
    std::uint16_t characteristics;
};

struct DataDirectory {
    std::uint32_t virtualAddress;
    std::uint32_t size;
};

struct OptionalHeader32 {
    std::uint16_t magic;
    std::uint8_t rest[90];
    std::uint32_t numberOfRvaAndSizes;
    DataDirectory directories[16];
};

struct OptionalHeader64 {
    std::uint16_t magic;
    std::uint8_t rest[106];
    std::uint32_t numberOfRvaAndSizes;
    DataDirectory directories[16];
};

struct SectionHeader {
    char name[8];
    std::uint32_t virtualSize;
    std::uint32_t virtualAddress;
    std::uint32_t sizeOfRawData;
    std::uint32_t pointerToRawData;
    std::uint32_t pointerToRelocations;
    std::uint32_t pointerToLinenumbers;
    std::uint16_t numberOfRelocations;
    std::uint16_t numberOfLinenumbers;
    std::uint32_t characteristics;
};

struct ImportDescriptor {
    std::uint32_t originalFirstThunk;
    std::uint32_t timeDateStamp;
    std::uint32_t forwarderChain;
    std::uint32_t name;
    std::uint32_t firstThunk;
};
#pragma pack(pop)

constexpr std::uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;
constexpr std::uint32_t IMAGE_NT_SIGNATURE = 0x00004550;
constexpr std::uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B;
constexpr std::uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;
constexpr std::uint16_t IMAGE_FILE_MACHINE_I386 = 0x014C;
constexpr std::uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;
constexpr std::uint16_t IMAGE_FILE_MACHINE_ARM64 = 0xAA64;
constexpr std::size_t IMPORT_DIRECTORY_INDEX = 1;

bool rangeValid(std::size_t size, std::size_t offset, std::size_t length) {
    return offset <= size && length <= size - offset;
}

} // namespace

template <typename T>
const T* PEImage::ptrAt(std::size_t offset) const {
    if (!rangeValid(data_.size(), offset, sizeof(T))) {
        return nullptr;
    }
    return reinterpret_cast<const T*>(data_.data() + offset);
}

bool PEImage::load(const std::string& path, std::string& error) {
    path_ = path;
    data_.clear();
    sections_.clear();
    imports_.clear();
    info_ = {};

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        error = "failed to open file: " + path;
        return false;
    }

    const auto end = file.tellg();
    if (end < 0) {
        error = "failed to determine file size";
        return false;
    }

    const auto size = static_cast<std::uint64_t>(end);
    if (size > std::numeric_limits<std::size_t>::max()) {
        error = "file is too large for this process";
        return false;
    }

    data_.resize(static_cast<std::size_t>(size));
    file.seekg(0);
    if (!data_.empty()) {
        file.read(reinterpret_cast<char*>(data_.data()), static_cast<std::streamsize>(data_.size()));
        if (!file) {
            error = "failed to read file";
            return false;
        }
    }

    return parse(error);
}

bool PEImage::parse(std::string& error) {
    return parseHeaders(error) && parseSections(error) && parseImports(error);
}

bool PEImage::parseHeaders(std::string& error) {
    const auto* dos = ptrAt<DOSHeader>(0);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        error = "not a valid MZ executable";
        return false;
    }

    if (dos->e_lfanew < 0) {
        error = "invalid PE header offset";
        return false;
    }

    const auto ntOffset = static_cast<std::size_t>(dos->e_lfanew);
    if (!rangeValid(data_.size(), ntOffset, sizeof(std::uint32_t) + sizeof(FileHeader) + sizeof(std::uint16_t))) {
        error = "truncated PE header";
        return false;
    }

    const auto* signature = ptrAt<std::uint32_t>(ntOffset);
    if (!signature || *signature != IMAGE_NT_SIGNATURE) {
        error = "missing PE signature";
        return false;
    }

    const auto* fileHeader = ptrAt<FileHeader>(ntOffset + sizeof(std::uint32_t));
    if (!fileHeader) {
        error = "truncated COFF header";
        return false;
    }

    const auto optionalOffset = ntOffset + sizeof(std::uint32_t) + sizeof(FileHeader);
    if (!rangeValid(data_.size(), optionalOffset, fileHeader->sizeOfOptionalHeader)) {
        error = "truncated optional header";
        return false;
    }

    const auto* magic = ptrAt<std::uint16_t>(optionalOffset);
    if (!magic) {
        error = "missing optional header magic";
        return false;
    }

    if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (fileHeader->machine != IMAGE_FILE_MACHINE_AMD64) {
            error = "PE32+ optional header with unexpected machine type";
            return false;
        }

        const auto* optional = ptrAt<OptionalHeader64>(optionalOffset);
        if (!optional || fileHeader->sizeOfOptionalHeader < sizeof(OptionalHeader64)) {
            error = "truncated PE32+ optional header";
            return false;
        }

        info_.architecture = Architecture::X64;
        info_.entryPointRva = *reinterpret_cast<const std::uint32_t*>(optional->rest + 14);
        info_.imageBase = *reinterpret_cast<const std::uint64_t*>(optional->rest + 22);
        info_.imageSize = *reinterpret_cast<const std::uint32_t*>(optional->rest + 54);
        info_.sectionAlignment = *reinterpret_cast<const std::uint32_t*>(optional->rest + 30);
        info_.fileAlignment = *reinterpret_cast<const std::uint32_t*>(optional->rest + 34);
        importDirectoryRva_ = optional->directories[IMPORT_DIRECTORY_INDEX].virtualAddress;
        importDirectorySize_ = optional->directories[IMPORT_DIRECTORY_INDEX].size;
    } else if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (fileHeader->machine != IMAGE_FILE_MACHINE_I386) {
            error = "PE32 optional header with unexpected machine type";
            return false;
        }

        const auto* optional = ptrAt<OptionalHeader32>(optionalOffset);
        if (!optional || fileHeader->sizeOfOptionalHeader < sizeof(OptionalHeader32)) {
            error = "truncated PE32 optional header";
            return false;
        }

        info_.architecture = Architecture::X86;
        info_.entryPointRva = *reinterpret_cast<const std::uint32_t*>(optional->rest + 14);
        info_.imageBase = *reinterpret_cast<const std::uint32_t*>(optional->rest + 22);
        info_.imageSize = *reinterpret_cast<const std::uint32_t*>(optional->rest + 54);
        info_.sectionAlignment = *reinterpret_cast<const std::uint32_t*>(optional->rest + 30);
        info_.fileAlignment = *reinterpret_cast<const std::uint32_t*>(optional->rest + 34);
        importDirectoryRva_ = optional->directories[IMPORT_DIRECTORY_INDEX].virtualAddress;
        importDirectorySize_ = optional->directories[IMPORT_DIRECTORY_INDEX].size;
    } else {
        error = "unsupported PE optional-header format";
        return false;
    }

    if (fileHeader->machine == IMAGE_FILE_MACHINE_ARM64) {
        error = "ARM64 PE parsing is not implemented in this MVP";
        return false;
    }

    const auto sectionOffset = optionalOffset + fileHeader->sizeOfOptionalHeader;
    const auto sectionBytes = static_cast<std::size_t>(fileHeader->numberOfSections) * sizeof(SectionHeader);
    if (!rangeValid(data_.size(), sectionOffset, sectionBytes)) {
        error = "truncated section table";
        return false;
    }

    return true;
}

bool PEImage::parseSections(std::string& error) {
    const auto* dos = ptrAt<DOSHeader>(0);
    const auto ntOffset = static_cast<std::size_t>(dos->e_lfanew);
    const auto* fileHeader = ptrAt<FileHeader>(ntOffset + sizeof(std::uint32_t));
    const auto optionalOffset = ntOffset + sizeof(std::uint32_t) + sizeof(FileHeader);
    const auto sectionOffset = optionalOffset + fileHeader->sizeOfOptionalHeader;

    for (std::uint16_t i = 0; i < fileHeader->numberOfSections; ++i) {
        const auto offset = sectionOffset + static_cast<std::size_t>(i) * sizeof(SectionHeader);
        const auto* raw = ptrAt<SectionHeader>(offset);
        if (!raw) {
            error = "invalid section header";
            return false;
        }

        Section section;
        section.name.assign(raw->name, raw->name + forge::internal::boundedLength(raw->name, sizeof(raw->name)));
        section.virtualAddress = raw->virtualAddress;
        section.virtualSize = raw->virtualSize;
        section.rawAddress = raw->pointerToRawData;
        section.rawSize = raw->sizeOfRawData;
        section.characteristics = raw->characteristics;
        sections_.push_back(std::move(section));
    }

    return true;
}

bool PEImage::rvaToOffset(std::uint32_t rva, std::size_t& out) const {
    for (const auto& section : sections_) {
        const std::uint64_t start = section.virtualAddress;
        const std::uint64_t span = std::max<std::uint32_t>(section.virtualSize, section.rawSize);
        const std::uint64_t end = start + span;

        if (rva >= start && static_cast<std::uint64_t>(rva) < end) {
            const auto delta = static_cast<std::uint32_t>(rva - section.virtualAddress);
            if (delta >= section.rawSize) {
                return false;
            }
            const auto offset = static_cast<std::size_t>(section.rawAddress) + delta;
            if (offset < data_.size()) {
                out = offset;
                return true;
            }
        }
    }

    return false;
}

bool PEImage::parseImports(std::string& error) {
    if (importDirectoryRva_ == 0 || importDirectorySize_ == 0) {
        return true;
    }

    std::size_t importOffsetValue = 0;
    if (!rvaToOffset(importDirectoryRva_, importOffsetValue)) {
        error = "import directory RVA does not map into file";
        return false;
    }
    const auto importOffset = importOffsetValue;

    for (std::size_t index = 0;; ++index) {
        const auto descriptorOffset = importOffset + index * sizeof(ImportDescriptor);
        const auto* descriptor = ptrAt<ImportDescriptor>(descriptorOffset);
        if (!descriptor) {
            error = "truncated import descriptor";
            return false;
        }

        if (descriptor->originalFirstThunk == 0 && descriptor->name == 0 && descriptor->firstThunk == 0) {
            break;
        }

        std::size_t nameOffsetValue = 0;
        if (!rvaToOffset(descriptor->name, nameOffsetValue) || nameOffsetValue >= data_.size()) {
            continue;
        }
        const auto nameOffset = nameOffsetValue;

        const char* moduleName = reinterpret_cast<const char*>(data_.data() + nameOffset);
        const auto remaining = data_.size() - nameOffset;
        const auto maxLen = std::min<std::size_t>(remaining, 4096);
        const auto length = forge::internal::boundedLength(moduleName, maxLen);
        const std::string module(moduleName, length);

        const std::uint32_t thunkRva = descriptor->originalFirstThunk != 0
            ? descriptor->originalFirstThunk
            : descriptor->firstThunk;

        std::size_t thunkOffsetValue = 0;
        if (!rvaToOffset(thunkRva, thunkOffsetValue)) {
            continue;
        }
        const auto thunkOffset = thunkOffsetValue;

        const std::size_t thunkWidth = info_.architecture == Architecture::X64 ? 8 : 4;
        for (std::size_t thunkIndex = 0;; ++thunkIndex) {
            const auto entryOffset = thunkOffset + thunkIndex * thunkWidth;
            if (!rangeValid(data_.size(), entryOffset, thunkWidth)) {
                break;
            }

            std::uint64_t value = 0;
            if (thunkWidth == 8) {
                std::memcpy(&value, data_.data() + entryOffset, sizeof(value));
            } else {
                std::uint32_t v32 = 0;
                std::memcpy(&v32, data_.data() + entryOffset, sizeof(v32));
                value = v32;
            }

            if (value == 0) {
                break;
            }

            const std::uint64_t ordinalFlag = info_.architecture == Architecture::X64
                ? 0x8000000000000000ull
                : 0x80000000ull;

            if ((value & ordinalFlag) != 0) {
                ImportSymbol symbol;
                symbol.module = module;
                symbol.ordinal = static_cast<std::uint16_t>(value & 0xFFFFu);
                symbol.byOrdinal = true;
                imports_.push_back(std::move(symbol));
                continue;
            }

            std::size_t hintNameOffsetValue = 0;
            if (!rvaToOffset(static_cast<std::uint32_t>(value), hintNameOffsetValue) || !rangeValid(data_.size(), hintNameOffsetValue, 2)) {
                continue;
            }
            const auto hintNameOffset = hintNameOffsetValue;

            const auto functionOffset = hintNameOffset + 2;
            if (functionOffset >= data_.size()) {
                continue;
            }

            const char* functionName = reinterpret_cast<const char*>(data_.data() + functionOffset);
            const auto remainingName = data_.size() - functionOffset;
            const auto maxNameLength = std::min<std::size_t>(remainingName, 4096);
            const auto functionLength = forge::internal::boundedLength(functionName, maxNameLength);

            ImportSymbol symbol;
            symbol.module = module;
            symbol.name.assign(functionName, functionLength);
            imports_.push_back(std::move(symbol));
        }
    }

    return true;
}

} // namespace forge
