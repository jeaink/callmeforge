#include "../include/forge/PEImage.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>

namespace forge {
    namespace internal {

        std::size_t boundedLength(const char* value, std::size_t maxLength) {
            std::size_t length = 0;
            while (length < maxLength && value[length] != '\0') {
                ++length;
            }
            return length;
        }

    } // namespace internal
} // namespace forge

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

        struct ExportDirectory {
            std::uint32_t characteristics;
            std::uint32_t timeDateStamp;
            std::uint16_t majorVersion;
            std::uint16_t minorVersion;
            std::uint32_t name;
            std::uint32_t ordinalBase;
            std::uint32_t numberOfFunctions;
            std::uint32_t numberOfNames;
            std::uint32_t addressOfFunctions;     // RVA
            std::uint32_t addressOfNames;         // RVA
            std::uint32_t addressOfNameOrdinals;  // RVA
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
        constexpr std::size_t EXPORT_DIRECTORY_INDEX = 0;
        constexpr std::size_t BASE_RELOCATION_INDEX = 5;

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

    bool PEImage::readUInt32AtOffset(std::size_t offset, std::uint32_t& out) const {
        if (!rangeValid(data_.size(), offset, sizeof(std::uint32_t))) return false;
        std::uint32_t value;
        std::memcpy(&value, data_.data() + offset, sizeof(value));
        out = value;
        return true;
    }

    bool PEImage::readBytes(std::size_t offset, std::size_t length, std::vector<std::uint8_t>& out) const {
        if (!rangeValid(data_.size(), offset, length)) return false;
        out.assign(data_.begin() + offset, data_.begin() + offset + length);
        return true;
    }

    bool PEImage::rvaToOffset(std::uint32_t rva, std::size_t& out) const {
        for (const auto& sec : sections_) {
            if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
                std::uint32_t offsetInSection = rva - sec.virtualAddress;
                if (offsetInSection < sec.rawSize) {
                    out = sec.rawAddress + offsetInSection;
                    return true;
                }
            }
        }
        return false;
    }

    bool PEImage::parseHeaders(std::string& error) {
        if (data_.size() < sizeof(DOSHeader)) {
            error = "file too small for DOS header";
            return false;
        }

        const auto* dos = reinterpret_cast<const DOSHeader*>(data_.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            error = "invalid DOS signature";
            return false;
        }

        std::size_t ntOffset = static_cast<std::size_t>(dos->e_lfanew);
        if (ntOffset + 4 > data_.size()) {
            error = "invalid NT header offset";
            return false;
        }

        std::uint32_t ntSig = *reinterpret_cast<const std::uint32_t*>(data_.data() + ntOffset);
        if (ntSig != IMAGE_NT_SIGNATURE) {
            error = "invalid NT signature";
            return false;
        }

        std::size_t fileHeaderOffset = ntOffset + 4;
        const auto* fileHeader = ptrAt<FileHeader>(fileHeaderOffset);
        if (!fileHeader) {
            error = "invalid file header";
            return false;
        }

        std::size_t optionalHeaderOffset = fileHeaderOffset + sizeof(FileHeader);

        if (fileHeader->machine == IMAGE_FILE_MACHINE_I386) {
            info_.architecture = Architecture::X86;
            const auto* opt = ptrAt<OptionalHeader32>(optionalHeaderOffset);
            if (!opt) {
                error = "invalid optional header";
                return false;
            }
            info_.entryPointRva = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(opt) + 16);
            info_.imageBase = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(opt) + 28);
            info_.imageSize = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(opt) + 56);
            info_.sectionAlignment = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(opt) + 32);
            info_.fileAlignment = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(opt) + 36);

            if (opt->numberOfRvaAndSizes > IMPORT_DIRECTORY_INDEX) {
                importDirectoryRva_ = opt->directories[IMPORT_DIRECTORY_INDEX].virtualAddress;
                importDirectorySize_ = opt->directories[IMPORT_DIRECTORY_INDEX].size;
            }
            if (opt->numberOfRvaAndSizes > EXPORT_DIRECTORY_INDEX) {
                exportDirectoryRva_ = opt->directories[EXPORT_DIRECTORY_INDEX].virtualAddress;
                exportDirectorySize_ = opt->directories[EXPORT_DIRECTORY_INDEX].size;
            }
            if (opt->numberOfRvaAndSizes > BASE_RELOCATION_INDEX) {
                relocationDirectoryRva_ = opt->directories[BASE_RELOCATION_INDEX].virtualAddress;
                relocationDirectorySize_ = opt->directories[BASE_RELOCATION_INDEX].size;
            }
        }
        else if (fileHeader->machine == IMAGE_FILE_MACHINE_AMD64 ||
            fileHeader->machine == IMAGE_FILE_MACHINE_ARM64) {
            info_.architecture = (fileHeader->machine == IMAGE_FILE_MACHINE_AMD64) ?
                Architecture::X64 : Architecture::ARM64;
            const auto* opt = ptrAt<OptionalHeader64>(optionalHeaderOffset);
            if (!opt) {
                error = "invalid optional header";
                return false;
            }
            info_.entryPointRva = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(opt) + 16);
            info_.imageBase = *reinterpret_cast<const std::uint64_t*>(
                reinterpret_cast<const std::uint8_t*>(opt) + 24);
            info_.imageSize = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(opt) + 56);
            info_.sectionAlignment = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(opt) + 32);
            info_.fileAlignment = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(opt) + 36);

            if (opt->numberOfRvaAndSizes > IMPORT_DIRECTORY_INDEX) {
                importDirectoryRva_ = opt->directories[IMPORT_DIRECTORY_INDEX].virtualAddress;
                importDirectorySize_ = opt->directories[IMPORT_DIRECTORY_INDEX].size;
            }
            if (opt->numberOfRvaAndSizes > EXPORT_DIRECTORY_INDEX) {
                exportDirectoryRva_ = opt->directories[EXPORT_DIRECTORY_INDEX].virtualAddress;
                exportDirectorySize_ = opt->directories[EXPORT_DIRECTORY_INDEX].size;
            }
            if (opt->numberOfRvaAndSizes > BASE_RELOCATION_INDEX) {
                relocationDirectoryRva_ = opt->directories[BASE_RELOCATION_INDEX].virtualAddress;
                relocationDirectorySize_ = opt->directories[BASE_RELOCATION_INDEX].size;
            }
        }
        else {
            error = "unsupported architecture";
            return false;
        }

        return true;
    }

    bool PEImage::parseSections(std::string& error) {
        std::size_t ntOffset = static_cast<std::size_t>(
            *reinterpret_cast<const std::int32_t*>(data_.data() + 60));
        std::size_t fileHeaderOffset = ntOffset + 4;
        const auto* fileHeader = ptrAt<FileHeader>(fileHeaderOffset);
        if (!fileHeader) {
            error = "invalid file header";
            return false;
        }

        std::size_t optionalHeaderSize = fileHeader->sizeOfOptionalHeader;
        std::size_t sectionTableOffset = fileHeaderOffset + sizeof(FileHeader) + optionalHeaderSize;

        for (std::uint16_t i = 0; i < fileHeader->numberOfSections; ++i) {
            std::size_t entryOffset = sectionTableOffset + i * sizeof(SectionHeader);
            const auto* secHeader = ptrAt<SectionHeader>(entryOffset);
            if (!secHeader) {
                error = "invalid section header";
                return false;
            }

            Section sec;
            sec.name = std::string(secHeader->name,
                std::min<std::size_t>(8, strnlen(secHeader->name, 8)));
            sec.virtualAddress = secHeader->virtualAddress;
            sec.virtualSize = secHeader->virtualSize;
            sec.rawAddress = secHeader->pointerToRawData;
            sec.rawSize = secHeader->sizeOfRawData;
            sec.characteristics = secHeader->characteristics;
            sections_.push_back(sec);
        }

        return true;
    }

    bool PEImage::parseImports(std::string& error) {
        if (importDirectoryRva_ == 0 || importDirectorySize_ == 0) return true;

        std::size_t importOffset = 0;
        if (!rvaToOffset(importDirectoryRva_, importOffset)) return true;

        std::size_t cursor = importOffset;
        while (cursor + sizeof(ImportDescriptor) <= data_.size()) {
            const auto* desc = reinterpret_cast<const ImportDescriptor*>(data_.data() + cursor);
            if (desc->name == 0) break;

            std::size_t nameOffset = 0;
            if (!rvaToOffset(desc->name, nameOffset)) {
                cursor += sizeof(ImportDescriptor);
                continue;
            }
            const char* namePtr = reinterpret_cast<const char*>(data_.data() + nameOffset);
            std::string moduleName(namePtr, strnlen(namePtr, 256));

            std::uint32_t iltRva = desc->originalFirstThunk != 0 ? desc->originalFirstThunk : desc->firstThunk;
            std::size_t iltOffset = 0;
            if (!rvaToOffset(iltRva, iltOffset)) {
                cursor += sizeof(ImportDescriptor);
                continue;
            }

            bool is64 = (info_.architecture == Architecture::X64);
            std::size_t entrySize = is64 ? 8 : 4;

            for (std::size_t i = 0; ; ++i) {
                std::size_t entryOffset = iltOffset + i * entrySize;
                if (entryOffset + entrySize > data_.size()) break;

                std::uint64_t entry = is64 ?
                    *reinterpret_cast<const std::uint64_t*>(data_.data() + entryOffset) :
                    *reinterpret_cast<const std::uint32_t*>(data_.data() + entryOffset);

                if (entry == 0) break;

                ImportSymbol sym;
                sym.module = moduleName;

                if (is64 && (entry & 0x8000000000000000ULL)) {
                    sym.byOrdinal = true;
                    sym.ordinal = static_cast<std::uint16_t>(entry & 0xFFFF);
                }
                else if (!is64 && (entry & 0x80000000U)) {
                    sym.byOrdinal = true;
                    sym.ordinal = static_cast<std::uint16_t>(entry & 0xFFFF);
                }
                else {
                    std::size_t hintNameOffset = 0;
                    if (!rvaToOffset(static_cast<std::uint32_t>(entry), hintNameOffset)) continue;
                    hintNameOffset += 2;
                    if (hintNameOffset >= data_.size()) continue;
                    const char* importNamePtr = reinterpret_cast<const char*>(data_.data() + hintNameOffset);
                    sym.name = std::string(importNamePtr, strnlen(importNamePtr, 512));
                    sym.byOrdinal = false;
                }

                imports_.push_back(sym);
            }

            cursor += sizeof(ImportDescriptor);
        }

        return true;
    }

    bool PEImage::parseExports(std::string& error) {
        if (exportDirectoryRva_ == 0 || exportDirectorySize_ == 0) return true;

        std::size_t exportOffset = 0;
        if (!rvaToOffset(exportDirectoryRva_, exportOffset)) return true;

        const auto* dir = ptrAt<ExportDirectory>(exportOffset);
        if (!dir) return true;

        const std::uint32_t numFuncs = dir->numberOfFunctions;
        const std::uint32_t numNames = dir->numberOfNames;
        const std::uint32_t funcTableRva = dir->addressOfFunctions;
        const std::uint32_t namesRva = dir->addressOfNames;
        const std::uint32_t ordinalsRva = dir->addressOfNameOrdinals;
        const std::uint32_t ordinalBase = dir->ordinalBase;

        std::size_t funcTableOffset = 0;
        if (!rvaToOffset(funcTableRva, funcTableOffset)) return true;

        std::size_t namesOffset = 0, ordinalsOffset = 0;
        if (numNames > 0) {
            if (!rvaToOffset(namesRva, namesOffset)) return true;
            if (!rvaToOffset(ordinalsRva, ordinalsOffset)) return true;
        }

        for (std::uint32_t i = 0; i < numFuncs; ++i) {
            std::size_t funcEntryOffset = funcTableOffset + i * sizeof(std::uint32_t);
            if (!rangeValid(data_.size(), funcEntryOffset, sizeof(std::uint32_t))) break;
            std::uint32_t rva = *reinterpret_cast<const std::uint32_t*>(data_.data() + funcEntryOffset);
            ExportSymbol sym;
            sym.ordinal = ordinalBase + i;
            sym.rva = rva;
            sym.name = "";
            exports_.push_back(sym);
        }

        for (std::uint32_t i = 0; i < numNames; ++i) {
            std::size_t namePtrOffset = namesOffset + i * sizeof(std::uint32_t);
            std::size_t ordOffset = ordinalsOffset + i * sizeof(std::uint16_t);
            if (!rangeValid(data_.size(), namePtrOffset, sizeof(std::uint32_t)) ||
                !rangeValid(data_.size(), ordOffset, sizeof(std::uint16_t))) break;
            std::uint32_t nameRva = *reinterpret_cast<const std::uint32_t*>(data_.data() + namePtrOffset);
            std::uint16_t nameOrdinal = *reinterpret_cast<const std::uint16_t*>(data_.data() + ordOffset);
            std::size_t nameOffset = 0;
            if (!rvaToOffset(nameRva, nameOffset)) continue;
            const char* namePtr = reinterpret_cast<const char*>(data_.data() + nameOffset);
            const auto remaining = data_.size() - nameOffset;
            const auto maxLen = std::min<std::size_t>(remaining, 4096);
            const auto len = internal::boundedLength(namePtr, maxLen);
            std::string name(namePtr, len);
            std::size_t exportIndex = static_cast<std::size_t>(nameOrdinal);
            if (exportIndex < exports_.size()) {
                exports_[exportIndex].name = name;
            }
        }

        return true;
    }

    bool PEImage::parseRelocations(std::string& error) {
        if (relocationDirectoryRva_ == 0 || relocationDirectorySize_ == 0) return true;

        std::size_t relocOffset = 0;
        if (!rvaToOffset(relocationDirectoryRva_, relocOffset)) return true;

        const std::size_t relocEnd = relocOffset + relocationDirectorySize_;
        std::size_t cursor = relocOffset;

        while (cursor + 8 <= relocEnd && cursor + 8 <= data_.size()) {
            const std::uint32_t pageRva = *reinterpret_cast<const std::uint32_t*>(data_.data() + cursor);
            const std::uint32_t blockSize = *reinterpret_cast<const std::uint32_t*>(data_.data() + cursor + 4);
            if (blockSize < 8) break;
            const std::size_t entriesStart = cursor + 8;
            const std::size_t entriesEnd = cursor + blockSize;
            if (entriesEnd > data_.size()) break;
            const std::size_t numEntries = (entriesEnd - entriesStart) / 2;
            for (std::size_t i = 0; i < numEntries; ++i) {
                const auto entryOffset = entriesStart + i * 2;
                const std::uint16_t entry = *reinterpret_cast<const std::uint16_t*>(data_.data() + entryOffset);
                const std::uint16_t type = entry >> 12;
                const std::uint16_t offset = entry & 0x0FFF;
                RelocationEntry r;
                r.rva = pageRva + offset;
                r.type = type;
                relocations_.push_back(r);
            }
            cursor += blockSize;
            if (blockSize == 0) break;
        }

        return true;
    }

    bool PEImage::load(const std::string& path, std::string& error) {
        path_ = path;
        data_.clear();
        sections_.clear();
        imports_.clear();
        exports_.clear();
        relocations_.clear();
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
        if (!parseHeaders(error)) return false;
        if (!parseSections(error)) return false;
        if (!parseImports(error)) return false;
        if (!parseExports(error)) return false;
        if (!parseRelocations(error)) return false;
        return true;
    }

} // namespace forge
