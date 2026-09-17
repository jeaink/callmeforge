#include "../include/forge/CLI.hpp"
#include "../include/forge/PEImage.hpp"
#include "../include/forge/PEParser.hpp"
#include "../include/forge/StringScanner.hpp"
#include "../include/forge/Analysis.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>

namespace forge {
namespace {

void usage() {
    std::cout
        << "Forge 0.1.0 - native game binary analysis toolkit\n\n"
        << "Usage:\n"
        << "  forge info <file>\n"
        << "  forge sections <file>\n"
        << "  forge imports <file>\n"
        << "  forge strings <file> [min-length]\n"
        << "  forge all <file>\n"
        << "  forge hexdump <file> <offset> <len>    # offset decimal or 0xhex\n"
        << "  forge peek-rva <file> <rva>          # show mapping and u32 at RVA\n"
        << "  forge peek-offset32 <file> <offset>  # read u32 at file offset\n"
        << "  forge metadata <file>                # run Phase 2 (binary metadata)\n"
        << "  forge analyze <file>                 # run Phase 3 (code analysis)\n"
        << "  forge relations <file>               # run Phase 4 (relationship analysis)\n"
        << "  forge typerecovery <file>            # run Phase 5 (type recovery)\n"
        << "  forge diff <file_v1> <file_v2>       # run Phase 6 (binary comparison)\n";
}

std::string hex(std::uint64_t value, int width = 0) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << std::setfill('0');
    if (width > 0) out << std::setw(width);
    out << value;
    return out.str();
}

bool parseNumber(const std::string& s, std::uint64_t& out) {
    std::istringstream in(s);
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        in >> std::hex >> out;
    } else {
        in >> out;
    }
    return !in.fail();
}

void hexdump(const PEImage& image, std::size_t offset, std::size_t len) {
    const auto& data = image.data();
    if (offset >= data.size()) {
        std::cerr << "offset out of range\n";
        return;
    }
    const std::size_t end = (data.size() < offset + len) ? data.size() : (offset + len);
    for (std::size_t i = offset; i < end; i += 16) {
        std::cout << std::setw(8) << std::setfill('0') << std::hex << i << std::dec << "  ";
        for (std::size_t j = 0; j < 16; ++j) {
            if (i + j < end) {
                std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)data[i + j] << ' ';
            } else {
                std::cout << "   ";
            }
        }
        std::cout << " ";
        for (std::size_t j = 0; j < 16 && i + j < end; ++j) {
            unsigned char c = data[i + j];
            std::cout << (c >= 0x20 && c <= 0x7E ? static_cast<char>(c) : '.');
        }
        std::cout << '\n';
    }
}

bool loadImage(const std::string& file, PEImage& image) {
    std::string error;
    if (!image.load(file, error)) {
        std::cerr << "forge: " << error << '\n';
        return false;
    }
    return true;
}

void printInfo(const PEImage& image) {
    const auto& info = image.info();
    std::cout << "File:       " << image.path() << '\n';
    std::cout << "Format:     PE\n";
    std::cout << "Arch:       " << architectureName(info.architecture) << '\n';
    std::cout << "Image base: " << hex(info.imageBase) << '\n';
    std::cout << "Entry RVA:  " << hex(info.entryPointRva, 8) << '\n';
    std::cout << "Image size: " << hex(info.imageSize, 8) << '\n';
    std::cout << "Sections:   " << image.sections().size() << '\n';
    std::cout << "Imports:    " << image.imports().size() << '\n';
}

void printSections(const PEImage& image) {
    std::cout << std::left
              << std::setw(12) << "NAME"
              << std::setw(12) << "RVA"
              << std::setw(12) << "V.SIZE"
              << std::setw(12) << "RAW"
              << std::setw(12) << "RAW SIZE"
              << "FLAGS\n";

    for (const auto& section : image.sections()) {
        std::cout << std::left
                  << std::setw(12) << section.name
                  << std::setw(12) << hex(section.virtualAddress, 8)
                  << std::setw(12) << hex(section.virtualSize, 8)
                  << std::setw(12) << hex(section.rawAddress, 8)
                  << std::setw(12) << hex(section.rawSize, 8)
                  << sectionCharacteristics(section.characteristics) << '\n';
    }
}

void printImports(const PEImage& image) {
    std::string currentModule;
    for (const auto& import : image.imports()) {
        if (import.module != currentModule) {
            currentModule = import.module;
            std::cout << '\n' << currentModule << '\n';
        }

        if (import.byOrdinal) {
            std::cout << "  #" << import.ordinal << '\n';
        } else {
            std::cout << "  " << import.name << '\n';
        }
    }
}

void printStrings(const PEImage& image, std::size_t minimumLength) {
    StringScanner scanner;
    const auto strings = scanner.scan(image.data(), minimumLength);

    for (const auto& hit : strings) {
        std::cout << hex(hit.offset, 8)
                  << " [" << hit.encoding << "] "
                  << hit.value << '\n';
    }

    std::cout << "\nTotal strings: " << strings.size() << '\n';
}

} // namespace

int runCLI(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        usage();
        return 1;
    }

    const auto& command = args[0];
    if (command == "help" || command == "--help" || command == "-h") {
        usage();
        return 0;
    }

    if (args.size() < 2) {
        usage();
        return 1;
    }

    const auto& file = args[1];
    std::ifstream test(file);
    if (!test) {
        std::cerr << "forge: file does not exist: " << file << '\n';
        return 1;
    }

    PEImage image;
    if (!loadImage(file, image)) return 1;

    if (command == "info") {
        printInfo(image);
    } else if (command == "sections") {
        printSections(image);
    } else if (command == "imports") {
        printImports(image);
    } else if (command == "strings") {
        std::size_t minimumLength = 5;
        if (args.size() >= 3) {
            try {
                minimumLength = std::stoull(args[2]);
            } catch (...) {
                std::cerr << "forge: invalid minimum string length\n";
                return 1;
            }
        }
        printStrings(image, minimumLength);
    } else if (command == "hexdump") {
        if (args.size() < 4) {
            std::cerr << "usage: forge hexdump <file> <offset> <len>\n";
            return 1;
        }
        std::uint64_t off = 0, len = 128;
        if (!parseNumber(args[2], off) || !parseNumber(args[3], len)) {
            std::cerr << "invalid offset/len\n";
            return 1;
        }
        hexdump(image, static_cast<std::size_t>(off), static_cast<std::size_t>(len));
    } else if (command == "peek-rva") {
        if (args.size() < 3) {
            std::cerr << "usage: forge peek-rva <file> <rva>\n";
            return 1;
        }
        std::uint64_t rva = 0;
        if (!parseNumber(args[2], rva)) {
            std::cerr << "invalid rva\n";
            return 1;
        }
        std::size_t offset = 0;
        if (!image.rvaToOffset(static_cast<std::uint32_t>(rva), offset)) {
            std::cerr << "rva does not map to file\n";
            return 1;
        }
        std::cout << "RVA " << hex(rva) << " -> offset " << hex(offset) << '\n';
        std::uint32_t value = 0;
        if (image.readUInt32AtOffset(offset, value)) {
            std::cout << "u32 at offset: " << hex(value, 8) << '\n';
        }
    } else if (command == "peek-offset32") {
        if (args.size() < 3) {
            std::cerr << "usage: forge peek-offset32 <file> <offset>\n";
            return 1;
        }
        std::uint64_t off = 0;
        if (!parseNumber(args[2], off)) {
            std::cerr << "invalid offset\n";
            return 1;
        }
        std::uint32_t value = 0;
        if (!image.readUInt32AtOffset(static_cast<std::size_t>(off), value)) {
            std::cerr << "offset out of range\n";
            return 1;
        }
        std::cout << "u32 at offset " << hex(off) << " = " << hex(value, 8) << '\n';
    } else if (command == "metadata") {
        std::string outMsg;
        if (!runBinaryMetadata(file, outMsg)) {
            std::cerr << "metadata analysis failed: " << outMsg << '\n';
            return 1;
        }
        std::cout << outMsg;
    } else if (command == "analyze") {
        std::vector<FunctionInfo> funcs;
        if (!runCodeAnalysis(file, funcs)) {
            std::cerr << "code analysis failed\n";
            return 1;
        }
        std::cout << "Discovered " << funcs.size() << " functions\n";
    } else if (command == "relations") {
        std::vector<StringReference> srefs;
        if (!runRelationshipAnalysis(file, srefs)) {
            std::cerr << "relationship analysis failed\n";
            return 1;
        }
        std::cout << "Found " << srefs.size() << " string references\n";
    } else if (command == "typerecovery") {
        std::vector<VTable> vts;
        if (!runTypeRecovery(file, vts)) {
            std::cerr << "type recovery failed\n";
            return 1;
        }
        std::cout << "Found " << vts.size() << " vtables\n";
    } else if (command == "diff") {
        if (args.size() < 3) {
            std::cerr << "usage: forge diff <file_v1> <file_v2>\n";
            return 1;
        }
        DiffSummary summary{};
        std::vector<LayoutChange> changes;
        if (!runBinaryComparison(args[1], args[2], summary, changes)) return 1;
        std::cout << "Functions changed: " << summary.functionsChanged << "\n";
        std::cout << "Functions added:   " << summary.functionsAdded << "\n";
        std::cout << "Functions removed: " << summary.functionsRemoved << "\n\n";
        std::cout << "Candidate layout changes:\n\n";
        for (const auto& c : changes) {
            std::cout << c.structureName << "::" << c.fieldName << "\n";
            std::cout << "    v1 -> " << c.v1Offset << "\n";
            std::cout << "    v2 -> " << c.v2Offset << "\n\n";
        }
    } else if (command == "all") {
        printInfo(image);
        std::cout << "\n== SECTIONS ==\n";
        printSections(image);
        std::cout << "\n== IMPORTS ==\n";
        printImports(image);
    } else {
        std::cerr << "forge: unknown command: " << command << "\n\n";
        usage();
        return 1;
    }

    return 0;
}

} // namespace forge
