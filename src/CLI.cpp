#include "../include/forge/CLI.hpp"
#include "../include/forge/PEImage.hpp"
#include "../include/forge/PEParser.hpp"
#include "../include/forge/StringScanner.hpp"

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
        << "  forge all <file>\n";
}

std::string hex(std::uint64_t value, int width = 0) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << std::setfill('0');
    if (width > 0) out << std::setw(width);
    out << value;
    return out.str();
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
                  << (hit.unicode ? " [UTF16] " : " [ASCII] ")
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
