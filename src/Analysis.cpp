#include "../include/forge/Analysis.hpp"
#include "../include/forge/PEImage.hpp"
#include "../include/forge/PEParser.hpp"
#include "../include/forge/StringScanner.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace forge {

// Enhanced internal decoder and CFG builder

struct DecodedInstr {
    std::size_t offset; // file offset within image data
    std::size_t size;   // instruction length
    bool isCall{false};
    bool isRet{false};
    bool isJump{false};
    bool isConditional{false};
    std::int64_t imm{0};   // immediate (for relative targets)
};

class SimpleDisassembler {
public:
    SimpleDisassembler(const std::vector<uint8_t>& data): data_(data) {}

    DecodedInstr decode(std::size_t off, bool is64) const {
        DecodedInstr out{off,0,false,false,false,false,0};
        if (off >= data_.size()) return out;
        const uint8_t* p = data_.data() + off;
        std::size_t remaining = data_.size() - off;

        std::size_t idx = 0;
        // skip prefixes
        bool prefix = true;
        while (prefix && idx < remaining) {
            uint8_t b = p[idx];
            switch (b) {
                case 0xF0: case 0xF2: case 0xF3:
                case 0x2E: case 0x36: case 0x3E: case 0x26: case 0x64: case 0x65:
                case 0x66: case 0x67:
                    ++idx; break;
                default: prefix = false; break;
            }
        }
        // REX
        if (is64 && idx < remaining) {
            uint8_t b = p[idx];
            if ((b & 0xF0) == 0x40) { ++idx; }
        }
        if (idx >= remaining) return out;
        uint8_t opcode = p[idx++];
        if (opcode == 0x0F) {
            if (idx >= remaining) return out;
            uint8_t op2 = p[idx++];
            if (op2 >= 0x80 && op2 <= 0x8F) {
                if (idx + 4 > remaining) return out;
                int32_t rel=0; std::memcpy(&rel, p+idx, 4);
                out.isJump=true; out.isConditional=true; out.imm=rel; out.size = (idx+4);
                return out;
            }
            out.size = idx; return out;
        }
        // simple opcodes
        switch (opcode) {
            case 0xE8: if (idx + 4 <= remaining) { int32_t rel=0; std::memcpy(&rel, p+idx, 4); out.isCall=true; out.imm=rel; out.size=idx+4; } return out;
            case 0xE9: if (idx + 4 <= remaining) { int32_t rel=0; std::memcpy(&rel, p+idx,4); out.isJump=true; out.imm=rel; out.size=idx+4; } return out;
            case 0xEB: if (idx +1 <= remaining) { int8_t rel=0; std::memcpy(&rel,p+idx,1); out.isJump=true; out.imm=rel; out.size=idx+1; } return out;
            case 0xC3: out.isRet=true; out.size=idx; return out;
            case 0xC2: if (idx+2<=remaining) { out.isRet=true; out.size=idx+2; } return out;
            default: break;
        }
        if (opcode >= 0x70 && opcode <= 0x7F) { if (idx+1<=remaining) { int8_t rel=0; std::memcpy(&rel,p+idx,1); out.isJump=true; out.isConditional=true; out.imm=rel; out.size=idx+1; } return out; }
        if (opcode == 0xFF) {
            // group: check ModR/M to detect CALL/JMP via FF /2 /3 etc. We'll mark as call/jump conservatively.
            if (idx >= remaining) return out;
            uint8_t modrm = p[idx++];
            uint8_t mod = (modrm & 0xC0) >> 6;
            uint8_t rm = modrm & 0x7;
            // if opcode is FF and reg bits 2(call) or 3(call) indicate call/jump
            uint8_t reg = (modrm & 0x38) >> 3;
            if (reg == 2 || reg == 3) out.isCall = true;
            out.size = idx; return out;
        }
        // crude ModR/M handling for many opcodes
        if (idx < remaining) {
            uint8_t modrm = p[idx];
            // not attempting full decode; assume 1 byte length
            out.size = idx;
            return out;
        }
        out.size = idx; return out;
    }
private:
    const std::vector<uint8_t>& data_;
};

struct BasicBlock {
    std::size_t startOffset;
    std::size_t endOffset; // exclusive
    std::vector<std::size_t> successors; // offsets
};

// Simple FNV-1a 64-bit hash over a byte range. Used to fingerprint function bytes
// so identical code can be recognized across analysis passes / binaries.
static std::uint64_t simpleHash(const std::vector<std::uint8_t>& data,
                                std::size_t offset,
                                std::size_t length) {
    const std::uint64_t kOffsetBasis = 0xCBF29CE484222325ULL;
    const std::uint64_t kPrime = 0x100000001B3ULL;

    std::uint64_t hash = kOffsetBasis;
    if (offset >= data.size()) return hash;

    const std::size_t end = (offset + length > data.size()) ? data.size() : offset + length;
    for (std::size_t i = offset; i < end; ++i) {
        hash ^= static_cast<std::uint64_t>(data[i]);
        hash *= kPrime;
    }
    return hash;
}

bool runCodeAnalysis(const std::string& path, std::vector<FunctionInfo>& outFunctions) {
    std::string error;
    PEImage img;
    if (!img.load(path, error)) return false;

    const auto& data = img.data();
    SimpleDisassembler disasm(data);

    // Map from function entry (file offset) -> FunctionInfo
    std::unordered_map<std::size_t, FunctionInfo> functionsMap;

    for (const auto& sec : img.sections()) {
        if ((sec.characteristics & 0x20000000u) == 0) continue; // not executable
        std::size_t start = sec.rawAddress;
        std::size_t size = sec.rawSize;
        if (start >= data.size()) continue;
        size = (data.size() < start + size) ? (data.size() - start) : size;
        const bool is64 = (img.info().architecture == Architecture::X64);

        // find candidates
        std::unordered_map<std::size_t, bool> entryCandidates;
        for (std::size_t i = start; i + 4 < start + size; ++i) {
            if (is64) {
                if (data[i]==0x55 && data[i+1]==0x48 && data[i+2]==0x89 && data[i+3]==0xE5) entryCandidates[i]=true;
            } else {
                if (data[i]==0x55 && data[i+1]==0x8B && data[i+2]==0xEC) entryCandidates[i]=true;
            }
        }
        for (const auto& e : img.exports()) {
            std::size_t off=0; if (img.rvaToOffset(e.rva, off)) { if (off>=start && off<start+size) entryCandidates[off]=true; }
        }

        // For each candidate, build basic blocks and CFG by exploring
        for (const auto& kv : entryCandidates) {
            std::size_t entryOff = kv.first;
            std::unordered_map<std::size_t, BasicBlock> blocks;
            std::queue<std::size_t> work;
            std::unordered_map<std::size_t,bool> visited;
            work.push(entryOff);
            visited[entryOff]=true;
            while (!work.empty()) {
                std::size_t cur = work.front(); work.pop();
                std::size_t cursor = cur;
                BasicBlock bb; bb.startOffset = cur; bb.endOffset = cur;
                while (cursor < start + size) {
                    DecodedInstr di = disasm.decode(cursor, is64);
                    if (di.size == 0) break;
                    cursor += di.size;
                    if (di.isRet) {
                        bb.endOffset = cursor; blocks[bb.startOffset] = bb; break;
                    }
                    if (di.isCall) {
                        // calls do not change fallthrough
                        continue;
                    }
                    if (di.isJump) {
                        // compute target
                        std::int64_t nextRva = static_cast<std::int64_t>(sec.virtualAddress + static_cast<std::uint32_t>(cursor - sec.rawAddress));
                        std::int64_t targetRva = nextRva + di.imm;
                        std::size_t targetOff = 0;
                        if (targetRva >= 0 && img.rvaToOffset(static_cast<std::uint32_t>(targetRva), targetOff)) {
                            bb.endOffset = cursor;
                            bb.successors.push_back(targetOff);
                            if (!visited[targetOff]) { work.push(targetOff); visited[targetOff]=true; }
                            // if conditional, also add fall-through
                            if (di.isConditional) {
                                std::size_t fall = cursor;
                                bb.successors.push_back(fall);
                                if (!visited[fall]) { work.push(fall); visited[fall]=true; }
                            }
                            blocks[bb.startOffset] = bb;
                            break;
                        } else {
                            bb.endOffset = cursor; blocks[bb.startOffset] = bb; break;
                        }
                    }
                    // otherwise continue
                }
                if (blocks.find(bb.startOffset)==blocks.end() && bb.endOffset==bb.startOffset) {
                    // no instructions decoded
                }
            }

            // compute function size as span of blocks
            std::size_t minOff = SIZE_MAX, maxOff = 0;
            for (const auto& bkv : blocks) {
                minOff = std::min(minOff, bkv.second.startOffset);
                maxOff = std::max(maxOff, bkv.second.endOffset);
            }
            if (minOff != SIZE_MAX && maxOff > minOff) {
                FunctionInfo f;
                f.rva = static_cast<std::uint32_t>(sec.virtualAddress + static_cast<std::uint32_t>(entryOff - sec.rawAddress));
                f.size = maxOff - minOff;
                f.hash = simpleHash(data, minOff, (f.size < 64) ? f.size : 64);
                functionsMap[entryOff] = f;
            }
        }
    }

    // move to outFunctions
    for (const auto& kv : functionsMap) outFunctions.push_back(kv.second);

    // annotate names from exports
    for (const auto& e : img.exports()) {
        for (auto& f : outFunctions) {
            if (f.rva == e.rva) f.name = e.name;
        }
    }

    return true;
}

namespace {

std::string hexValue(std::uint64_t value, int width = 0) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << std::setfill('0');
    if (width > 0) out << std::setw(width);
    out << value;
    return out.str();
}

bool isExecutableSection(const Section& section) {
    return (section.characteristics & 0x20000000u) != 0; // IMAGE_SCN_MEM_EXECUTE
}

// Translate a file offset back to an RVA using the section table.
std::uint32_t fileOffsetToRva(const PEImage& img, std::size_t offset) {
    for (const auto& section : img.sections()) {
        const std::size_t rawStart = section.rawAddress;
        const std::size_t rawEnd = rawStart + section.rawSize;
        if (offset >= rawStart && offset < rawEnd) {
            return section.virtualAddress + static_cast<std::uint32_t>(offset - rawStart);
        }
    }
    return 0;
}

bool isExecutableRva(const PEImage& img, std::uint32_t rva) {
    for (const auto& section : img.sections()) {
        if (!isExecutableSection(section)) continue;
        if (rva >= section.virtualAddress && rva < section.virtualAddress + section.virtualSize) {
            return true;
        }
    }
    return false;
}

std::uint32_t readUInt32(const std::vector<std::uint8_t>& data, std::size_t offset) {
    std::uint32_t value = 0;
    std::memcpy(&value, data.data() + offset, sizeof(value));
    return value;
}

} // namespace

// Phase 2: Binary metadata. Summarizes the PE structures already parsed by
// PEImage (exports, relocations, section/image layout) into a report string.
bool runBinaryMetadata(const std::string& path, std::string& outMessage) {
    std::string error;
    PEImage img;
    if (!img.load(path, error)) {
        outMessage = error;
        return false;
    }

    const auto& info = img.info();
    std::ostringstream out;
    out << "Binary metadata\n";
    out << "  File:       " << img.path() << "\n";
    out << "  Arch:       " << architectureName(info.architecture) << "\n";
    out << "  Image base: " << hexValue(info.imageBase) << "\n";
    out << "  Entry RVA:  " << hexValue(info.entryPointRva, 8) << "\n";
    out << "  Image size: " << hexValue(info.imageSize, 8) << "\n";
    out << "  Sections:   " << img.sections().size() << "\n";
    out << "  Imports:    " << img.imports().size() << "\n";
    out << "  Exports:    " << img.exports().size() << "\n";
    out << "  Relocs:     " << img.relocations().size() << "\n\n";

    out << "Exports:\n";
    if (img.exports().empty()) {
        out << "  (none)\n";
    } else {
        for (const auto& e : img.exports()) {
            out << "  " << hexValue(e.rva, 8) << "  ";
            out << (e.name.empty() ? ("#" + std::to_string(e.ordinal)) : e.name);
            out << "\n";
        }
    }
    out << "\n";

    std::map<std::uint16_t, std::size_t> relocTypes;
    for (const auto& r : img.relocations()) {
        relocTypes[r.type] += 1;
    }
    out << "Relocation types:\n";
    if (relocTypes.empty()) {
        out << "  (none)\n";
    } else {
        for (const auto& kv : relocTypes) {
            out << "  type " << kv.first << ": " << kv.second << "\n";
        }
    }

    outMessage = out.str();
    return true;
}

namespace {

// Heuristically scan executable sections for instructions whose operand is a
// target RVA in 'targets'. Records the RVA of each reference site.
void scanCodeReferences(const PEImage& img,
                        const std::vector<std::uint8_t>& data,
                        const std::unordered_set<std::uint32_t>& targets,
                        std::unordered_map<std::uint32_t, std::vector<std::uint32_t>>& refs) {
    const bool is64 = (img.info().architecture == Architecture::X64);
    const std::uint64_t imageBase = img.info().imageBase;

    auto noteRef = [&](std::uint32_t targetRva, std::uint32_t siteRva) {
        if (targets.find(targetRva) != targets.end()) {
            refs[targetRva].push_back(siteRva);
        }
    };

    for (const auto& section : img.sections()) {
        if (!isExecutableSection(section)) continue;
        const std::size_t start = section.rawAddress;
        const std::size_t end = std::min<std::size_t>(
            data.size(), static_cast<std::size_t>(section.rawAddress) + section.rawSize);
        if (start >= end) continue;

        for (std::size_t i = start; i + 2 <= end; ++i) {
            const std::uint32_t siteRva =
                section.virtualAddress + static_cast<std::uint32_t>(i - section.rawAddress);

            if (is64) {
                // RIP-relative LEA/MOV: REX.W (48..4F) + 8D/8B + ModRM(mod=00, rm=101).
                if (i + 7 <= end && data[i] >= 0x48 && data[i] <= 0x4F &&
                    (data[i + 1] == 0x8D || data[i + 1] == 0x8B) &&
                    (data[i + 2] & 0xC7) == 0x05) {
                    std::int32_t disp = 0;
                    std::memcpy(&disp, data.data() + i + 3, sizeof(disp));
                    const std::int64_t target =
                        static_cast<std::int64_t>(siteRva) + 7 + static_cast<std::int64_t>(disp);
                    if (target >= 0) noteRef(static_cast<std::uint32_t>(target), siteRva);
                }
                // Absolute pointer load: mov r64, imm64 (REX.W + B8..BF + imm64).
                if (i + 10 <= end && data[i] == 0x48 &&
                    data[i + 1] >= 0xB8 && data[i + 1] <= 0xBF) {
                    std::uint64_t imm = 0;
                    std::memcpy(&imm, data.data() + i + 2, sizeof(imm));
                    if (imm >= imageBase && (imm - imageBase) <= 0xFFFFFFFFULL) {
                        noteRef(static_cast<std::uint32_t>(imm - imageBase), siteRva);
                    }
                }
            } else {
                // 32-bit absolute operands: push/mov/moffs32 hold a full VA.
                const std::uint8_t op = data[i];
                const bool hasImm32 = (op == 0x68) || (op == 0xA1) || (op == 0xA3) ||
                                      (op >= 0xB8 && op <= 0xBF);
                if (hasImm32 && i + 5 <= end) {
                    std::uint32_t imm = 0;
                    std::memcpy(&imm, data.data() + i + 1, sizeof(imm));
                    if (static_cast<std::uint64_t>(imm) >= imageBase &&
                        (static_cast<std::uint64_t>(imm) - imageBase) <= 0xFFFFFFFFULL) {
                        noteRef(static_cast<std::uint32_t>(imm - imageBase), siteRva);
                    }
                }
            }
        }
    }
}

} // namespace

// Phase 4: Relationship analysis. Finds strings in the image and locates code
// sites that reference them.
bool runRelationshipAnalysis(const std::string& path, std::vector<StringReference>& outStringRefs) {
    std::string error;
    PEImage img;
    if (!img.load(path, error)) return false;

    const auto& data = img.data();

    StringScanner scanner;
    const auto strings = scanner.scan(data, 5, true, false, false, true);

    std::vector<std::uint32_t> stringRvas;
    stringRvas.reserve(strings.size());
    std::unordered_set<std::uint32_t> targetRvas;
    for (const auto& s : strings) {
        const std::uint32_t rva = fileOffsetToRva(img, s.offset);
        stringRvas.push_back(rva);
        if (rva != 0) targetRvas.insert(rva);
    }

    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> refs;
    if (!targetRvas.empty()) {
        scanCodeReferences(img, data, targetRvas, refs);
    }

    for (std::size_t k = 0; k < strings.size(); ++k) {
        if (stringRvas[k] == 0) continue;
        auto it = refs.find(stringRvas[k]);
        if (it == refs.end() || it->second.empty()) continue;

        StringReference ref;
        ref.value = strings[k].value;
        ref.fileOffset = strings[k].offset;
        ref.referencingRvas = it->second;
        std::sort(ref.referencingRvas.begin(), ref.referencingRvas.end());
        ref.referencingRvas.erase(
            std::unique(ref.referencingRvas.begin(), ref.referencingRvas.end()),
            ref.referencingRvas.end());
        outStringRefs.push_back(std::move(ref));
    }

    return true;
}

namespace {

// A candidate vtable must contain at least this many consecutive pointers into
// an executable section; anything shorter is treated as noise.
constexpr std::size_t kMinimumVTableMethods = 3;

} // namespace

// Phase 5: Type recovery (basic vtable detection). Scans non-executable data
// sections for runs of RVAs that point into executable code.
bool runTypeRecovery(const std::string& path, std::vector<VTable>& outVTables) {
    std::string error;
    PEImage img;
    if (!img.load(path, error)) return false;

    if (img.info().architecture != Architecture::X64 &&
        img.info().architecture != Architecture::X86) {
        return true; // only x86/x64 pointer layouts are handled
    }

    const auto& data = img.data();
    const std::size_t pointerSize = 4; // PE stores pointers as RVAs (4 bytes)

    for (const auto& section : img.sections()) {
        if (isExecutableSection(section)) continue; // vtables live in data sections
        if (section.rawSize < pointerSize * kMinimumVTableMethods) continue;

        const std::size_t start = section.rawAddress;
        const std::size_t end = std::min<std::size_t>(
            data.size(), static_cast<std::size_t>(section.rawAddress) + section.rawSize);
        if (start >= end) continue;

        std::size_t i = start;
        while (i + pointerSize <= end) {
            if (!isExecutableRva(img, readUInt32(data, i))) {
                i += pointerSize;
                continue;
            }

            const std::size_t runStart = i;
            std::vector<std::uint32_t> methods;
            std::size_t j = i;
            while (j + pointerSize <= end) {
                const std::uint32_t method = readUInt32(data, j);
                if (!isExecutableRva(img, method)) break;
                methods.push_back(method);
                j += pointerSize;
            }

            if (methods.size() >= kMinimumVTableMethods) {
                VTable vt;
                vt.rva = fileOffsetToRva(img, runStart);
                vt.methodRvas = std::move(methods);
                outVTables.push_back(std::move(vt));
                i = j;
            } else {
                i += pointerSize;
            }
        }
    }

    return true;
}

// Phase 6: Binary comparison. Matches functions between two builds by export
// name (and by content hash for unnamed functions) and reports differences.
bool runBinaryComparison(const std::string& pathV1,
                         const std::string& pathV2,
                         DiffSummary& outSummary,
                         std::vector<LayoutChange>& outChanges) {
    std::vector<FunctionInfo> funcs1;
    std::vector<FunctionInfo> funcs2;
    if (!runCodeAnalysis(pathV1, funcs1)) return false;
    if (!runCodeAnalysis(pathV2, funcs2)) return false;

    outSummary = {};
    outChanges.clear();

    std::unordered_map<std::string, const FunctionInfo*> named1;
    std::unordered_map<std::string, const FunctionInfo*> named2;
    for (const auto& f : funcs1) if (!f.name.empty()) named1[f.name] = &f;
    for (const auto& f : funcs2) if (!f.name.empty()) named2[f.name] = &f;

    // Named functions: matched by export name.
    for (const auto& kv : named1) {
        const auto it = named2.find(kv.first);
        if (it == named2.end()) {
            outSummary.functionsRemoved += 1;
            continue;
        }
        if (kv.second->hash != it->second->hash) {
            outSummary.functionsChanged += 1;
        }
        if (kv.second->rva != it->second->rva) {
            LayoutChange change;
            change.structureName = "ExportedFunction";
            change.fieldName = kv.first;
            change.v1Offset = hexValue(kv.second->rva, 8);
            change.v2Offset = hexValue(it->second->rva, 8);
            outChanges.push_back(std::move(change));
        }
    }
    for (const auto& kv : named2) {
        if (named1.find(kv.first) == named1.end()) {
            outSummary.functionsAdded += 1;
        }
    }

    // Unnamed functions: matched by content hash, counted only when unmatched.
    std::unordered_map<std::uint64_t, std::size_t> hashes1;
    std::unordered_map<std::uint64_t, std::size_t> hashes2;
    for (const auto& f : funcs1) if (f.name.empty()) hashes1[f.hash] += 1;
    for (const auto& f : funcs2) if (f.name.empty()) hashes2[f.hash] += 1;

    for (const auto& kv : hashes1) {
        const auto it = hashes2.find(kv.first);
        const std::size_t matched = (it == hashes2.end()) ? 0 : it->second;
        if (kv.second > matched) outSummary.functionsRemoved += (kv.second - matched);
    }
    for (const auto& kv : hashes2) {
        const auto it = hashes1.find(kv.first);
        const std::size_t matched = (it == hashes1.end()) ? 0 : it->second;
        if (kv.second > matched) outSummary.functionsAdded += (kv.second - matched);
    }

    return true;
}

} // namespace forge
