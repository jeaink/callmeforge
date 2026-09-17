#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace forge {

// Phase 2 types (exports/relocs) are provided by PEImage now.

// Phase 3: Code analysis
struct FunctionInfo {
    std::uint32_t rva;       // start RVA
    std::size_t size;        // estimated size in bytes
    std::uint64_t hash;      // simple hash of bytes for comparison
    std::string name;        // optional (from exports)
};

// Phase 4: Relationship analysis
struct StringReference {
    std::string value;
    std::size_t fileOffset;
    std::vector<std::uint32_t> referencingRvas; // RVAs in code that reference the string
};

// Phase 5: Type recovery (basic vtable detection)
struct VTable {
    std::uint32_t rva; // file RVA of vtable start
    std::vector<std::uint32_t> methodRvas; // RVAs of methods pointed to
};

// Phase 6: Diff results
struct DiffSummary {
    std::size_t functionsChanged;
    std::size_t functionsAdded;
    std::size_t functionsRemoved;
};

struct LayoutChange {
    std::string structureName;
    std::string fieldName;
    std::string v1Offset;
    std::string v2Offset;
};

// Phase 2
bool runBinaryMetadata(const std::string& path, std::string& outMessage);

// Phase 3
bool runCodeAnalysis(const std::string& path, std::vector<FunctionInfo>& outFunctions);

// Phase 4
bool runRelationshipAnalysis(const std::string& path, std::vector<StringReference>& outStringRefs);

// Phase 5
bool runTypeRecovery(const std::string& path, std::vector<VTable>& outVTables);

// Phase 6
bool runBinaryComparison(const std::string& pathV1, const std::string& pathV2, DiffSummary& outSummary, std::vector<LayoutChange>& outChanges);

} // namespace forge
