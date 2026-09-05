#include "anomaly/ue5_ftext.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

namespace anomaly {
namespace {

constexpr auto kDisplayGetterBytes = std::to_array<std::uint8_t>({
    0x48, 0x8B, 0x51, 0x30, 0x48, 0x83, 0xC1, 0x20, 0x48, 0x85,
    0xD2, 0x48, 0x8D, 0x42, 0x08, 0x48, 0x0F, 0x44, 0xC1, 0xC3});
constexpr auto kTableGetterBytes = std::to_array<std::uint8_t>({
    0x48, 0x89, 0x5C, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20,
    0x48, 0x8B, 0x49, 0x18, 0x33, 0xDB, 0x48, 0x8B, 0xFA, 0x48,
    0x85, 0xC9, 0x74, 0x5F, 0x45, 0x33, 0xC0, 0x48, 0x8D, 0x54,
    0x24, 0x30, 0xE8});

// Offsets observed in the two ITextData implementations and string-table lookups.
constexpr std::pair<std::string_view, std::int64_t> kLayouts[]{
    {"ftext.textData", 0}, {"ftextData.textSource", 32},
    {"ftextData.displayStringGetter", 40}, {"ftextData.sharedDisplayStringGetter", 48},
    {"ftextData.sharedDisplayString", 48}, {"ftextData.stringTableReference", 24},
    {"ftextStringTableReference.tableId", 16}, {"ftextStringTableReference.keyId", 24},
    {"ftextStringTableReference.cachedDisplayString", 48}, {"sharedString.value", 8},
    {"stringTable.entries", 32}, {"stringTableEntry.sourceString", 16},
    {"stringTable.mapElementStride", 32}, {"stringTable.mapValue", 8},
    {"fstring.data", 0}, {"fstring.count", 8}, {"fstring.capacity", 12},
    {"dataTable.rowMapData", 0}, {"dataTable.rowMapNum", 8},
    {"dataTable.rowMapMax", 12}, {"dataTable.rowMapNumFree", 52},
    {"dataTable.rowMapInlineFlags", 16}, {"dataTable.rowMapFlagsData", 32},
    {"dataTable.rowMapFlagsNum", 40}, {"dataTable.rowMapFlagsMax", 44}};
constexpr std::int32_t kMaximumEntries = 4096;

std::int64_t Offset(const BuildProfile& profile, std::string_view key) {
    const auto found = profile.layout.find(std::string(key));
    return found == profile.layout.end() ? -1 : found->second;
}

std::uintptr_t Address(std::uintptr_t base, std::int64_t offset) {
    if (base == 0 || offset < 0 || static_cast<std::uint64_t>(offset) >
            (std::numeric_limits<std::uintptr_t>::max)() - base) return 0;
    return base + static_cast<std::uintptr_t>(offset);
}

template <typename T>
bool Read(const SymbolMemory& memory, std::uintptr_t address, T& result) {
    return address != 0 && memory.Read(address, &result, sizeof(result));
}

template <typename T, std::size_t N>
bool Field(const std::array<std::uint8_t, N>& bytes, std::int64_t offset, T& value) {
    if (offset < 0 || static_cast<std::size_t>(offset) > N ||
        sizeof(T) > N - static_cast<std::size_t>(offset)) return false;
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return true;
}

template <std::size_t N>
bool Matches(const SymbolMemory& memory, std::uintptr_t address,
             const std::array<std::uint8_t, N>& expected) {
    std::array<std::uint8_t, N> bytes{};
    return Read(memory, address, bytes) && bytes == expected;
}

FeatureValidationResult ValidateLayout(
    const BuildProfile& profile, std::string_view feature,
    const ProfileResolutionSnapshot& resolution, const SymbolMemory& memory) {
    if (feature != kUe5FTextFeature) return {false, "FText validator used by another feature"};
    for (const auto& [key, expected] : kLayouts) {
        if (Offset(profile, key) != expected) {
            return {false, "unsupported FText layout: " + std::string(key)};
        }
    }
    const auto declared = profile.features.find(std::string(feature));
    for (const auto id : {kUe5FTextDisplayGetter, kUe5FTextTableGetter, kUe5StringTableRegistry}) {
        const auto* symbol = resolution.FindSymbol(id);
        if (declared == profile.features.end() ||
            std::find(declared->second.begin(), declared->second.end(), id) == declared->second.end() ||
            symbol == nullptr || !symbol->Available()) {
            return {false, "FText symbol unavailable: " + std::string(id)};
        }
    }
    if (!Matches(memory, resolution.FindSymbol(kUe5FTextDisplayGetter)->address, kDisplayGetterBytes) ||
        !Matches(memory, resolution.FindSymbol(kUe5FTextTableGetter)->address, kTableGetterBytes)) {
        return {false, "ITextData getter instruction contract changed"};
    }
    return {true, {}};
}

// Read one bounded sparse-map snapshot; holes must not expose retired entries.
template <typename Key>
std::uintptr_t FindMapValue(const BuildProfile& profile, const SymbolMemory& memory,
                            std::uintptr_t map, Key key) {
    std::array<std::uint8_t, 80> header{};
    std::uintptr_t data{}, flags_data{};
    std::int32_t count{}, capacity{}, free{}, flags_count{}, flags_capacity{};
    if (!Read(memory, map, header) ||
        !Field(header, Offset(profile, "dataTable.rowMapData"), data) ||
        !Field(header, Offset(profile, "dataTable.rowMapNum"), count) ||
        !Field(header, Offset(profile, "dataTable.rowMapMax"), capacity) ||
        !Field(header, Offset(profile, "dataTable.rowMapNumFree"), free) ||
        !Field(header, Offset(profile, "dataTable.rowMapFlagsData"), flags_data) ||
        !Field(header, Offset(profile, "dataTable.rowMapFlagsNum"), flags_count) ||
        !Field(header, Offset(profile, "dataTable.rowMapFlagsMax"), flags_capacity) ||
        count <= 0 || count > capacity || capacity > kMaximumEntries ||
        free < 0 || free >= count || flags_count < count || flags_count > kMaximumEntries ||
        flags_capacity < flags_count || data == 0) return 0;
    const auto words = static_cast<std::size_t>((flags_count + 31) / 32);
    std::vector<std::uint32_t> flags(words);
    if (flags_data == 0) {
        if (words > 4) return 0;
        flags_data = Address(map, Offset(profile, "dataTable.rowMapInlineFlags"));
    }
    const auto stride = Offset(profile, "stringTable.mapElementStride");
    const auto value_offset = Offset(profile, "stringTable.mapValue");
    if (stride < static_cast<std::int64_t>(sizeof(Key)) || stride > 128 || value_offset < 0 ||
        value_offset + static_cast<std::int64_t>(sizeof(std::uintptr_t)) > stride ||
        flags_data == 0 || !memory.Read(flags_data, flags.data(), words * sizeof(std::uint32_t))) return 0;
    std::vector<std::uint8_t> rows(static_cast<std::size_t>(count) * static_cast<std::size_t>(stride));
    if (!memory.Read(data, rows.data(), rows.size())) return 0;
    for (std::int32_t index = 0; index < count; ++index) {
        if ((flags[static_cast<std::size_t>(index) / 32] & (1U << (index % 32))) == 0) continue;
        const auto* row = rows.data() + static_cast<std::size_t>(index) * stride;
        Key candidate{};
        std::memcpy(&candidate, row, sizeof(candidate));
        if (candidate != key) continue;
        std::uintptr_t value{};
        std::memcpy(&value, row + value_offset, sizeof(value));
        return value;
    }
    return 0;
}

std::string ReadString(const BuildProfile& profile, const SymbolMemory& memory,
                       std::uintptr_t address) {
    std::array<std::uint8_t, 16> header{};
    std::uintptr_t data{};
    std::int32_t count{}, capacity{};
    if (!Read(memory, address, header) ||
        !Field(header, Offset(profile, "fstring.data"), data) ||
        !Field(header, Offset(profile, "fstring.count"), count) ||
        !Field(header, Offset(profile, "fstring.capacity"), capacity) ||
        data == 0 || count <= 1 || count > 4096 || capacity < count || capacity > 8192) return {};
    std::vector<wchar_t> wide(static_cast<std::size_t>(count));
    if (!memory.Read(data, wide.data(), wide.size() * sizeof(wchar_t)) || wide.back() != L'\0') return {};
    wide.pop_back();
    if (std::any_of(wide.begin(), wide.end(), [](wchar_t ch) {
            return (ch < 0x20 && ch != L'\t' && ch != L'\n' && ch != L'\r') || ch == 0x7F;
        })) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
        static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string value(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), static_cast<int>(wide.size()),
            value.data(), size, nullptr, nullptr) != size) return {};
    return value;
}

}  // namespace

void RegisterUe5FTextValidator(FeatureLayoutValidatorRegistry& validators) {
    validators.Register(std::string(kUe5FTextValidator), ValidateLayout);
}

std::string ReadUe5FTextUtf8(
    const BuildProfile& profile, const ProfileResolutionSnapshot& resolution,
    const SymbolMemory& memory, const std::array<std::uint8_t, 16>& text) noexcept {
    try {
        if (!resolution.FeatureAvailable(kUe5FTextFeature)) return {};
        const auto* display_getter = resolution.FindSymbol(kUe5FTextDisplayGetter);
        const auto* table_getter = resolution.FindSymbol(kUe5FTextTableGetter);
        const auto* registry = resolution.FindSymbol(kUe5StringTableRegistry);
        if (!display_getter || !table_getter || !registry) return {};
        std::uintptr_t data{}, vtable{}, getter{};
        if (!Field(text, Offset(profile, "ftext.textData"), data) || !Read(memory, data, vtable) ||
            !Read(memory, Address(vtable, Offset(profile, "ftextData.displayStringGetter")), getter)) return {};
        if (getter == display_getter->address) {
            std::uintptr_t shared{};
            if (!Read(memory, Address(data, Offset(profile, "ftextData.sharedDisplayString")), shared)) return {};
            return ReadString(profile, memory, shared != 0
                ? Address(shared, Offset(profile, "sharedString.value"))
                : Address(data, Offset(profile, "ftextData.textSource")));
        }
        if (!Read(memory, Address(vtable, Offset(profile, "ftextData.sharedDisplayStringGetter")), getter) ||
            getter != table_getter->address) return {};
        std::uintptr_t reference{}, shared{};
        if (!Read(memory, Address(data, Offset(profile, "ftextData.stringTableReference")), reference) ||
            !Read(memory, Address(reference, Offset(profile, "ftextStringTableReference.cachedDisplayString")), shared)) return {};
        if (shared != 0) return ReadString(profile, memory, Address(shared, Offset(profile, "sharedString.value")));
        std::uint64_t table_id{};
        std::uint32_t key{};
        if (!Read(memory, Address(reference, Offset(profile, "ftextStringTableReference.tableId")), table_id) ||
            !Read(memory, Address(reference, Offset(profile, "ftextStringTableReference.keyId")), key)) return {};
        const auto table = FindMapValue(profile, memory, registry->address, table_id);
        const auto entry = FindMapValue(profile, memory, Address(table, Offset(profile, "stringTable.entries")), key);
        return ReadString(profile, memory, Address(entry, Offset(profile, "stringTableEntry.sourceString")));
    } catch (...) {
        return {};
    }
}

std::string ReadUe5FTextUtf8(
    const BuildProfile& profile, const ProfileResolutionSnapshot& resolution,
    const SymbolMemory& memory, std::uintptr_t address) noexcept {
    try {
        std::array<std::uint8_t, 16> text{};
        return Read(memory, address, text) ? ReadUe5FTextUtf8(profile, resolution, memory, text) : std::string{};
    } catch (...) {
        return {};
    }
}

}  // namespace anomaly
