#pragma once

#include "anomaly/symbol_resolver.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace anomaly {

inline constexpr std::string_view kUe5FTextFeature = "ue5.ftext";
inline constexpr std::string_view kUe5FTextValidator = "ue5-ftext-layout-v1";
inline constexpr std::string_view kUe5FTextDisplayGetter = "ue5.FTextData.GetDisplayString";
inline constexpr std::string_view kUe5FTextTableGetter =
    "ue5.FTextDataStringTableEntry.GetSharedDisplayString";
inline constexpr std::string_view kUe5StringTableRegistry = "ue5.StringTableRegistry";

void RegisterUe5FTextValidator(FeatureLayoutValidatorRegistry& validators);

// Copies an existing display/source string. Never calls UE or retains its pointers.
[[nodiscard]] std::string ReadUe5FTextUtf8(
    const BuildProfile& profile, const ProfileResolutionSnapshot& resolution,
    const SymbolMemory& memory, const std::array<std::uint8_t, 16>& text) noexcept;

[[nodiscard]] std::string ReadUe5FTextUtf8(
    const BuildProfile& profile, const ProfileResolutionSnapshot& resolution,
    const SymbolMemory& memory, std::uintptr_t address) noexcept;

}  // namespace anomaly
