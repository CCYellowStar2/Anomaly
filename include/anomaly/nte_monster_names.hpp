#pragma once

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace anomaly {

inline std::string NteMonsterDisplayIdentity(std::string_view source) {
    std::string identity(source);
    if (identity.starts_with("Default__")) identity.erase(0, 9U);
    if (identity.ends_with("_C")) identity.resize(identity.size() - 2U);
    for (char& value : identity) {
        if (value >= 'A' && value <= 'Z') value = static_cast<char>(value - 'A' + 'a');
    }
    const auto blueprint_marker = identity.find("_bp");
    if (blueprint_marker != std::string::npos &&
        (blueprint_marker + 3U == identity.size() || identity[blueprint_marker + 3U] == '_')) {
        identity.resize(blueprint_marker);
        return identity;
    }
    const auto first_separator = identity.find('_');
    if (first_separator == std::string::npos) return {};
    const auto second_separator = identity.find('_', first_separator + 1U);
    if (second_separator != std::string::npos) identity.resize(second_separator);
    return identity;
}

// Accept only the observed numbered monster/boss families, not arbitrary prefixes.
inline std::string_view NteMonsterBaseIdentity(std::string_view identity) {
    const auto separator = identity.find('_');
    if (separator == std::string_view::npos) return {};
    const auto kind = identity.substr(0, separator);
    if (kind != "mon" && kind != "boss") return {};
    const auto end = identity.find('_', separator + 1U);
    const auto base = identity.substr(0, end);
    const auto number = base.substr(separator + 1U);
    if (number.empty() || !std::all_of(number.begin(), number.end(), [](char ch) {
            return ch >= '0' && ch <= '9';
        })) return {};
    return base;
}

inline std::vector<std::string> NteMonsterStringTableKeys(
    std::string_view source, bool base_only = false) {
    const auto lower = [](std::string value) {
        for (char& ch : value) {
            if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
        }
        return value;
    };
    std::string stem(source);
    if (stem.starts_with("Default__")) stem.erase(0, 9U);
    if (stem.ends_with("_C")) stem.resize(stem.size() - 2U);
    const auto marker = lower(stem).find("_bp");
    if (marker != std::string::npos &&
        (marker + 3U == stem.size() || stem[marker + 3U] == '_')) stem.resize(marker);
    auto normalized = lower(stem);
    std::vector<std::string> keys;
    keys.reserve(8);
    const auto add_stem = [&keys](std::string_view value) {
        if (value.empty()) return;
        for (const auto suffix : {"_Name", "_name"}) {
            auto key = std::string(value) + suffix;
            if (std::find(keys.begin(), keys.end(), key) == keys.end()) keys.push_back(std::move(key));
        }
    };
    if (!normalized.starts_with("mon_") && !normalized.starts_with("boss_")) {
        const auto legacy = NteMonsterDisplayIdentity(source);
        if (!base_only && legacy.size() <= 64) add_stem(legacy);
        return keys;
    }
    if (stem.empty() || stem.size() > 64) return {};
    if (base_only) {
        const auto base = NteMonsterBaseIdentity(normalized);
        if (base.empty() || base == normalized) return {};
        stem = base;
        normalized = stem;
    }
    // Live keys mix mon_012/mon_12, and _Name/_name. Preserve variant suffixes.
    const auto normalize_number = [](std::string value) {
        const auto start = value.find('_') + 1U;
        const auto end = value.find('_', start);
        const auto count = end == std::string::npos ? value.size() - start : end - start;
        const auto number = std::string_view(value).substr(start, count);
        if (number.empty() || !std::all_of(number.begin(), number.end(), [](char ch) {
                return ch >= '0' && ch <= '9';
            })) return value;
        std::size_t zeros{};
        while (count - zeros > 2U && number[zeros] == '0') ++zeros;
        value.erase(start, zeros);
        if (count == 1U) value.insert(start, 1U, '0');
        return value;
    };
    add_stem(stem);
    add_stem(normalized);
    add_stem(normalize_number(stem));
    add_stem(normalize_number(normalized));
    return keys;
}

// Multiple rows may share a name; disagreement rejects the broad fallback.
inline bool MergeNteMonsterFallbackName(std::string& value, std::string_view candidate) {
    if (candidate.empty()) return true;
    if (!value.empty() && value != candidate) return false;
    value = candidate;
    return true;
}

}  // namespace anomaly
