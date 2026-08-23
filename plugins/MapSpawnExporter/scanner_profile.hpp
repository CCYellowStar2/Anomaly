#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace anomaly_map_spawn_exporter {

// These values mirror the validated UE5 object/DataTable contract currently used
// by the NTE profile. The exporter only reads immutable table rows and never
// walks UWorld levels or actor/entity snapshots.
inline constexpr std::string_view kGObjectsPattern =
    "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8B 04 D1 C3 33 C0 48 8B 00 C3";
inline constexpr std::ptrdiff_t kGObjectsAddend = -16;
inline constexpr std::uint32_t kRipDisplacementOffset = 3;
inline constexpr std::uint32_t kRipInstructionSize = 7;
inline constexpr std::uint32_t kObjectItemsOffset = 16;
inline constexpr std::uint32_t kObjectCountOffset = 36;
inline constexpr std::uint32_t kObjectMaxCountOffset = 32;
inline constexpr std::uint32_t kObjectMaxChunksOffset = 40;
inline constexpr std::uint32_t kObjectNumChunksOffset = 44;
inline constexpr std::uint32_t kObjectChunkSize = 65536;
inline constexpr std::uint32_t kObjectItemStride = 24;

inline constexpr std::uint32_t kDataTableRowMapOffset = 0x30;
inline constexpr std::uint32_t kDataTableRowStride = 24;
inline constexpr std::uint32_t kDataTableRowPointerOffset = 8;
inline constexpr std::uint32_t kMaximumDataTableRows = 32768;
inline constexpr std::uint32_t kMaximumRowBytes = 0x200;

inline constexpr std::uint32_t kObjectClassOffset = 0x10;
inline constexpr std::uint32_t kObjectNameOffset = 0x18;
inline constexpr std::uint32_t kObjectOuterOffset = 0x20;
inline constexpr std::uint32_t kDataTableRowStructOffset = 0x28;

inline constexpr std::uint32_t kTeleportBelongsLevelOffset = 0x08;
inline constexpr std::uint32_t kTeleportFloorOffset = 0x28;
inline constexpr std::uint32_t kTeleportTransformTranslationOffset = 0x60;
inline constexpr std::uint32_t kTeleportTypeOffset = 0xB8;
inline constexpr std::uint32_t kTeleportCanTeleportOffset = 0xD8;
inline constexpr std::uint32_t kTeleportOverrideTransformOffset = 0xD9;
inline constexpr std::uint32_t kTeleportOverrideTranslationOffset = 0x100;

inline constexpr std::uint32_t kRandomItemTableOffset = 0x48;
inline constexpr std::uint32_t kOracleStoneDataAssetTableOffset = 0x40;
inline constexpr std::uint32_t kOracleStoneLevelOffset = 0x10;
inline constexpr std::uint32_t kOracleStoneFloorOffset = 0x30;
inline constexpr std::uint32_t kOracleStoneLocationOffset = 0x40;
inline constexpr std::uint32_t kRandomItemLevelNameOffset = 8;
inline constexpr std::uint32_t kRandomItemTypeOffset = 0x20;
inline constexpr std::uint32_t kRandomItemTransformOffset = 0x30;
inline constexpr std::uint32_t kTransformTranslationOffset = 0x20;

inline constexpr std::size_t kMaximumNameBytes = 1024;
inline constexpr std::uint32_t kMaximumObjectCount = 16U * 1024U * 1024U;
inline constexpr std::uint32_t kMaximumObjectChunks = 4096;

}  // namespace anomaly_map_spawn_exporter
