#include "anomaly/sdk/cpp.hpp"
#include "anomaly/sdk/services/core.h"
#include "anomaly/sdk/services/interop.h"
#include "anomaly/sdk/services/ue5.h"
#include "anomaly/sdk/services/ui.h"
#include "anomaly/sdk/services/nte.h"
#include "anomaly/sdk/services/localization.h"
#include "anomaly/sdk/services/plugin_state.h"
#include "plugins/common/localization.hpp"

#include <Windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <new>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

constexpr std::string_view kTablePath =
    "/Game/DataTable/Treasurebox/DT_TreasureboxConfig.DT_TreasureboxConfig";

constexpr std::ptrdiff_t kDataTableRowMapOffset = 0x30;
constexpr std::uint32_t kDataTableRowStride = 24;
constexpr std::uint32_t kDataTableRowPointerOffset = 8;
constexpr std::ptrdiff_t kCoordOffset = 48;

constexpr std::string_view kGObjectsPattern =
    "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8B 04 D1 C3 33 C0 48 8B 00 C3";
constexpr std::ptrdiff_t kGObjectsAddend = -16;
constexpr std::uint32_t kRipDisplacementOffset = 3;
constexpr std::uint32_t kRipInstructionSize = 7;
constexpr std::ptrdiff_t kObjectItemsOffset = 16;
constexpr std::ptrdiff_t kObjectCountOffset = 36;
constexpr std::ptrdiff_t kObjectNumChunksOffset = 44;
constexpr std::uint32_t kObjectChunkSize = 65536;
constexpr std::uint32_t kObjectItemStride = 24;
constexpr std::size_t kMaximumNameBytes = 1024;

constexpr double kTeleportZOffset = 60.0;
constexpr double kApproachRadiusCentimeters = 100.0;
constexpr std::string_view kLandmarkWorld = "XL_map_bigworld_test";
constexpr double kLandmarkArrivalRadiusCentimeters = 500.0;
constexpr double kLandmarkTransferTimeoutSeconds = 20.0;
constexpr double kLandmarkSettleSeconds = 2.0;
constexpr double kArrivalRadiusCentimeters = 600.0;
constexpr double kMovementTimeoutSeconds = 20.0;
constexpr double kProgressCheckIntervalSeconds = 3.0;
constexpr double kProgressThresholdCentimeters = 80.0;
constexpr double kReissueDelaySeconds = 4.0;
constexpr std::uint32_t kMaximumMapLandmarks = 4096;

struct RawName final {
    std::int32_t comparison_index{};
    std::uint32_t number{};
};

struct Point final {
    std::string row_name;
    double x{};
    double y{};
    double z{};
};

struct MapLandmark final {
    std::uint64_t sequence{};
    std::uint32_t index{};
    double destination[3]{};
    std::string teleport_id;
};

std::vector<Point> VisionPoints() {
    return {
        {"伤心英熊_mon_019_SadBear_BP_World_C_0", -28170, 84678, 6503},
        {"伤心英熊_mon_019_SadBear_BP_World_C_1", -283560, 348658, 2312},
        {"伤心英熊_mon_019_SadBear_BP_World_C_2", -34682, 131390, 2843},
        {"伤心英熊_mon_019_SadBear_BP_World_C_3", 27585, 115101, 7057},
        {"伤心英熊_mon_019_SadBear_BP_World_C_4", 35051, 73480, 6201},
        {"伤心英熊_mon_019_SadBear_BP_World_C_5", 36087, 138934, 3167},
        {"妖刀_mon_13_1_BP_World_C_6", -129110, 133352, 6713},
        {"妖刀_mon_13_1_BP_World_C_7", -172989, 122003, 7117},
        {"妖刀_mon_13_1_BP_World_Perform_C_8", -111304, 162488, 5980},
        {"妖刀_mon_13_1_BP_World_Perform_C_9", -145267, 79781, 7543},
        {"妖刀_mon_13_1_BP_World_Perform_C_10", -19120, 23926, 7711},
        {"妖刀_mon_13_1_BP_World_Perform_C_11", -277508, 346179, 3955},
        {"妖刀_mon_13_1_BP_World_Perform_C_12", -77961, 138950, 3892},
        {"妖刀_mon_13_1_BP_World_Perform_C_13", 29187, 100218, 7173},
        {"妖刀_mon_13_2_BP_World_C_14", -150925, 82837, 7561},
        {"妖刀_mon_13_2_BP_World_Interaction_C_15", -143290, 213280, 8766},
        {"妖刀_mon_13_BP_World_C_16", -201739, 106656, 7572},
        {"妖刀_mon_13_BP_World_C_17", -253256, 361426, 5616},
        {"妖刀_mon_13_BP_World_Interaction_C_18", -36600, 88375, 5222},
        {"妖刀_mon_13_horizontal_BP_World_C_19", -86569, 130546, 7882},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_20", -105359, 65605, 7131},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_21", -105589, 66670, 7136},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_22", -119567, 196220, 5758},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_23", -137731, 160872, 6835},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_24", -164979, 139373, 6745},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_25", -21772, 47950, 7710},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_26", -24617, 66364, 6913},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_27", -33772, 31497, 7744},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_28", -36058, 50158, 7690},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_29", -46555, 104935, 2886},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_30", -49823, 86262, 2900},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_31", -50231, 85743, 2900},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_32", -58223, 72915, 3638},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_33", 18630, 104502, 6555},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_34", 29359, 138598, 3166},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_35", 42088, 52008, 5114},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_36", 42097, 116235, 6999},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_37", 7970, 30375, 7696},
        {"贩售机附电灵_mon_14_BP_World_Interaction_C_38", 8775, 31078, 7684},
        {"洄天鱼幡_mon_025_BP_Blue_World_Passive_C_39", -133541, 153285, 13629},
        {"洄天鱼幡_mon_025_BP_Blue_World_Passive_C_40", -190922, 184853, 8251},
        {"洄天鱼幡_mon_025_BP_Blue_World_Passive_C_41", -21200, 68382, 28231},
        {"洄天鱼幡_mon_025_BP_Blue_World_Passive_C_42", -61212, -21036, 9408},
        {"洄天鱼幡_mon_025_BP_Green_World_Passive_C_43", -132500, 152691, 13629},
        {"洄天鱼幡_mon_025_BP_Green_World_Passive_C_44", -190846, 183799, 8245},
        {"洄天鱼幡_mon_025_BP_Green_World_Passive_C_45", -21939, 68863, 28294},
        {"洄天鱼幡_mon_025_BP_Green_World_Passive_C_46", -60069, -19342, 8985},
        {"洄天鱼幡_mon_025_BP_Red_World_Passive_C_47", -132508, 153895, 13629},
        {"洄天鱼幡_mon_025_BP_Red_World_Passive_C_48", -189837, 184982, 8293},
        {"洄天鱼幡_mon_025_BP_Red_World_Passive_C_49", -22069, 67703, 28445},
        {"洄天鱼幡_mon_025_BP_Red_World_Passive_C_50", -62230, -19428, 9003},
        {"洄天鱼幡_mon_025_BP_World_Vision_02_1_C_51", 5217, 109465, 28755},
        {"洄天鱼幡_mon_025_BP_World_Vision_02_2_C_52", 5217, 109465, 28755},
        {"洄天鱼幡_mon_025_BP_World_Vision_02_3_C_53", 5217, 109465, 28755},
        {"洄天鱼幡_mon_025_BP_World_W103308_01_C_54", -153361, 204915, 6668},
        {"洄天鱼幡_mon_025_BP_World_W103308_02_C_55", -153361, 204915, 6668},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_56", -110366, 79375, 15476},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_57", -123577, 190121, 8783},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_58", -124398, 96588, 12899},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_59", -139539, 156211, 11671},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_60", -141856, 127782, 12499},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_61", -179873, 146591, 10085},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_62", -181567, 239880, 2463},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_63", -184345, 98966, 12662},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_64", -207027, 193561, 7655},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_65", -35988, 119065, 13859},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_66", -45688, 88125, 9597},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_67", -76466, 69499, 10501},
        {"洄天鱼幡_mon_025_double_1_BP_World_C_68", 38406, 55294, 9518},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_69", -110366, 79375, 15476},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_70", -123577, 190121, 8783},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_71", -124398, 96588, 12899},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_72", -139539, 156211, 11671},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_73", -141856, 127782, 12499},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_74", -179873, 146591, 10085},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_75", -181567, 239880, 2463},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_76", -184345, 98966, 12662},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_77", -207027, 193561, 7655},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_78", -35988, 119065, 13859},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_79", -45688, 88125, 9597},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_80", -76466, 69499, 10501},
        {"洄天鱼幡_mon_025_double_2_BP_World_C_81", 38406, 55294, 9518},
        {"纸翼战队_mon_26_BP_World_C_82", -103972, 50917, 8488},
        {"纸翼战队_mon_26_BP_World_C_83", -124312, 59338, 8465},
        {"纸翼战队_mon_26_BP_World_C_84", -135156, 233737, 2510},
        {"纸翼战队_mon_26_BP_World_C_85", -16940, 95140, 6540},
        {"纸翼战队_mon_26_BP_World_C_86", -195094, 187235, 8278},
        {"纸翼战队_mon_26_BP_World_C_87", -254512, 348519, 2601},
        {"纸翼战队_mon_26_BP_World_C_88", -30925, 16442, 8710},
        {"纸翼战队_mon_26_BP_World_C_89", -43748, 6288, 7665},
        {"纸翼战队_mon_26_BP_World_C_90", -6871, 13074, 8910},
        {"纸翼战队_mon_26_BP_World_C_91", -80561, 288, 8355},
        {"纸翼战队_mon_26_BP_World_C_92", 23426, 77367, 6500},
        {"纸翼战队_mon_26_BP_World_C_93", 48854, 123607, 6485},
        {"纸翼战队_mon_26_BP_World_Perform_C_94", -119972, 147571, 8455},
        {"纸翼战队_mon_26_BP_World_Perform_C_95", -125859, 73580, 7985},
        {"纸翼战队_mon_26_BP_World_Perform_C_96", -201744, 213237, 18241},
        {"纸翼战队_mon_26_BP_World_Perform_C_97", -44462, 14189, 7512},
        {"纸翼战队_mon_26_BP_World_Perform_C_98", 24980, 44301, 52768},
        {"波普_mon_012_1_BP_World_Area01_002_C_99", -122624, 156946, 10139},
        {"波普_mon_012_1_BP_World_Area02_001_C_100", -182767, 124538, 7429},
        {"波普_mon_012_1_BP_World_Area02_002_C_101", -113712, 64380, 8749},
        {"波普_mon_012_1_BP_World_Area02_003_C_102", -92400, 97459, 6317},
        {"波普_mon_012_1_BP_World_AreaSpecial_01_C_103", -119497, 185081, 6131},
        {"波普_mon_012_1_BP_World_AreaSpecial_02_C_104", -128896, 126920, 6785},
        {"波普_mon_012_2_BP_World_Area01_002_C_105", -122630, 156952, 10146},
        {"波普_mon_012_2_BP_World_Area02_001_C_106", -182767, 124538, 7446},
        {"波普_mon_012_2_BP_World_Area02_002_C_107", -113712, 64380, 8779},
        {"波普_mon_012_2_BP_World_Area02_003_C_108", -92400, 97459, 6282},
        {"波普_mon_012_2_BP_World_AreaSpecial_01_C_109", -119491, 185088, 6170},
        {"波普_mon_012_2_BP_World_AreaSpecial_02_C_110", -128896, 126920, 6878},
    };
}

static const char* kVisionNames[] = {
    "伤心英熊", "妖刀", "贩售机附电灵", "洄天鱼幡", "纸翼战队", "波普"
};

struct Context final {
    const AnomalyHostApiV1* host{};
    const AnomalySignatureServiceV1* signature{};
    const AnomalyUe5NamesServiceV1* names{};
    const AnomalyUe5ObjectsServiceV1* objects{};
    const AnomalyNteSessionServiceV1* session{};
    const AnomalyNtePlayerServiceV1* player{};
    const AnomalyNtePlayerTeleportServiceV1* teleport{};
    const AnomalyNteNavigationServiceV1* navigation{};
    const AnomalyNteMapLandmarksServiceV1* map_landmarks{};
    const AnomalyPluginStateServiceV1* plugin_state{};
    anomaly::plugins::Localizer localizer;

    std::uintptr_t g_objects_address{};

    std::mutex mutex;
    std::vector<Point> points;
    std::unordered_set<std::string> done_set;
    std::string state_directory;
    std::string status;
    std::uint32_t type_choice{0};
    std::uint32_t sub_choice{0};
    std::vector<Point> filtered_points;
    std::atomic_bool read_pending{};
    std::atomic_bool developer_mode{};
    std::atomic_bool manual_teleport_pending{};
    std::atomic_bool save_pending{};
    double manual_teleport_x{}, manual_teleport_y{}, manual_teleport_z{};
    std::string manual_teleport_row;
    std::uint64_t landmarks_sequence{};
    std::vector<MapLandmark> landmarks;
    bool landmark_transfer_attempted{};
    bool landmark_transfer_wait{};
    double landmark_destination[3]{};
    double landmark_origin[2]{};
    double pending_target[3]{};
    std::chrono::steady_clock::time_point landmark_deadline{};
    std::chrono::steady_clock::time_point landmark_arrival_time{};
    bool navigating{};
    std::chrono::steady_clock::time_point navigation_last_progress_at{};
    std::chrono::steady_clock::time_point navigation_progress_check_at{};
    std::chrono::steady_clock::time_point navigation_retry_at{};
    double navigation_target[3]{};
    double navigation_last_position[3]{};
    bool navigation_has_last_position{};
};

void RebuildFilteredLocked(Context& context) {
    context.filtered_points.clear();
    if (context.type_choice == 0 || context.sub_choice == 0) {
        context.filtered_points = context.points;
    } else {
        const char* prefix = kVisionNames[context.sub_choice - 1];
        const std::size_t prefix_len = std::strlen(prefix);
        for (const Point& p : context.points) {
            if (p.row_name.compare(0, prefix_len, prefix) == 0) {
                context.filtered_points.push_back(p);
            }
        }
    }
}

template <typename Struct, typename Field>
bool HasField(const Struct* value, const std::size_t offset) noexcept {
    return value != nullptr && value->struct_size >= offset + sizeof(Field);
}

bool SignatureReady(const AnomalySignatureServiceV1* s) noexcept {
    return HasField<AnomalySignatureServiceV1,
               decltype(AnomalySignatureServiceV1::resolve)>(
               s, offsetof(AnomalySignatureServiceV1, resolve)) &&
        s->resolve != nullptr;
}

bool NamesReady(const AnomalyUe5NamesServiceV1* s) noexcept {
    return HasField<AnomalyUe5NamesServiceV1,
               decltype(AnomalyUe5NamesServiceV1::resolve_utf8)>(
               s, offsetof(AnomalyUe5NamesServiceV1, resolve_utf8)) &&
        s->resolve_utf8 != nullptr;
}

bool ObjectsReady(const AnomalyUe5ObjectsServiceV1* s) noexcept {
    return HasField<AnomalyUe5ObjectsServiceV1,
               decltype(AnomalyUe5ObjectsServiceV1::find_exact)>(
               s, offsetof(AnomalyUe5ObjectsServiceV1, find_exact)) &&
        s->find_exact != nullptr;
}

bool NavigationReady(const AnomalyNteNavigationServiceV1* s) noexcept {
    return HasField<AnomalyNteNavigationServiceV1,
               decltype(AnomalyNteNavigationServiceV1::move_to_location)>(
               s, offsetof(AnomalyNteNavigationServiceV1, move_to_location)) &&
        s->move_to_location != nullptr && s->stop_movement != nullptr;
}

bool DeveloperModeEnabled(const AnomalyUiServiceV1* ui) noexcept {
    return HasField<AnomalyUiServiceV1,
               decltype(AnomalyUiServiceV1::developer_mode_enabled)>(
               ui, offsetof(AnomalyUiServiceV1, developer_mode_enabled)) &&
        ui->developer_mode_enabled != nullptr &&
        ui->developer_mode_enabled(ui->user) != 0;
}

template <typename T>
bool Read(const void* address, T& value) noexcept {
    if (address == nullptr) return false;
    std::memcpy(&value, address, sizeof(T));
    return true;
}

void* ReadPointer(const void* address) noexcept {
    std::uintptr_t value{};
    return Read(address, value) ? reinterpret_cast<void*>(value) : nullptr;
}

bool ResolveRipRelative(
    const Context& context, const std::string_view pattern,
    const std::ptrdiff_t addend, std::uintptr_t& address) noexcept {
    address = 0;
    if (!SignatureReady(context.signature)) return false;
    std::uintptr_t instruction{};
    if (context.signature->resolve(
            context.signature->user, anomaly::sdk::StringView("HTGame.exe"),
            anomaly::sdk::StringView(".text"),
            anomaly::sdk::StringView(pattern), &instruction)
            .code != ANOMALY_STATUS_V1_OK ||
        instruction == 0) {
        return false;
    }
    std::int32_t displacement{};
    if (!Read(reinterpret_cast<const void*>(instruction + kRipDisplacementOffset),
              displacement)) {
        return false;
    }
    const auto resolved = static_cast<std::intptr_t>(instruction) +
        static_cast<std::intptr_t>(kRipInstructionSize) + displacement;
    if (resolved <= 0) return false;
    if (addend < 0) {
        const auto magnitude = static_cast<std::uintptr_t>(-(addend + 1)) + 1U;
        if (static_cast<std::uintptr_t>(resolved) <= magnitude) return false;
        address = static_cast<std::uintptr_t>(resolved) - magnitude;
    } else {
        address = static_cast<std::uintptr_t>(resolved) +
            static_cast<std::uintptr_t>(addend);
    }
    return address != 0;
}

void* ObjectAt(const std::uintptr_t g_objects, const std::uint32_t index) noexcept {
    std::int32_t count{};
    std::int32_t num_chunks{};
    std::uintptr_t items{};
    if (!Read(reinterpret_cast<const void*>(g_objects + kObjectItemsOffset), items) ||
        items == 0 ||
        !Read(reinterpret_cast<const void*>(g_objects + kObjectCountOffset), count) ||
        !Read(reinterpret_cast<const void*>(g_objects + kObjectNumChunksOffset),
              num_chunks) ||
        count <= 0 || index >= static_cast<std::uint32_t>(count) || num_chunks <= 0) {
        return nullptr;
    }
    const auto chunk_index = index / kObjectChunkSize;
    const auto within = index % kObjectChunkSize;
    if (chunk_index >= static_cast<std::uint32_t>(num_chunks)) return nullptr;
    const auto chunk = ReadPointer(reinterpret_cast<const void*>(
        items + static_cast<std::uintptr_t>(chunk_index) * sizeof(void*)));
    if (!chunk) return nullptr;
    return ReadPointer(reinterpret_cast<const std::uint8_t*>(chunk) +
        static_cast<std::uintptr_t>(within) * kObjectItemStride);
}

std::string ResolveName(
    const AnomalyUe5NamesServiceV1* names, const std::uint32_t name_id) {
    if (!NamesReady(names) || name_id == 0) return {};
    std::size_t size{};
    if (names->resolve_utf8(names->user, name_id, nullptr, &size).code !=
            ANOMALY_STATUS_V1_OK ||
        size <= 1 || size > kMaximumNameBytes) {
        return {};
    }
    std::string value(size, '\0');
    if (names->resolve_utf8(names->user, name_id, value.data(), &size).code !=
            ANOMALY_STATUS_V1_OK ||
        size <= 1 || size > value.size()) {
        return {};
    }
    value.resize(size - 1U);
    return value;
}

bool SnapshotPlayerPosition(Context& context, double (&position)[3]) noexcept {
    if (context.player == nullptr || context.player->snapshot == nullptr) {
        return false;
    }
    AnomalyNtePlayerSnapshotV1 snapshot{sizeof(snapshot)};
    if (context.player->snapshot(context.player->user, &snapshot).code !=
            ANOMALY_STATUS_V1_OK ||
        snapshot.handle.id == 0) {
        return false;
    }
    position[0] = snapshot.position[0];
    position[1] = snapshot.position[1];
    position[2] = snapshot.position[2];
    return true;
}

double PlanarDistanceSquared(double ax, double ay, double bx, double by) noexcept {
    const double dx = ax - bx;
    const double dy = ay - by;
    return dx * dx + dy * dy;
}

bool LandmarksReady(const AnomalyNteMapLandmarksServiceV1* s) noexcept {
    return HasField<AnomalyNteMapLandmarksServiceV1,
               decltype(AnomalyNteMapLandmarksServiceV1::teleport)>(
               s, offsetof(AnomalyNteMapLandmarksServiceV1, teleport)) &&
        s->sequence != nullptr && s->count != nullptr &&
        s->snapshot_at != nullptr && s->teleport != nullptr;
}

// Caller must hold context.mutex.
bool RefreshLandmarkCatalog(Context& context) noexcept {
    const auto* service = context.map_landmarks;
    if (!LandmarksReady(service)) return false;
    const std::uint64_t sequence = service->sequence(service->user);
    if (sequence == 0) return false;
    if (context.landmarks_sequence == sequence) return true;
    const std::uint32_t count = service->count(service->user);
    if (count > kMaximumMapLandmarks) return false;
    std::vector<MapLandmark> landmarks;
    landmarks.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        AnomalyNteMapLandmarkSnapshotV1 snapshot{sizeof(snapshot)};
        if (service->snapshot_at(service->user, index, &snapshot).code !=
                ANOMALY_STATUS_V1_OK ||
            snapshot.sequence != sequence ||
                (snapshot.flags & ANOMALY_NTE_MAP_LANDMARK_V1_VALID) == 0) {
            return false;
        }
        if (std::string_view(snapshot.world) != kLandmarkWorld) continue;
        if (!std::isfinite(snapshot.destination[0]) ||
            !std::isfinite(snapshot.destination[1]) ||
            !std::isfinite(snapshot.destination[2])) {
            continue;
        }
        MapLandmark landmark;
        landmark.sequence = sequence;
        landmark.index = index;
        landmark.destination[0] = snapshot.destination[0];
        landmark.destination[1] = snapshot.destination[1];
        landmark.destination[2] = snapshot.destination[2];
        landmark.teleport_id = snapshot.teleport_id;
        landmarks.push_back(std::move(landmark));
    }
    if (service->sequence(service->user) != sequence) return false;
    context.landmarks_sequence = sequence;
    context.landmarks = std::move(landmarks);
    return true;
}

// Caller must hold context.mutex.
bool TryBeginLandmarkTransfer(Context& context, const Point& target,
                              double player_x, double player_y) noexcept {
    if (context.landmark_transfer_attempted) return false;
    context.landmark_transfer_attempted = true;
    if (!RefreshLandmarkCatalog(context) || context.landmarks.empty()) {
        return false;
    }
    std::size_t nearest_index = 0;
    double nearest_distance = 1e300;
    for (std::size_t i = 0; i < context.landmarks.size(); ++i) {
        const double distance = PlanarDistanceSquared(
            context.landmarks[i].destination[0],
            context.landmarks[i].destination[1], target.x, target.y);
        if (distance < nearest_distance) {
            nearest_distance = distance;
            nearest_index = i;
        }
    }
    const double direct_distance =
        PlanarDistanceSquared(player_x, player_y, target.x, target.y);
    if (!(direct_distance > nearest_distance)) return false;
    const MapLandmark& nearest = context.landmarks[nearest_index];
    const auto* service = context.map_landmarks;
    if (!LandmarksReady(service) ||
        service->sequence(service->user) != nearest.sequence) {
        return false;
    }
    AnomalyNteMapLandmarkTeleportRequestV1 request{sizeof(request)};
    request.mode = ANOMALY_NTE_MAP_LANDMARK_TRANSFER_V1_NORMAL;
    request.sequence = nearest.sequence;
    request.index = nearest.index;
    if (service->teleport(service->user, &request).code != ANOMALY_STATUS_V1_OK) {
        return false;
    }
    context.landmark_destination[0] = nearest.destination[0];
    context.landmark_destination[1] = nearest.destination[1];
    context.landmark_destination[2] = nearest.destination[2];
    context.landmark_origin[0] = player_x;
    context.landmark_origin[1] = player_y;
    context.landmark_arrival_time = std::chrono::steady_clock::time_point{};
    context.landmark_transfer_wait = true;
    context.landmark_deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(static_cast<long long>(
            kLandmarkTransferTimeoutSeconds * 1000.0));
    return true;
}

std::string GetStateDirectory(const AnomalyPluginStateServiceV1* service) noexcept {
    if (service == nullptr || service->directory == nullptr) return {};
    std::size_t size{};
    if (service->directory(service->user, nullptr, &size).code != ANOMALY_STATUS_V1_OK ||
        size <= 1 || size > 4096) {
        return {};
    }
    std::string value(size, '\0');
    if (service->directory(service->user, value.data(), &size).code !=
            ANOMALY_STATUS_V1_OK ||
        size <= 1 || size > value.size()) {
        return {};
    }
    value.resize(size - 1U);
    return value;
}

void ReadTable(Context& context) {
    std::vector<Point> points;
    void* table_object{};
    if (!ObjectsReady(context.objects)) {
        std::lock_guard<std::mutex> lock(context.mutex);
        context.status = context.localizer.Text(
            "status.read_failed", "Read table failed");
        return;
    }
    AnomalyGenerationHandleV1 handle{};
    const auto st = context.objects->find_exact(
        context.objects->user, anomaly::sdk::StringView(kTablePath), &handle);
    if (st.code != ANOMALY_STATUS_V1_OK || handle.id == 0) {
        std::lock_guard<std::mutex> lock(context.mutex);
        context.status = context.localizer.Text(
            "status.read_failed", "Read table failed");
        return;
    }
    if (context.g_objects_address == 0 &&
        !ResolveRipRelative(context, kGObjectsPattern, kGObjectsAddend,
                            context.g_objects_address)) {
        std::lock_guard<std::mutex> lock(context.mutex);
        context.status = context.localizer.Text(
            "status.read_failed", "Read table failed");
        return;
    }
    const auto index = ANOMALY_UE5_OBJECT_HANDLE_INDEX(handle);
    table_object = ObjectAt(context.g_objects_address, index);
    if (table_object == nullptr) {
        std::lock_guard<std::mutex> lock(context.mutex);
        context.status = context.localizer.Text(
            "status.read_failed", "Read table failed");
        return;
    }
    struct ArrayHeader {
        std::uintptr_t data{};
        std::int32_t count{};
        std::int32_t capacity{};
    } header;
    if (!Read(reinterpret_cast<const void*>(
                  reinterpret_cast<std::uintptr_t>(table_object) + kDataTableRowMapOffset),
              header) ||
        header.count <= 0 || header.capacity < header.count || header.data == 0) {
        std::lock_guard<std::mutex> lock(context.mutex);
        context.status = context.localizer.Text(
            "status.read_failed", "Read table failed");
        return;
    }
    for (std::int32_t i = 0; i < header.count; ++i) {
        const auto element = header.data +
            static_cast<std::uintptr_t>(i) * kDataTableRowStride;
        RawName row_id{};
        std::uintptr_t row{};
        if (!Read(reinterpret_cast<const void*>(element), row_id) ||
            row_id.comparison_index == 0) continue;
        if (!Read(reinterpret_cast<const void*>(element + kDataTableRowPointerOffset),
                  row) || row == 0) continue;
        double x{}, y{}, z{};
        Read(reinterpret_cast<const void*>(row + kCoordOffset), x);
        Read(reinterpret_cast<const void*>(row + kCoordOffset + 8), y);
        Read(reinterpret_cast<const void*>(row + kCoordOffset + 16), z);
        if (x == 0.0 && y == 0.0 && z == 0.0) continue;
        Point p;
        p.row_name = ResolveName(
            context.names, static_cast<std::uint32_t>(row_id.comparison_index));
        p.x = x;
        p.y = y;
        p.z = z;
        points.push_back(std::move(p));
    }
    std::lock_guard<std::mutex> lock(context.mutex);
    context.points = std::move(points);
    RebuildFilteredLocked(context);
    const std::string count_str = std::to_string(context.points.size());
    const std::array read_args{std::string_view(count_str)};
    context.status = context.localizer.Format(
        "status.read", "Read {0} points", read_args);
}

bool Teleport(Context& context, const Point& p) noexcept {
    if (context.session == nullptr || context.player == nullptr ||
        context.teleport == nullptr || context.teleport->teleport == nullptr) {
        return false;
    }
    AnomalyNteSessionSnapshotV1 ss{sizeof(ss)};
    AnomalyNtePlayerSnapshotV1 ps{sizeof(ps)};
    if (context.session->snapshot(context.session->user, &ss).code != ANOMALY_STATUS_V1_OK ||
        context.player->snapshot(context.player->user, &ps).code != ANOMALY_STATUS_V1_OK) {
        return false;
    }
    if (ss.world.id == 0 || ps.handle.id == 0) return false;
    AnomalyNtePlayerTeleportRequestV1 request{sizeof(request)};
    request.flags = 0;
    request.world = ss.world;
    request.player = ps.handle;
    request.position[0] = p.x;
    request.position[1] = p.y;
    request.position[2] = p.z + kTeleportZOffset;
    return context.teleport->teleport(context.teleport->user, &request).code ==
        ANOMALY_STATUS_V1_OK;
}

bool IssueNavigation(Context& context, const Point& p) noexcept {
    if (!NavigationReady(context.navigation)) return false;
    double destination[3]{p.x, p.y, p.z};
    double player_position[3]{};
    if (SnapshotPlayerPosition(context, player_position)) {
        const double dx = player_position[0] - p.x;
        const double dy = player_position[1] - p.y;
        const double length = std::sqrt(dx * dx + dy * dy);
        if (length > 1.0) {
            destination[0] += dx * kApproachRadiusCentimeters / length;
            destination[1] += dy * kApproachRadiusCentimeters / length;
        }
    }
    return context.navigation->move_to_location(
        context.navigation->user, destination).code == ANOMALY_STATUS_V1_OK;
}

bool StartNavigation(Context& context, const Point& p,
                     std::chrono::steady_clock::time_point now) noexcept {
    if (!IssueNavigation(context, p)) return false;
    context.navigating = true;
    context.navigation_target[0] = p.x;
    context.navigation_target[1] = p.y;
    context.navigation_target[2] = p.z;
    context.navigation_has_last_position = false;
    context.navigation_last_progress_at = now;
    context.navigation_progress_check_at = now + std::chrono::milliseconds(
        static_cast<long long>(kProgressCheckIntervalSeconds * 1000.0));
    context.navigation_retry_at = now + std::chrono::milliseconds(
        static_cast<long long>(kReissueDelaySeconds * 1000.0));
    return true;
}

void LoadDoneSet(Context& context) {
    context.done_set.clear();
    if (context.state_directory.empty()) return;
    const std::string path = context.state_directory + "\\done.txt";
    std::FILE* file = std::fopen(path.c_str(), "rb");
    if (file == nullptr) return;
    std::string line;
    char buffer[1024];
    std::size_t n{};
    while ((n = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (std::size_t i = 0; i < n; ++i) {
            if (buffer[i] == '\n' || buffer[i] == '\r') {
                if (!line.empty()) context.done_set.insert(line);
                line.clear();
            } else {
                line.push_back(buffer[i]);
            }
        }
    }
    if (!line.empty()) context.done_set.insert(line);
    std::fclose(file);
}

void SaveDoneSet(Context& context) {
    if (context.state_directory.empty()) return;
    const std::string path = context.state_directory + "\\done.txt";
    std::FILE* file = std::fopen(path.c_str(), "wb");
    if (file == nullptr) return;
    for (const std::string& row : context.done_set) {
        std::fwrite(row.data(), 1, row.size(), file);
        std::fwrite("\n", 1, 1, file);
    }
    std::fclose(file);
}

void Draw(void* plugin_context, const AnomalyUiServiceV1* supplied_ui) {
    if (plugin_context == nullptr) return;
    auto& context = *static_cast<Context*>(plugin_context);
    const AnomalyUiServiceV1* ui = supplied_ui;
    if (ui == nullptr) {
        ui = anomaly::sdk::Host(context.host)
                 .Query<AnomalyUiServiceV1>(
                     ANOMALY_UI_SERVICE_V1_ID, ANOMALY_UI_SERVICE_V1_VERSION)
                 .get();
    }
    if (ui == nullptr || ui->text == nullptr || ui->button == nullptr) return;
    context.developer_mode.store(DeveloperModeEnabled(ui),
                                 std::memory_order_release);
    int open = 1;
    const std::string window_title =
        context.localizer.Text("window.title", "打怪资源点");
    anomaly::sdk::UiWindow window(ui, window_title, &open);
    if (!window) return;

    const std::string combat_label =
        context.localizer.Text("type.combat", "打怪宝箱（xx点的赠礼）");
    const std::string vision_label =
        context.localizer.Text("type.vision", "异像家具材料");
    if (ui->button(ui->user, anomaly::sdk::StringView(combat_label), 0.0F, 0.0F) != 0) {
        {
            std::lock_guard<std::mutex> lock(context.mutex);
            context.type_choice = 0;
            context.sub_choice = 0;
            context.points.clear();
            RebuildFilteredLocked(context);
            context.status = context.localizer.Text("status.combat_hint", "正在读表...");
        }
        context.read_pending.store(true, std::memory_order_release);
    }
    if (ui->same_line != nullptr) ui->same_line(ui->user, 0.0F, 4.0F);
    if (ui->button(ui->user, anomaly::sdk::StringView(vision_label), 0.0F, 0.0F) != 0) {
        std::lock_guard<std::mutex> lock(context.mutex);
        context.type_choice = 1;
        context.sub_choice = 0;
        context.points = VisionPoints();
        RebuildFilteredLocked(context);
        const std::string count_str = std::to_string(context.points.size());
        const std::array count_args{std::string_view(count_str)};
        context.status = context.localizer.Format("status.read", "Read {0} points", count_args);
    }
    ui->separator(ui->user);

    const std::string all_label = context.localizer.Text("sub.all", "全部");
    if (ui->button(ui->user, anomaly::sdk::StringView(all_label), 0.0F, 0.0F) != 0) {
        std::lock_guard<std::mutex> lock(context.mutex);
        context.sub_choice = 0;
        RebuildFilteredLocked(context);
    }
    if (context.type_choice == 1) {
        for (int i = 0; i < 6; ++i) {
            if (ui->same_line != nullptr) ui->same_line(ui->user, 0.0F, 4.0F);
            if (ui->button(ui->user, anomaly::sdk::StringView(kVisionNames[i]), 0.0F, 0.0F) != 0) {
                std::lock_guard<std::mutex> lock(context.mutex);
                context.sub_choice = static_cast<std::uint32_t>(i + 1);
                RebuildFilteredLocked(context);
            }
        }
    }
    ui->separator(ui->user);

    ui->separator(ui->user);

    std::string status;
    std::vector<Point> list;
    {
        std::lock_guard<std::mutex> lock(context.mutex);
        status = context.status;
        list = context.filtered_points;
    }
    if (!status.empty()) {
        ui->text(ui->user, anomaly::sdk::StringView(status));
    }
    const std::string done_str = std::to_string(context.done_set.size());
    const std::string total_str = std::to_string(list.size());
    const std::array done_args{
        std::string_view(done_str), std::string_view(total_str)};
    const std::string done_count = context.localizer.Format(
        "status.done_count", "Done {0}/{1}", done_args);
    ui->text(ui->user, anomaly::sdk::StringView(done_count));

    ui->separator(ui->user);
    if (ui->begin_child != nullptr && ui->end_child != nullptr) {
        ui->begin_child(ui->user, anomaly::sdk::StringView("list"), 0.0F, 400.0F, 0);
        const bool developer_mode =
            context.developer_mode.load(std::memory_order_acquire);
        const std::string tp_label = context.localizer.Text(
            developer_mode ? "action.teleport" : "action.navigate",
            developer_mode ? "TP" : "Walk");
        for (std::size_t i = 0; i < list.size(); ++i) {
            const Point& pt = list[i];
            const std::string tp_btn = tp_label + "##tp" + std::to_string(i);
            if (ui->button(ui->user, anomaly::sdk::StringView(tp_btn), 0.0F, 0.0F) != 0) {
                context.manual_teleport_x = pt.x;
                context.manual_teleport_y = pt.y;
                context.manual_teleport_z = pt.z;
                context.manual_teleport_row = pt.row_name;
                context.manual_teleport_pending.store(true, std::memory_order_release);
            }
            if (ui->same_line != nullptr) {
                ui->same_line(ui->user, 0.0F, 4.0F);
            }
            ui->text(ui->user, anomaly::sdk::StringView(pt.row_name));
            if (ui->same_line != nullptr) {
                ui->same_line(ui->user, 0.0F, 4.0F);
            }
            bool done = context.done_set.count(pt.row_name) > 0;
            int done_int = done ? 1 : 0;
            const std::string done_label = context.localizer.Text(
                done ? "action.unmark" : "action.mark_done",
                done ? "Unmark" : "Mark done");
            const std::string done_id =
                done_label + "##done" + std::to_string(i);
            if (ui->checkbox != nullptr &&
                ui->checkbox(ui->user, anomaly::sdk::StringView(done_id),
                             &done_int) != 0) {
                if (done_int != 0) {
                    context.done_set.insert(pt.row_name);
                } else {
                    context.done_set.erase(pt.row_name);
                }
                context.save_pending.store(true, std::memory_order_release);
            }
        }
        ui->end_child(ui->user);
    }
}

}  // namespace

AnomalyStatusV1 ANOMALY_CALL Load(const AnomalyHostApiV1* host, void** plugin_context) {
    if (!host || !plugin_context || host->api_major != ANOMALY_PLUGIN_API_V1_MAJOR) {
        return {ANOMALY_STATUS_V1_INVALID_ARGUMENT, 0, {nullptr, 0}};
    }
    auto* context = new (std::nothrow) Context{};
    if (!context) return {ANOMALY_STATUS_V1_FAILED, 0, {nullptr, 0}};
    context->host = host;
    const auto view = anomaly::sdk::Host(host);
    context->localizer = anomaly::plugins::Localizer(host);
    context->signature = view.Query<AnomalySignatureServiceV1>(
        ANOMALY_SIGNATURE_SERVICE_V1_ID, ANOMALY_SIGNATURE_SERVICE_V1_VERSION).get();
    context->names = view.Query<AnomalyUe5NamesServiceV1>(
        ANOMALY_UE5_NAMES_SERVICE_V1_ID, ANOMALY_UE5_NAMES_SERVICE_V1_VERSION).get();
    context->objects = view.Query<AnomalyUe5ObjectsServiceV1>(
        ANOMALY_UE5_OBJECTS_SERVICE_V1_ID, ANOMALY_UE5_OBJECTS_SERVICE_V1_VERSION).get();
    context->session = view.Query<AnomalyNteSessionServiceV1>(
        ANOMALY_NTE_SESSION_SERVICE_V1_ID, ANOMALY_NTE_SESSION_SERVICE_V1_VERSION).get();
    context->player = view.Query<AnomalyNtePlayerServiceV1>(
        ANOMALY_NTE_PLAYER_SERVICE_V1_ID, ANOMALY_NTE_PLAYER_SERVICE_V1_VERSION).get();
    context->teleport = view.Query<AnomalyNtePlayerTeleportServiceV1>(
        ANOMALY_NTE_PLAYER_TELEPORT_SERVICE_V1_ID,
        ANOMALY_NTE_PLAYER_TELEPORT_SERVICE_V1_VERSION).get();
    context->navigation = view.Query<AnomalyNteNavigationServiceV1>(
        ANOMALY_NTE_NAVIGATION_SERVICE_V1_ID,
        ANOMALY_NTE_NAVIGATION_SERVICE_V1_VERSION).get();
    context->map_landmarks = view.Query<AnomalyNteMapLandmarksServiceV1>(
        ANOMALY_NTE_MAP_LANDMARKS_SERVICE_V1_ID,
        ANOMALY_NTE_MAP_LANDMARKS_SERVICE_V1_VERSION).get();
    context->plugin_state = view.Query<AnomalyPluginStateServiceV1>(
        ANOMALY_PLUGIN_STATE_SERVICE_V1_ID,
        ANOMALY_PLUGIN_STATE_SERVICE_V1_VERSION).get();
    context->state_directory = GetStateDirectory(context->plugin_state);
    if (!SignatureReady(context->signature) || !NamesReady(context->names) ||
        !ObjectsReady(context->objects)) {
        delete context;
        return {ANOMALY_STATUS_V1_UNAVAILABLE, 0, {nullptr, 0}};
    }
    *plugin_context = context;
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Start(void* plugin_context) {
    if (!plugin_context) {
        return {ANOMALY_STATUS_V1_INVALID_ARGUMENT, 0, {nullptr, 0}};
    }
    auto& context = *static_cast<Context*>(plugin_context);
    LoadDoneSet(context);
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Stop(void* plugin_context, std::uint32_t) {
    if (!plugin_context) {
        return {ANOMALY_STATUS_V1_INVALID_ARGUMENT, 0, {nullptr, 0}};
    }
    return anomaly::sdk::Ok();
}

void ANOMALY_CALL Unload(void* plugin_context) {
    delete static_cast<Context*>(plugin_context);
}

void ANOMALY_CALL Update(void* plugin_context, const double) {
    if (!plugin_context) return;
    auto& context = *static_cast<Context*>(plugin_context);
    const auto now = std::chrono::steady_clock::now();

    if (context.read_pending.exchange(false, std::memory_order_acq_rel)) {
        ReadTable(context);
    }

    if (context.landmark_transfer_wait) {
        double position[3]{};
        const bool have_position = SnapshotPlayerPosition(context, position);
        const bool arrived = have_position &&
            PlanarDistanceSquared(position[0], position[1],
                context.landmark_destination[0],
                context.landmark_destination[1]) <=
                kLandmarkArrivalRadiusCentimeters *
                    kLandmarkArrivalRadiusCentimeters;
        if (arrived && context.landmark_arrival_time ==
                           std::chrono::steady_clock::time_point{}) {
            context.landmark_arrival_time = now;
        }
        const bool settled =
            context.landmark_arrival_time !=
                std::chrono::steady_clock::time_point{} &&
            now - context.landmark_arrival_time >=
                std::chrono::milliseconds(static_cast<long long>(
                    kLandmarkSettleSeconds * 1000.0));
        if (settled || now >= context.landmark_deadline) {
            context.landmark_transfer_wait = false;
            context.landmark_arrival_time = std::chrono::steady_clock::time_point{};
            Point p;
            p.x = context.pending_target[0];
            p.y = context.pending_target[1];
            p.z = context.pending_target[2];
            p.row_name = context.manual_teleport_row;
            if (StartNavigation(context, p, now)) {
                std::lock_guard<std::mutex> lock(context.mutex);
                const std::array nav_args{std::string_view(p.row_name)};
                context.status = context.localizer.Format(
                    "status.navigating", "Walking [{0}]", nav_args);
            } else {
                std::lock_guard<std::mutex> lock(context.mutex);
                context.status = context.localizer.Text(
                    "status.navigation_failed", "Walk failed");
            }
        }
    }

    if (context.navigating) {
        double position[3]{};
        const bool have_position = SnapshotPlayerPosition(context, position);
        bool arrived = false;
        if (have_position) {
            const double distance_squared = PlanarDistanceSquared(
                position[0], position[1],
                context.navigation_target[0], context.navigation_target[1]);
            arrived = distance_squared <=
                kArrivalRadiusCentimeters * kArrivalRadiusCentimeters;
        }
        if (now >= context.navigation_progress_check_at) {
            if (have_position) {
                if (context.navigation_has_last_position) {
                    const double moved = std::sqrt(PlanarDistanceSquared(
                        position[0], position[1],
                        context.navigation_last_position[0],
                        context.navigation_last_position[1]));
                    if (moved >= kProgressThresholdCentimeters) {
                        context.navigation_last_progress_at = now;
                        context.navigation_retry_at = now + std::chrono::milliseconds(
                            static_cast<long long>(kReissueDelaySeconds * 1000.0));
                    }
                }
                context.navigation_last_position[0] = position[0];
                context.navigation_last_position[1] = position[1];
                context.navigation_last_position[2] = position[2];
                context.navigation_has_last_position = true;
            }
            context.navigation_progress_check_at = now +
                std::chrono::milliseconds(static_cast<long long>(
                    kProgressCheckIntervalSeconds * 1000.0));
        }
        if (arrived) {
            context.navigation->stop_movement(context.navigation->user);
            context.navigating = false;
            std::lock_guard<std::mutex> lock(context.mutex);
            const std::array arrived_args{
                std::string_view(context.manual_teleport_row)};
            context.status = context.localizer.Format(
                "status.arrived", "Arrived [{0}]", arrived_args);
        } else if (now - context.navigation_last_progress_at >=
                   std::chrono::milliseconds(static_cast<long long>(
                       kMovementTimeoutSeconds * 1000.0))) {
            context.navigation->stop_movement(context.navigation->user);
            context.navigating = false;
            std::lock_guard<std::mutex> lock(context.mutex);
            context.status = context.localizer.Text(
                "status.navigation_timeout", "Walk timeout");
        } else {
            if (now >= context.navigation_retry_at) {
                context.navigation_retry_at = now + std::chrono::milliseconds(
                    static_cast<long long>(kReissueDelaySeconds * 1000.0));
                context.navigation->stop_movement(context.navigation->user);
                Point p;
                p.x = context.pending_target[0];
                p.y = context.pending_target[1];
                p.z = context.pending_target[2];
                p.row_name = context.manual_teleport_row;
                if (!IssueNavigation(context, p)) {
                    context.navigating = false;
                    std::lock_guard<std::mutex> lock(context.mutex);
                    context.status = context.localizer.Text(
                        "status.navigation_failed", "Walk failed");
                }
            }
            if (context.navigating && have_position) {
                const double distance_cm = std::sqrt(PlanarDistanceSquared(
                    position[0], position[1],
                    context.navigation_target[0], context.navigation_target[1]));
                const std::string distance_str =
                    std::to_string(static_cast<long long>(distance_cm));
                const std::array distance_args{
                    std::string_view(distance_str),
                    std::string_view(context.manual_teleport_row)};
                std::lock_guard<std::mutex> lock(context.mutex);
                context.status = context.localizer.Format(
                    "status.navigating_distance", "Walking {0}cm [{1}]",
                    distance_args);
            }
        }
    }

    if (context.manual_teleport_pending.exchange(false, std::memory_order_acq_rel)) {
        Point p;
        p.x = context.manual_teleport_x;
        p.y = context.manual_teleport_y;
        p.z = context.manual_teleport_z;
        p.row_name = context.manual_teleport_row;
        context.pending_target[0] = p.x;
        context.pending_target[1] = p.y;
        context.pending_target[2] = p.z;
        context.landmark_transfer_attempted = false;
        context.landmark_transfer_wait = false;
        if (context.navigating && NavigationReady(context.navigation)) {
            context.navigation->stop_movement(context.navigation->user);
        }
        context.navigating = false;
        context.navigation_has_last_position = false;
        if (context.developer_mode.load(std::memory_order_acquire)) {
            if (!Teleport(context, p)) {
                std::lock_guard<std::mutex> lock(context.mutex);
                context.status = context.localizer.Text(
                    "status.teleport_failed", "Teleport failed");
            }
        } else if (NavigationReady(context.navigation)) {
            double player_position[3]{};
            const bool have_player = SnapshotPlayerPosition(context, player_position);
            bool landmark_started = false;
            if (have_player) {
                landmark_started = TryBeginLandmarkTransfer(
                    context, p, player_position[0], player_position[1]);
            }
            if (landmark_started) {
                std::lock_guard<std::mutex> lock(context.mutex);
                context.status = context.localizer.Text(
                    "status.landmark_transfer", "Fast travel");
            } else if (StartNavigation(context, p, now)) {
                std::lock_guard<std::mutex> lock(context.mutex);
                const std::array nav_args{std::string_view(p.row_name)};
                context.status = context.localizer.Format(
                    "status.navigating", "Walking [{0}]", nav_args);
            } else {
                std::lock_guard<std::mutex> lock(context.mutex);
                context.status = context.localizer.Text(
                    "status.teleport_failed", "Teleport failed");
            }
        } else {
            std::lock_guard<std::mutex> lock(context.mutex);
            context.status = context.localizer.Text(
                "status.navigation_unavailable", "Navigation unavailable");
        }
    }
    if (context.save_pending.exchange(false, std::memory_order_acq_rel)) {
        SaveDoneSet(context);
    }
}

ANOMALY_SDK_EXPORT AnomalyStatusV1 ANOMALY_CALL AnomalyPluginEntryV1(
    AnomalyPluginDescriptorV1* descriptor) {
    if (!descriptor || descriptor->struct_size < sizeof(*descriptor)) {
        return {ANOMALY_STATUS_V1_INVALID_ARGUMENT, 0, {nullptr, 0}};
    }
    *descriptor = {
        sizeof(*descriptor), ANOMALY_PLUGIN_API_V1_MAJOR, ANOMALY_PLUGIN_API_V1_MINOR,
        anomaly::sdk::StringView("anomaly.local.combat-box"),
        anomaly::sdk::StringView("打怪资源点"),
        anomaly::sdk::StringView("CCYellowStar"),
        anomaly::sdk::StringView("0.1.0"), Load, Start, Stop, Unload, Update, Draw};
    return anomaly::sdk::Ok();
}
