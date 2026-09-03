#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shobjidl.h>
#include <combaseapi.h>
#include <objbase.h>
#include <shlwapi.h>
#include <wrl/client.h>
#include <filesystem>
#include <fstream>
using Microsoft::WRL::ComPtr;
#include "anomaly/sdk/cpp.hpp"
#include "anomaly/sdk/services/core.h"
#include "anomaly/sdk/services/interop.h"
#include "anomaly/sdk/services/platform.h"
#include "anomaly/sdk/services/ue5.h"
#include "anomaly/sdk/services/ui.h"
#include <nlohmann/json.hpp>
#include "better_pose_profile.hpp"
#include "../common/localization.hpp"

#include <atomic>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace better_pose_profile;

constexpr std::string_view kPoseSettingsSchemaId =
    "anomaly.builtin.character-pose.settings";
constexpr std::uint32_t kPoseSettingsSchemaVersion = 1;
constexpr std::size_t kMaximumPoseSettingsBytes = 1U << 20;
constexpr std::string_view kPoseExportPath = "pose-export.json";
constexpr std::string_view kPoseProfileDirectory = "character-pose/profiles/";
constexpr std::string_view kPoseSettingsSchema = R"json(
{
  "type": "object",
  "additionalProperties": false,
  "required": ["bones"],
  "properties": {
    "rootOffset": {
      "type": "array",
      "minItems": 3,
      "maxItems": 3,
      "items": {"type": "number"}
    },
    "bones": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["index", "pitch", "yaw", "roll"],
        "properties": {
          "index": {"type": "integer", "minimum": 0},
          "pitch": {"type": "number", "minimum": -180.0, "maximum": 180.0},
          "yaw": {"type": "number", "minimum": -180.0, "maximum": 180.0},
          "roll": {"type": "number", "minimum": -180.0, "maximum": 180.0}
        }
      }
    }
  }
}
)json";

struct RuntimeState {
  std::uintptr_t g_world_address{};
  std::uintptr_t character{};
  std::uintptr_t mesh{};
  std::uintptr_t anim_instance{};
  std::uint32_t animation_mode{};
  std::uint8_t animation_flags{};
  std::uint32_t bone_space_count{};
  std::uintptr_t bone_space_data{};
  std::uint32_t component_space_count{};
  std::uintptr_t component_space_data{};
  std::uint32_t local_space_count{};
  std::uintptr_t local_space_data{};
  float rate_scale{1.0F};
  float root_motion_scale{1.0F};

  bool saved_rate{};
  float original_rate_scale{1.0F};
  bool saved_root_motion{};
  float original_root_motion_scale{1.0F};
  bool saved_pause{};
  std::uint8_t original_animation_flags{};
  bool saved_forced_lod{};
  bool forced_lod_applied{};
  std::int32_t original_forced_lod{};
  bool saved_animation_mode{};
  bool animation_mode_applied{};
  std::uint8_t original_animation_mode{};
  bool saved_multi_threaded_update{};
  std::uint8_t original_multi_threaded_update_flags{};
  std::uintptr_t multi_threaded_update_instance{};

  bool saved_pose{};
  std::uint32_t pose_bone_index{};
  std::array<double, 3> original_translation{};
  std::array<double, 3> original_component_translation{};
  std::uintptr_t pose_mesh{};
  std::uintptr_t pose_data{};
  std::uint32_t pose_count{};
  std::uintptr_t pose_component_data{};
  std::uint32_t pose_component_count{};
  std::vector<std::uint32_t> pose_descendants{};
};

struct ObjectRegistry {
  std::uintptr_t items{};
  std::uint32_t count{};
  std::uint32_t max_count{};
  std::uint32_t max_chunks{};
  std::uint32_t num_chunks{};
};

struct RenderSnapshot {
  bool active{};
  std::uintptr_t character{};
  std::uintptr_t mesh{};
  std::uintptr_t anim_instance{};
  std::uint32_t animation_mode{};
  std::uint32_t bone_space_count{};
  std::uintptr_t bone_space_data{};
  std::uint32_t component_space_count{};
  std::uintptr_t component_space_data{};
  float rate_scale{1.0F};
  float root_motion_scale{1.0F};
  bool pose_available{};
  std::vector<std::string> bone_names;
  std::array<char, 256> status{};
  std::array<char, 256> reflection_status{};
  std::array<char, 256> pose_status{};
  std::uint32_t pose_bone_index{};
  std::array<double, 3> component_translation_readback{};
  std::array<double, 3> bone_translation_readback{};
};

struct Context final {
  const AnomalyHostApiV1 *host{};
  anomaly::plugins::Localizer localizer;
  const AnomalyCoreServiceV1 *core{};
  const AnomalySignatureServiceV1 *signature{};
  const AnomalyUe5NamesServiceV1 *names{};
  const AnomalyUe5ObjectsServiceV1 *objects{};
  const AnomalyUiServiceV1 *ui{};
  const AnomalyHookServiceV1 *hook{};
  const AnomalyConfigServiceV1 *config{};
  const AnomalyStorageServiceV1 *storage{};
  const AnomalySchedulerServiceV1 *scheduler{};

  std::mutex state_mutex;
  std::mutex pose_angles_mutex;
  RenderSnapshot snapshot;
  RuntimeState runtime;
  AnomalyGenerationHandleV1 settings_schema{};
  std::vector<std::array<double, 3>> bone_angles;
  std::vector<std::array<double, 12>> pose_base_locals;
  std::uintptr_t pose_base_mesh{};
  bool pose_base_ready{};
  std::atomic_bool pose_settings_dirty{};
  std::uintptr_t g_objects_address{};
  ObjectRegistry object_registry{};
  std::string reflection_status{"reflection idle"};
  std::array<char, 256> pose_status{};
  std::vector<std::string> bone_names;
  std::vector<std::int32_t> bone_parents;
  std::uintptr_t bone_parents_mesh{};
  std::uint32_t bone_parents_count{};
  bool bone_parents_ready{};
  std::uintptr_t bone_names_mesh{};
  std::uint32_t bone_names_count{};
  bool bone_names_attempted{};
  std::array<char, 128> bone_filter{};

  std::atomic_bool freeze_enabled{};
  std::atomic_bool rate_override_enabled{};
  std::atomic_bool root_motion_override_enabled{};
  std::atomic_bool pose_override_enabled{};
  AnomalyGenerationHandleV1 tick_hook{};
  std::uintptr_t tick_original{};
  std::uintptr_t tick_target{};
  std::atomic<std::uint32_t> reflection_action_requested{0};
  std::atomic<float> requested_rate_scale{1.0F};
  std::atomic<float> requested_root_motion_scale{1.0F};
  std::atomic<std::uint32_t> requested_bone_index{0};
  std::array<std::atomic<double>, 3> requested_translation{};
  std::array<std::atomic<double>, 3> requested_root_offset{};
  std::array<std::atomic<double>, 3> edited_translation{};
  std::atomic_bool pose_reset_requested{};
  std::atomic<std::uint32_t> pose_file_action_requested{0};
  std::string active_character_id;
  bool character_profiles_initialized{};
  std::array<char, 128> pose_export_name{};
  std::string pose_export_folder;
  std::string pose_import_file;
};

std::atomic<Context *> g_active{};

AnomalyStatusV1 Status(const std::uint32_t code,
                       const std::string_view message = {}) noexcept {
  return {code, 0, {message.data(), message.size()}};
}

template <typename Struct, typename Field>
bool HasField(const Struct *value, const std::size_t offset) noexcept {
  return value != nullptr && value->struct_size >= offset + sizeof(Field);
}

template <typename Service>
const Service *Query(const AnomalyHostApiV1 *host, const char *id,
                     const std::uint32_t version) noexcept {
  return anomaly::sdk::Host(host).Query<Service>(id, version).get();
}

bool CoreReady(const AnomalyCoreServiceV1 *service) noexcept {
  return HasField<AnomalyCoreServiceV1,
                  decltype(AnomalyCoreServiceV1::read_memory)>(
             service, offsetof(AnomalyCoreServiceV1, read_memory)) &&
         HasField<AnomalyCoreServiceV1,
                  decltype(AnomalyCoreServiceV1::write_memory)>(
             service, offsetof(AnomalyCoreServiceV1, write_memory)) &&
         service->read_memory != nullptr && service->write_memory != nullptr;
}

bool SignatureReady(const AnomalySignatureServiceV1 *service) noexcept {
  return HasField<AnomalySignatureServiceV1,
                  decltype(AnomalySignatureServiceV1::resolve)>(
             service, offsetof(AnomalySignatureServiceV1, resolve)) &&
         service->resolve != nullptr;
}

bool UiReady(const AnomalyUiServiceV1 *service) noexcept {
  return HasField<AnomalyUiServiceV1,
                  decltype(AnomalyUiServiceV1::input_double)>(
             service, offsetof(AnomalyUiServiceV1, input_double)) &&
         service->set_next_window_size != nullptr &&
         service->begin_window != nullptr && service->end_window != nullptr &&
         service->text != nullptr && service->checkbox != nullptr &&
         service->slider_float != nullptr && service->input_double != nullptr &&
         service->separator != nullptr && service->button != nullptr &&
         service->same_line != nullptr;
}

bool HookReady(const AnomalyHookServiceV1 *service) noexcept {
  return HasField<AnomalyHookServiceV1,
                  decltype(AnomalyHookServiceV1::end_callback)>(
             service, offsetof(AnomalyHookServiceV1, end_callback)) &&
         service->create != nullptr && service->release != nullptr &&
         service->begin_callback != nullptr && service->end_callback != nullptr;
}

bool ConfigReady(const AnomalyConfigServiceV1 *service) noexcept {
  return HasField<AnomalyConfigServiceV1,
                  decltype(AnomalyConfigServiceV1::write_atomic)>(
             service, offsetof(AnomalyConfigServiceV1, write_atomic)) &&
         service->register_schema != nullptr && service->read != nullptr &&
         service->write_atomic != nullptr &&
         service->unregister_schema != nullptr;
}

bool StorageReady(const AnomalyStorageServiceV1 *service) noexcept {
  return service != nullptr && service->read != nullptr &&
         service->write_atomic != nullptr;
}

bool SchedulerReady(const AnomalySchedulerServiceV1 *service) noexcept {
  return service != nullptr && service->schedule != nullptr;
}

AnomalyByteSpanV1 Bytes(const std::string_view value) noexcept {
  return {reinterpret_cast<const std::uint8_t *>(value.data()), value.size()};
}

void EnsurePoseAngleCapacity(Context &context) noexcept {
  std::lock_guard<std::mutex> lock(context.pose_angles_mutex);
  const auto count = context.runtime.local_space_count;
  if (context.bone_angles.size() < count)
    context.bone_angles.resize(count);
}

bool ApplyPoseDocument(Context &context, const nlohmann::json &json) noexcept {
  try {
    if (!json.is_object() || !json.contains("bones") ||
        !json.at("bones").is_array())
      return false;
    std::vector<std::array<double, 3>> loaded;
    for (const auto &item : json.at("bones")) {
      if (!item.is_object() || !item.contains("index") ||
          !item.contains("pitch") || !item.contains("yaw") ||
          !item.contains("roll"))
        return false;
      const auto index = item.at("index").get<std::uint64_t>();
      if (index >= kMaximumBoneIndex)
        return false;
      auto pitch = item.at("pitch").get<double>();
      auto yaw = item.at("yaw").get<double>();
      auto roll = item.at("roll").get<double>();
      const auto normalize_angle = [](double value) {
        while (value > 180.0)
          value -= 360.0;
        while (value <= -180.0)
          value += 360.0;
        return value;
      };
      pitch = normalize_angle(pitch);
      yaw = normalize_angle(yaw);
      roll = normalize_angle(roll);
      if (pitch < -180.0 || pitch > 180.0 || yaw < -180.0 || yaw > 180.0 ||
          roll < -180.0 || roll > 180.0)
        return false;
      if (loaded.size() <= index)
        loaded.resize(static_cast<std::size_t>(index) + 1);
      loaded[static_cast<std::size_t>(index)] = {pitch, yaw, roll};
    }
    std::array<double, 3> root_offset{};
    if (json.contains("rootOffset")) {
      if (!json.at("rootOffset").is_array() || json.at("rootOffset").size() != 3)
        return false;
      for (std::size_t index{}; index != 3; ++index) {
        if (!json.at("rootOffset").at(index).is_number())
          return false;
        root_offset[index] = json.at("rootOffset").at(index).get<double>();
      }
    }
    std::lock_guard<std::mutex> lock(context.pose_angles_mutex);
    context.bone_angles = std::move(loaded);
    context.requested_root_offset[0].store(root_offset[0], std::memory_order_release);
    context.requested_root_offset[1].store(root_offset[1], std::memory_order_release);
    context.requested_root_offset[2].store(root_offset[2], std::memory_order_release);
    return true;
  } catch (...) {
    return false;
  }
}

std::string BuildPoseDocument(Context &context) noexcept {
  nlohmann::json root = nlohmann::json::object();
  auto bones = nlohmann::json::array();
  {
    std::lock_guard<std::mutex> lock(context.pose_angles_mutex);
    for (std::size_t index{}; index != context.bone_angles.size(); ++index) {
      const auto &angle = context.bone_angles[index];
      if (angle[0] == 0.0 && angle[1] == 0.0 && angle[2] == 0.0)
        continue;
      bones.push_back({{"index", index},
                       {"pitch", angle[0]},
                       {"yaw", angle[1]},
                       {"roll", angle[2]}});
    }
  }
  std::array<double, 3> root_offset{};
  root_offset[0] = context.requested_root_offset[0].load(std::memory_order_acquire);
  root_offset[1] = context.requested_root_offset[1].load(std::memory_order_acquire);
  root_offset[2] = context.requested_root_offset[2].load(std::memory_order_acquire);
  root["bones"] = std::move(bones);
  root["rootOffset"] = root_offset;
  return root.dump();
}

std::string PoseProfilePath(const std::string &character_id) noexcept {
  return "character-pose-profile-" + character_id + ".json";
}

bool PersistPoseSettings(Context &context) noexcept {
  if (!ConfigReady(context.config))
    return false;
  try {
    const std::string document = BuildPoseDocument(context);
    if (document.size() > kMaximumPoseSettingsBytes)
      return false;
    const auto config_status = context.config->write_atomic(
        context.config->user, anomaly::sdk::StringView(kPoseSettingsSchemaId),
        kPoseSettingsSchemaVersion, Bytes(document));
    bool profile_ok = true;
    if (!context.active_character_id.empty() && StorageReady(context.storage)) {
      const std::string path = PoseProfilePath(context.active_character_id);
      profile_ok =
          context.storage
              ->write_atomic(context.storage->user,
                             anomaly::sdk::StringView(path), Bytes(document))
              .code == ANOMALY_STATUS_V1_OK;
    }
    return config_status.code == ANOMALY_STATUS_V1_OK && profile_ok;
  } catch (...) {
    return false;
  }
}

int LoadCharacterPoseProfile(Context &context,
                             const std::string &character_id) noexcept {
  if (!StorageReady(context.storage))
    return -1;
  const std::string path = PoseProfilePath(character_id);
  std::size_t size{};
  const auto probe = context.storage->read(
      context.storage->user, anomaly::sdk::StringView(path), {nullptr, 0},
      &size);
  if (probe.code == ANOMALY_STATUS_V1_NOT_FOUND)
    return 0;
  if (probe.code != ANOMALY_STATUS_V1_OK || size == 0 ||
      size > kMaximumPoseSettingsBytes)
    return -1;
  std::string document(size, '\0');
  std::size_t copied = size;
  if (context.storage
          ->read(context.storage->user, anomaly::sdk::StringView(path),
                 {reinterpret_cast<std::uint8_t *>(document.data()),
                  document.size()},
                 &copied)
          .code != ANOMALY_STATUS_V1_OK ||
      copied == 0 || copied > document.size())
    return -1;
  try {
    const auto json =
        nlohmann::json::parse(document.begin(), document.begin() + copied);
    return ApplyPoseDocument(context, json) ? 1 : -1;
  } catch (...) {
    return -1;
  }
}

void ResetPoseValues(Context &context) noexcept {
  {
    std::lock_guard<std::mutex> lock(context.pose_angles_mutex);
    for (auto &angle : context.bone_angles)
      angle = {0.0, 0.0, 0.0};
  }
  context.requested_root_offset[0].store(0.0, std::memory_order_release);
  context.requested_root_offset[1].store(0.0, std::memory_order_release);
  context.requested_root_offset[2].store(0.0, std::memory_order_release);
}

bool LoadPoseSettings(Context &context) noexcept {
  if (!ConfigReady(context.config))
    return false;
  try {
    std::uint32_t version{};
    std::size_t size{};
    const auto probe = context.config->read(
        context.config->user, anomaly::sdk::StringView(kPoseSettingsSchemaId),
        &version, {nullptr, 0}, &size);
    if (probe.code == ANOMALY_STATUS_V1_NOT_FOUND) {
      {
        std::lock_guard<std::mutex> lock(context.pose_angles_mutex);
        context.bone_angles.clear();
      }
      return PersistPoseSettings(context);
    }
    if (probe.code != ANOMALY_STATUS_V1_OK ||
        version != kPoseSettingsSchemaVersion || size == 0 ||
        size > kMaximumPoseSettingsBytes)
      return false;
    std::string document(size, '\0');
    std::size_t copied = size;
    if (context.config
            ->read(context.config->user,
                   anomaly::sdk::StringView(kPoseSettingsSchemaId), &version,
                   {reinterpret_cast<std::uint8_t *>(document.data()),
                    document.size()},
                   &copied)
            .code != ANOMALY_STATUS_V1_OK ||
        copied == 0 || copied > document.size())
      return false;
    const auto json =
        nlohmann::json::parse(document.begin(), document.begin() + copied);
    return ApplyPoseDocument(context, json);
  } catch (...) {
    return false;
  }
}
bool ObjectsReady(const AnomalyUe5ObjectsServiceV1 *service) noexcept {
  return HasField<AnomalyUe5ObjectsServiceV1,
                  decltype(AnomalyUe5ObjectsServiceV1::find_exact)>(
             service, offsetof(AnomalyUe5ObjectsServiceV1, find_exact)) &&
         service->find_exact != nullptr;
}

bool NamesReady(const AnomalyUe5NamesServiceV1 *service) noexcept {
  return HasField<AnomalyUe5NamesServiceV1,
                  decltype(AnomalyUe5NamesServiceV1::resolve_utf8)>(
             service, offsetof(AnomalyUe5NamesServiceV1, resolve_utf8)) &&
         service->resolve_utf8 != nullptr;
}

bool AddAddress(const std::uintptr_t base, const std::uint64_t offset,
                std::uintptr_t &result) noexcept {
  if (base == 0 || offset > (std::numeric_limits<std::uintptr_t>::max)() - base)
    return false;
  result = base + static_cast<std::uintptr_t>(offset);
  return true;
}

template <typename T>
bool Read(Context &context, const std::uintptr_t address, T &value) noexcept {
  if (!CoreReady(context.core) || address == 0)
    return false;
  AnomalyMutableByteSpanV1 destination{
      reinterpret_cast<std::uint8_t *>(&value), sizeof(value)};
  return context.core->read_memory(context.core->user, address, destination)
             .code == ANOMALY_STATUS_V1_OK;
}

template <typename T>
bool Write(Context &context, const std::uintptr_t address,
           const T &value) noexcept {
  if (!CoreReady(context.core) || address == 0)
    return false;
  const AnomalyByteSpanV1 source{
      reinterpret_cast<const std::uint8_t *>(&value), sizeof(value)};
  return context.core->write_memory(context.core->user, address, source).code ==
         ANOMALY_STATUS_V1_OK;
}

bool ReadPointerAt(Context &context, const std::uintptr_t base,
                   const std::uint32_t offset,
                   std::uintptr_t &value) noexcept {
  std::uintptr_t address{};
  return AddAddress(base, offset, address) && Read(context, address, value) &&
         value != 0;
}

bool ResolveSignature(Context &context, const std::string_view pattern,
                      std::uintptr_t &address) noexcept {
  address = 0;
  return SignatureReady(context.signature) &&
         context.signature
                 ->resolve(context.signature->user,
                           anomaly::sdk::StringView("HTGame.exe"),
                           anomaly::sdk::StringView(".text"),
                           anomaly::sdk::StringView(pattern), &address)
                 .code == ANOMALY_STATUS_V1_OK &&
         address != 0;
}

bool ResolveGWorld(Context &context) noexcept {
  std::uintptr_t instruction{};
  std::int32_t displacement{};
  if (!ResolveSignature(context, kGWorldPattern, instruction) ||
      !Read(context, instruction + kGWorldResolveOffset, displacement))
    return false;
  const auto resolved = static_cast<std::intptr_t>(instruction) +
                        kGWorldInstructionSize + displacement;
  if (resolved <= 0)
    return false;
  context.runtime.g_world_address = static_cast<std::uintptr_t>(resolved);
  return true;
}

bool ResolveLocalCharacter(Context &context) noexcept {
  context.runtime.character = 0;
  context.runtime.mesh = 0;
  context.runtime.anim_instance = 0;
  std::uintptr_t world{};
  std::uintptr_t game_instance{};
  std::uintptr_t local_players{};
  std::uintptr_t local_player{};
  std::uintptr_t controller{};
  std::uintptr_t character{};
  std::uintptr_t mesh{};
  if (!Read(context, context.runtime.g_world_address, world) ||
      !ReadPointerAt(context, world, kWorldGameInstanceOffset, game_instance) ||
      !ReadPointerAt(context, game_instance, kGameInstanceLocalPlayersOffset,
                     local_players) ||
      !Read(context, local_players, local_player) || local_player == 0 ||
      !ReadPointerAt(context, local_player, kLocalPlayerControllerOffset,
                     controller) ||
      !ReadPointerAt(context, controller, kControllerPawnOffset, character) ||
      !ReadPointerAt(context, character, kCharacterMeshOffset, mesh)) {
    return false;
  }
  context.runtime.character = character;
  context.runtime.mesh = mesh;
  return true;
}

bool ReadAnimationState(Context &context) noexcept {
  const auto mesh = context.runtime.mesh;
  if (mesh == 0)
    return false;
  std::uint8_t animation_mode{};
  std::uint8_t animation_flags{};
  if (!Read(context, mesh + kMeshAnimationModeOffset, animation_mode) ||
      !Read(context, mesh + kMeshAnimationFlagsOffset, animation_flags))
    return false;
  static_cast<void>(Read(context, mesh + kMeshAnimScriptInstanceOffset,
                        context.runtime.anim_instance));
  context.runtime.animation_mode = animation_mode;
  context.runtime.animation_flags = animation_flags;
  return true;
}

bool ReadArrayHeader(Context &context, const std::uintptr_t array_address,
                     std::uintptr_t &data, std::uint32_t &count) noexcept {
  data = 0;
  count = 0;
  if (array_address == 0)
    return false;
  std::int32_t count_value{};
  if (!Read(context, array_address + kArrayDataOffset, data) ||
      !Read(context, array_address + kArrayCountOffset, count_value) ||
      count_value < 0)
    return false;
  count = static_cast<std::uint32_t>(count_value);
  return true;
}

bool ReadPoseArrays(Context &context) noexcept {
  const auto mesh = context.runtime.mesh;
  if (mesh == 0)
    return false;
  std::uintptr_t bone_space_data{};
  std::uint32_t bone_space_count{};
  std::uintptr_t component_space_data{};
  std::uint32_t component_space_count{};
  std::uintptr_t local_space_data{};
  std::uint32_t local_space_count{};
  const bool authoritative =
      ReadArrayHeader(context, mesh + kMeshBoneSpaceTransformsOffset,
                      bone_space_data, bone_space_count) &&
      ReadArrayHeader(context, mesh + kMeshComponentSpaceTransformsOffset,
                      component_space_data, component_space_count) &&
      ReadArrayHeader(context, mesh + kMeshLocalSpaceTransformsOffset,
                      local_space_data, local_space_count) &&
      bone_space_data != 0 && bone_space_count != 0 &&
      component_space_data != 0 && component_space_count != 0 &&
      local_space_data != 0 && local_space_count != 0 &&
      bone_space_count == component_space_count &&
      component_space_count == local_space_count;
  if (authoritative) {
    context.runtime.bone_space_data = bone_space_data;
    context.runtime.bone_space_count = bone_space_count;
    context.runtime.component_space_data = component_space_data;
    context.runtime.component_space_count = component_space_count;
    context.runtime.local_space_data = local_space_data;
    context.runtime.local_space_count = local_space_count;
    return true;
  }
  static_cast<void>(ReadArrayHeader(
      context, mesh + kMeshCachedBoneSpaceTransformsOffset,
      context.runtime.bone_space_data, context.runtime.bone_space_count));
  return ReadArrayHeader(
      context, mesh + kMeshCachedComponentSpaceTransformsOffset,
      context.runtime.component_space_data,
      context.runtime.component_space_count);
}

bool RestorePause(Context &context) noexcept {
  RuntimeState &state = context.runtime;
  if (!state.saved_pause || state.mesh == 0)
    return true;
  if (!Write(context, state.mesh + kMeshAnimationFlagsOffset,
             state.original_animation_flags))
    return false;
  state.saved_pause = false;
  state.animation_flags = state.original_animation_flags;
  return true;
}

bool ApplyPause(Context &context, const bool enabled) noexcept {
  RuntimeState &state = context.runtime;
  if (state.mesh == 0)
    return false;
  if (!enabled)
    return RestorePause(context);
  if (state.saved_pause)
    return true;
  std::uint8_t flags{};
  if (!Read(context, state.mesh + kMeshAnimationFlagsOffset, flags))
    return false;
  state.original_animation_flags = flags;
  flags |= static_cast<std::uint8_t>(1U << kAnimationFlagPauseAnimsBit);
  if (!Write(context, state.mesh + kMeshAnimationFlagsOffset, flags))
    return false;
  state.saved_pause = true;
  state.animation_flags = flags;
  return true;
}

bool RestoreRate(Context &context) noexcept {
  RuntimeState &state = context.runtime;
  if (!state.saved_rate || state.mesh == 0)
    return true;
  if (!Write(context, state.mesh + kMeshGlobalAnimRateScaleOffset,
             state.original_rate_scale))
    return false;
  state.saved_rate = false;
  return true;
}

bool ApplyRate(Context &context, const bool enabled, const float value) noexcept {
  RuntimeState &state = context.runtime;
  if (state.mesh == 0)
    return false;
  if (!enabled)
    return RestoreRate(context);
  if (!state.saved_rate) {
    float original{};
    if (!Read(context, state.mesh + kMeshGlobalAnimRateScaleOffset, original))
      return false;
    state.original_rate_scale = original;
    state.saved_rate = true;
  }
  return Write(context, state.mesh + kMeshGlobalAnimRateScaleOffset, value);
}

bool RestoreRootMotion(Context &context) noexcept {
  RuntimeState &state = context.runtime;
  if (!state.saved_root_motion || state.character == 0)
    return true;
  if (!Write(context, state.character + kCharacterAnimRootMotionScaleOffset,
             state.original_root_motion_scale))
    return false;
  state.saved_root_motion = false;
  return true;
}

bool ApplyRootMotion(Context &context, const bool enabled,
                     const float value) noexcept {
  RuntimeState &state = context.runtime;
  if (state.character == 0)
    return false;
  if (!enabled)
    return RestoreRootMotion(context);
  if (!state.saved_root_motion) {
    float original{};
    if (!Read(context, state.character + kCharacterAnimRootMotionScaleOffset,
              original))
      return false;
    state.original_root_motion_scale = original;
    state.saved_root_motion = true;
  }
  return Write(context, state.character + kCharacterAnimRootMotionScaleOffset,
               value);
}

bool RestoreMultiThreadedUpdate(Context &context) noexcept {
  RuntimeState &state = context.runtime;
  if (!state.saved_multi_threaded_update || state.anim_instance == 0)
    return true;
  if (state.multi_threaded_update_instance != state.anim_instance) {
    state.saved_multi_threaded_update = false;
    return true;
  }
  if (!Write(context, state.anim_instance + kAnimInstanceUseMultiThreadedUpdateOffset,
             state.original_multi_threaded_update_flags))
    return false;
  state.saved_multi_threaded_update = false;
  state.multi_threaded_update_instance = 0;
  return true;
}

bool ApplyMultiThreadedUpdate(Context &context, const bool enabled) noexcept {
  RuntimeState &state = context.runtime;
  if (!enabled)
    return RestoreMultiThreadedUpdate(context);
  if (state.anim_instance == 0)
    return false;
  if (state.saved_multi_threaded_update &&
      state.multi_threaded_update_instance != state.anim_instance) {
    state.saved_multi_threaded_update = false;
  }
  if (!state.saved_multi_threaded_update) {
    std::uint8_t flags{};
    if (!Read(context, state.anim_instance + kAnimInstanceUseMultiThreadedUpdateOffset,
              flags))
      return false;
    state.original_multi_threaded_update_flags = flags;
    state.saved_multi_threaded_update = true;
    state.multi_threaded_update_instance = state.anim_instance;
  }
  std::uint8_t flags = state.original_multi_threaded_update_flags;
  flags &= static_cast<std::uint8_t>(
      ~(1U << kAnimInstanceUseMultiThreadedUpdateBit));
  return Write(context, state.anim_instance + kAnimInstanceUseMultiThreadedUpdateOffset,
               flags);
}

bool RestorePose(Context &context) noexcept {
  RuntimeState &state = context.runtime;
  if (!state.saved_pose)
    return true;
  state.pose_descendants.clear();
  state.saved_pose = false;
  return true;
}

bool CallVirtualUFunction(Context &context, std::uintptr_t object,
                          std::string_view function_path, const void *parameters,
                          std::size_t parameter_size, std::string &detail,
                          void *output = nullptr) noexcept;
bool ApplyPoseByName(Context &context, std::uint32_t bone,
                     const std::array<double, 3> &translation,
                     std::string &detail) noexcept;

bool ForcePoseMeshObjectUpdate(Context &context) noexcept {
  const auto mesh = context.runtime.mesh;
  if (mesh == 0)
    return false;
  std::uint8_t flags{};
  if (!Read(context, mesh + kMeshForceMeshObjectUpdateOffset, flags))
    return false;
  flags |= static_cast<std::uint8_t>(1U << kMeshForceMeshObjectUpdateBit);
  return Write(context, mesh + kMeshForceMeshObjectUpdateOffset, flags);
}

struct Vec3d {
  double x{};
  double y{};
  double z{};
};

struct Quatd {
  double x{};
  double y{};
  double z{};
  double w{1.0};
};

struct Transformd {
  Quatd rotation{};
  Vec3d translation{};
  Vec3d scale{1.0, 1.0, 1.0};
};

Quatd QuatMultiply(const Quatd &a, const Quatd &b) noexcept {
  Quatd out;
  out.x = a.w * b.x + a.x * b.w + a.y * b.z - a.z * b.y;
  out.y = a.w * b.y - a.x * b.z + a.y * b.w + a.z * b.x;
  out.z = a.w * b.z + a.x * b.y - a.y * b.x + a.z * b.w;
  out.w = a.w * b.w - a.x * b.x - a.y * b.y - a.z * b.z;
  return out;
}

Vec3d QuatRotateVector(const Quatd &q, const Vec3d &v) noexcept {
  const Vec3d u{q.x, q.y, q.z};
  const Vec3d uv{
      u.y * v.z - u.z * v.y,
      u.z * v.x - u.x * v.z,
      u.x * v.y - u.y * v.x,
  };
  const Vec3d uuv{
      u.y * uv.z - u.z * uv.y,
      u.z * uv.x - u.x * uv.z,
      u.x * uv.y - u.y * uv.x,
  };
  const double two = 2.0;
  return Vec3d{
      v.x + two * (q.w * uv.x + uuv.x),
      v.y + two * (q.w * uv.y + uuv.y),
      v.z + two * (q.w * uv.z + uuv.z),
  };
}

Transformd TransformMultiply(const Transformd &a,
                             const Transformd &b) noexcept {
  Transformd out;
  out.rotation = QuatMultiply(a.rotation, b.rotation);
  const Vec3d scaled{
      b.translation.x * a.scale.x,
      b.translation.y * a.scale.y,
      b.translation.z * a.scale.z,
  };
  const Vec3d rotated = QuatRotateVector(a.rotation, scaled);
  out.translation = Vec3d{
      a.translation.x + rotated.x,
      a.translation.y + rotated.y,
      a.translation.z + rotated.z,
  };
  out.scale = Vec3d{
      a.scale.x * b.scale.x,
      a.scale.y * b.scale.y,
      a.scale.z * b.scale.z,
  };
  return out;
}

Quatd RotatorToQuat(const double pitch_degrees, const double yaw_degrees,
                    const double roll_degrees) noexcept {
  constexpr double kDegreesToRadians = 3.14159265358979323846 / 180.0;
  const double half = kDegreesToRadians * 0.5;
  const double sp = std::sin(pitch_degrees * half);
  const double cp = std::cos(pitch_degrees * half);
  const double sy = std::sin(yaw_degrees * half);
  const double cy = std::cos(yaw_degrees * half);
  const double sr = std::sin(roll_degrees * half);
  const double cr = std::cos(roll_degrees * half);
  Quatd out;
  out.x = cr * sp * sy - sr * cp * cy;
  out.y = -cr * sp * cy - sr * cp * sy;
  out.z = cr * cp * sy - sr * sp * cy;
  out.w = cr * cp * cy + sr * sp * sy;
  return out;
}

bool ReadTransform(Context &context, const std::uintptr_t address,
                   Transformd &transform) noexcept {
  if (!Read(context, address + kTransformRotationOffset, transform.rotation) ||
      !Read(context, address + kTransformTranslationOffset,
            transform.translation) ||
      !Read(context, address + kTransformScaleOffset, transform.scale))
    return false;
  return true;
}

bool WriteTransform(Context &context, const std::uintptr_t address,
                    const Transformd &transform) noexcept {
  return Write(context, address + kTransformRotationOffset,
               transform.rotation) &&
         Write(context, address + kTransformTranslationOffset,
               transform.translation) &&
         Write(context, address + kTransformScaleOffset, transform.scale);
}

struct PackedTransform {
  double rotation[4]{};
  double translation[3]{};
  double padding{};
  double scale[3]{1.0, 1.0, 1.0};
  double tail_padding{};
};

static_assert(sizeof(PackedTransform) == kTransformSize,
              "PackedTransform must match the game FTransform layout");

void PackTransform(const Transformd &source, PackedTransform &destination) noexcept {
  destination.rotation[0] = source.rotation.x;
  destination.rotation[1] = source.rotation.y;
  destination.rotation[2] = source.rotation.z;
  destination.rotation[3] = source.rotation.w;
  destination.translation[0] = source.translation.x;
  destination.translation[1] = source.translation.y;
  destination.translation[2] = source.translation.z;
  destination.padding = 0.0;
  destination.scale[0] = source.scale.x;
  destination.scale[1] = source.scale.y;
  destination.scale[2] = source.scale.z;
}

bool WriteBytes(Context &context, const std::uintptr_t address,
                const void *data, const std::size_t size) noexcept {
  if (!CoreReady(context.core) || address == 0 || data == nullptr || size == 0)
    return false;
  const AnomalyByteSpanV1 source{
      reinterpret_cast<const std::uint8_t *>(data), size};
  return context.core->write_memory(context.core->user, address, source).code ==
         ANOMALY_STATUS_V1_OK;
}

Transformd ComputeBoneComponent(
    const std::uint32_t bone_index,
    const std::vector<Transformd> &locals,
    const std::vector<std::int32_t> &parents,
    std::vector<Transformd> &components,
    std::vector<std::uint8_t> &marks) noexcept {
  if (marks[bone_index] == 2)
    return components[bone_index];
  if (marks[bone_index] == 1)
    return {};
  marks[bone_index] = 1;
  Transformd parent_component;
  const std::int32_t parent = parents[bone_index];
  if (parent >= 0 && static_cast<std::uint32_t>(parent) < parents.size())
    parent_component =
        ComputeBoneComponent(static_cast<std::uint32_t>(parent), locals,
                             parents, components, marks);
  components[bone_index] =
      TransformMultiply(parent_component, locals[bone_index]);
  marks[bone_index] = 2;
  return components[bone_index];
}

void ApplyPoseOverridesInTick(Context &context) noexcept {
  RuntimeState &state = context.runtime;
  if (!context.pose_override_enabled.load(std::memory_order_acquire) ||
      state.mesh == 0 || state.local_space_data == 0 || state.pose_data == 0 ||
      state.pose_component_data == 0 || state.local_space_count == 0 ||
      state.pose_count != state.local_space_count ||
      state.pose_component_count != state.local_space_count)
    return;

  const std::uint32_t count = state.local_space_count;
  std::vector<std::array<double, 3>> angles;
  {
    std::lock_guard<std::mutex> lock(context.pose_angles_mutex);
    if (context.bone_angles.size() < count)
      return;
    angles.assign(context.bone_angles.begin(),
                  context.bone_angles.begin() + count);
  }
  if (context.bone_parents.size() != count)
    return;

  bool any_override = false;
  for (const auto &angle : angles) {
    if (angle[0] != 0.0 || angle[1] != 0.0 || angle[2] != 0.0) {
      any_override = true;
      break;
    }
  }
  if (!any_override)
    return;

  std::vector<Transformd> locals(count);
  for (std::uint32_t bone_index{}; bone_index != count; ++bone_index) {
    std::uintptr_t local_address{};
    if (!AddAddress(state.local_space_data,
                    static_cast<std::uint64_t>(bone_index) * kTransformSize,
                    local_address) ||
        !ReadTransform(context, local_address, locals[bone_index]))
      return;
    if (angles[bone_index][0] != 0.0 || angles[bone_index][1] != 0.0 ||
        angles[bone_index][2] != 0.0) {
      const Quatd offset =
          RotatorToQuat(angles[bone_index][0], angles[bone_index][1],
                        angles[bone_index][2]);
      locals[bone_index].rotation =
          QuatMultiply(offset, locals[bone_index].rotation);
    }
  }

  std::vector<Transformd> components(count);
  std::vector<std::uint8_t> marks(count, 0);
  for (std::uint32_t bone_index{}; bone_index != count; ++bone_index)
    static_cast<void>(ComputeBoneComponent(bone_index, locals,
                                           context.bone_parents, components,
                                           marks));

  std::vector<PackedTransform> packed(count);
  for (std::uint32_t bone_index{}; bone_index != count; ++bone_index)
    PackTransform(components[bone_index], packed[bone_index]);

  const auto *bytes = reinterpret_cast<const std::uint8_t *>(packed.data());
  const auto byte_count = packed.size() * sizeof(PackedTransform);
  static_cast<void>(WriteBytes(context, state.pose_data, bytes, byte_count));
  static_cast<void>(
      WriteBytes(context, state.pose_component_data, bytes, byte_count));
  static_cast<void>(ForcePoseMeshObjectUpdate(context));
}

bool BuildPoseDescendants(Context &context, const std::uint32_t bone,
                          std::vector<std::uint32_t> &descendants) noexcept {
  descendants.clear();
  const auto count = context.runtime.local_space_count;
  if (bone >= count)
    return false;
  descendants.push_back(bone);
  if (context.bone_parents.size() != count)
    return false;
  std::vector<std::vector<std::uint32_t>> children(count);
  for (std::uint32_t index{}; index != count; ++index) {
    const std::int32_t parent = context.bone_parents[index];
    if (parent >= 0 && static_cast<std::uint32_t>(parent) < count)
      children[static_cast<std::uint32_t>(parent)].push_back(index);
  }
  for (std::size_t cursor{}; cursor != descendants.size(); ++cursor) {
    const auto parent = descendants[cursor];
    for (const std::uint32_t child : children[parent])
      descendants.push_back(child);
  }
  return true;
}

bool ApplyPose(Context &context, const bool enabled, const std::uint32_t bone,
               const std::array<double, 3> &rotation) noexcept {
  RuntimeState &state = context.runtime;
  if (state.mesh == 0 || state.bone_space_data == 0 ||
      state.bone_space_count == 0 || bone >= state.bone_space_count ||
      state.component_space_data == 0 || state.component_space_count == 0 ||
      bone >= state.component_space_count || state.local_space_data == 0 ||
      state.local_space_count == 0 || bone >= state.local_space_count)
    return false;
  if (!enabled)
    return RestorePose(context);

  const bool same_bone = state.saved_pose && state.pose_bone_index == bone &&
                         state.pose_mesh == state.mesh &&
                         state.pose_data == state.bone_space_data &&
                         state.pose_component_data == state.component_space_data;
  if (!same_bone) {
    if (state.saved_pose && !RestorePose(context))
      return false;
    std::vector<std::uint32_t> descendants;
    if (!BuildPoseDescendants(context, bone, descendants) ||
        descendants.empty())
      return false;
    state.saved_pose = true;
    state.pose_mesh = state.mesh;
    state.pose_data = state.bone_space_data;
    state.pose_count = state.bone_space_count;
    state.pose_component_data = state.component_space_data;
    state.pose_component_count = state.component_space_count;
    state.pose_bone_index = bone;
    state.pose_descendants = std::move(descendants);
  }

  std::snprintf(context.pose_status.data(), context.pose_status.size(),
                "pose: joint=%u pitch=%.2f yaw=%.2f roll=%.2f bones=%u",
                static_cast<unsigned>(bone), rotation[0], rotation[1],
                rotation[2],
                static_cast<unsigned>(state.pose_descendants.size()));
  return true;
}

bool ResolvePoseTickTarget(Context &context, std::uintptr_t &target) noexcept {
  target = 0;
  const auto mesh = context.runtime.mesh;
  if (mesh == 0)
    return false;
  std::uintptr_t vtable{};
  if (!Read(context, mesh, vtable) || vtable == 0)
    return false;
  std::uintptr_t function{};
  const std::uint64_t slot_address =
      static_cast<std::uint64_t>(kSkeletalMeshTickVtableSlot) * sizeof(void *);
  if (slot_address > (std::numeric_limits<std::uintptr_t>::max)() - vtable ||
      !Read(context, vtable + static_cast<std::uintptr_t>(slot_address),
            function) ||
      function == 0)
    return false;
  if (function < 0x140000000ULL || function > 0x180000000ULL)
    return false;
  target = function;
  return true;
}

void ANOMALY_CALL SkeletalMeshTickDetour(void *object, float delta_seconds,
                                         unsigned tick_type,
                                         void *tick_function) noexcept;
void ApplyPoseOverridesDirect(Context &context) noexcept;

bool ReleasePoseTickHook(Context &context) noexcept {
  if (!HookReady(context.hook) || context.tick_hook.id == 0)
    return true;
  const auto status =
      context.hook->release(context.hook->user, context.tick_hook);
  if (status.code != ANOMALY_STATUS_V1_OK) {
    return false;
  }
  context.tick_hook = {};
  context.tick_original = 0;
  context.tick_target = 0;
  g_active.store(nullptr, std::memory_order_release);
  return true;
}

bool EnsurePoseTickHook(Context &context) noexcept {
  if (!HookReady(context.hook))
    return false;
  std::uintptr_t target{};
  if (!ResolvePoseTickTarget(context, target))
    return false;
  if (context.tick_hook.id != 0 && context.tick_target == target &&
      context.tick_original != 0)
    return true;
  if (context.tick_hook.id != 0) {
    if (!ReleasePoseTickHook(context))
      return false;
  }
  g_active.store(&context, std::memory_order_release);
  AnomalyHookRequestV1 request{sizeof(request)};
  request.kind = ANOMALY_HOOK_V1_FUNCTION;
  request.target = target;
  request.detour = reinterpret_cast<void *>(&SkeletalMeshTickDetour);
  request.label = anomaly::sdk::StringView("character-pose-skeletal-tick");
  std::uintptr_t original{};
  AnomalyGenerationHandleV1 handle{};
  const auto status =
      context.hook->create(context.hook->user, &request, &original, &handle);
  if (status.code != ANOMALY_STATUS_V1_OK || handle.id == 0 || original == 0) {
    g_active.store(nullptr, std::memory_order_release);
    context.tick_hook = {};
    context.tick_original = 0;
    context.tick_target = 0;
    return false;
  }
  context.tick_hook = handle;
  context.tick_original = original;
  context.tick_target = target;
  return true;
}

using SkeletalMeshTickFn = void(ANOMALY_CALL *)(void *, float, unsigned, void *);

void ANOMALY_CALL SkeletalMeshTickDetour(void *object, float delta_seconds,
                                         unsigned tick_type,
                                         void *tick_function) noexcept {
  Context *context = g_active.load(std::memory_order_acquire);
  AnomalyGenerationHandleV1 lease{};
  bool leased = false;
  SkeletalMeshTickFn original = nullptr;
  try {
    if (context != nullptr && context->tick_hook.id != 0 &&
        HookReady(context->hook)) {
      leased = context->hook
                   ->begin_callback(context->hook->user, context->tick_hook,
                                    &lease)
                   .code == ANOMALY_STATUS_V1_OK;
      original = reinterpret_cast<SkeletalMeshTickFn>(context->tick_original);
    }
  } catch (...) {
    original = context == nullptr
                   ? nullptr
                   : reinterpret_cast<SkeletalMeshTickFn>(context->tick_original);
  }

  try {
    if (original != nullptr)
      original(object, delta_seconds, tick_type, tick_function);
  } catch (...) {
  }

  try {
    if (context != nullptr && context->pose_override_enabled.load(
                                      std::memory_order_acquire) &&
        object == reinterpret_cast<void *>(context->runtime.mesh)) {
      ApplyPoseOverridesDirect(*context);
    }
  } catch (...) {
  }

  if (leased && context != nullptr && HookReady(context->hook)) {
    static_cast<void>(context->hook->end_callback(context->hook->user, lease));
  }
}

bool ResolveGObjects(Context &context) noexcept {
  std::uintptr_t instruction{};
  std::int32_t displacement{};
  if (!ResolveSignature(context, kGObjectsPattern, instruction) ||
      !Read(context, instruction + kGObjectsResolveOffset, displacement))
    return false;
  const auto resolved = static_cast<std::intptr_t>(instruction) +
                        kGObjectsInstructionSize + displacement +
                        kGObjectsAddend;
  if (resolved <= 0)
    return false;
  context.g_objects_address = static_cast<std::uintptr_t>(resolved);
  return true;
}

bool RefreshObjectRegistry(Context &context) noexcept {
  if (context.object_registry.items != 0)
    return true;
  if (context.g_objects_address == 0 && !ResolveGObjects(context))
    return false;
  ObjectRegistry next{};
  std::uint32_t count{};
  std::uint32_t max_count{};
  std::uint32_t max_chunks{};
  std::uint32_t num_chunks{};
  if (!ReadPointerAt(context, context.g_objects_address, kObjectItemsOffset,
                     next.items) ||
      !Read(context, context.g_objects_address + kObjectCountOffset, count) ||
      !Read(context, context.g_objects_address + kObjectMaxCountOffset,
            max_count) ||
      !Read(context, context.g_objects_address + kObjectMaxChunksOffset,
            max_chunks) ||
      !Read(context, context.g_objects_address + kObjectNumChunksOffset,
            num_chunks) ||
      count == 0 || max_count < count || max_chunks < num_chunks ||
      num_chunks == 0 || num_chunks > 4096)
    return false;
  next.count = count;
  next.max_count = max_count;
  next.max_chunks = max_chunks;
  next.num_chunks = num_chunks;
  context.object_registry = next;
  return true;
}

bool FindObjectAddressByPath(Context &context, const std::string_view path,
                             std::uintptr_t &object,
                             std::string *detail = nullptr) noexcept {
  object = 0;
  if (!ObjectsReady(context.objects) || path.empty()) {
    if (detail != nullptr) *detail = "object service or path unavailable";
    return false;
  }
  if (!RefreshObjectRegistry(context)) {
    if (detail != nullptr) *detail = "GObjects registry unavailable";
    return false;
  }
  AnomalyGenerationHandleV1 handle{};
  auto find = [&](const std::string_view candidate) {
    handle = {};
    return context.objects
               ->find_exact(context.objects->user,
                            anomaly::sdk::StringView(candidate), &handle)
               .code == ANOMALY_STATUS_V1_OK &&
           handle.id != 0;
  };
  if (!find(path)) {
    std::string alternate(path);
    const auto separator = alternate.rfind('.');
    if (separator == std::string::npos) {
      if (detail != nullptr) *detail = "exact object lookup failed";
      return false;
    }
    alternate[separator] = ':';
    if (!find(alternate)) {
      if (detail != nullptr) *detail = "exact object lookup failed";
      return false;
    }
  }
  if (handle.id == 0) {
    if (detail != nullptr) *detail = "exact object handle is invalid";
    return false;
  }
  const std::uint32_t index = ANOMALY_UE5_OBJECT_HANDLE_INDEX(handle);
  if (index >= context.object_registry.count) {
    if (detail != nullptr) *detail = "exact object index is out of range";
    return false;
  }
  const std::uint32_t chunk_index = index / kObjectChunkSize;
  const std::uint32_t within_chunk = index % kObjectChunkSize;
  if (chunk_index >= context.object_registry.num_chunks) {
    if (detail != nullptr) *detail = "exact object chunk is out of range";
    return false;
  }
  std::uintptr_t chunk{};
  if (!ReadPointerAt(context, context.object_registry.items,
                     static_cast<std::uint32_t>(chunk_index * sizeof(void *)),
                     chunk) ||
      !ReadPointerAt(context, chunk,
                     static_cast<std::uint32_t>(within_chunk) *
                         kObjectItemStride,
                     object)) {
    if (detail != nullptr) *detail = "exact object slot is unreadable";
    return false;
  }
  if (object == 0) {
    if (detail != nullptr) *detail = "exact object slot is null";
    return false;
  }
  return true;
}

std::string Hex(const std::uintptr_t value) noexcept;

bool ResolveName(Context &context, const std::uint32_t name_id,
                 std::string &value) noexcept {
  value.clear();
  if (!NamesReady(context.names) || name_id == 0)
    return false;
  std::array<char, 128> local{};
  std::size_t size = local.size();
  AnomalyStatusV1 status = context.names->resolve_utf8(
      context.names->user, name_id, local.data(), &size);
  if (status.code == ANOMALY_STATUS_V1_OK && size > 1 && size <= local.size()) {
    value.assign(local.data(), size - 1U);
    return true;
  }
  if (status.code != ANOMALY_STATUS_V1_BUFFER_TOO_SMALL || size <= 1 ||
      size > 2048)
    return false;
  std::string buffer(size, '\0');
  status = context.names->resolve_utf8(context.names->user, name_id,
                                       buffer.data(), &size);
  if (status.code != ANOMALY_STATUS_V1_OK || size <= 1 || size > buffer.size())
    return false;
  buffer.resize(size - 1U);
  value = std::move(buffer);
  return true;
}

bool CallVirtualUFunction(Context &context, const std::uintptr_t object,
                          const std::string_view function_path,
                          const void *parameters,
                          const std::size_t parameter_size,
                          std::string &detail,
                          void *output) noexcept {
  detail.clear();
  if (object == 0 || function_path.empty() ||
      parameter_size > kMaximumUFunctionParameterBytes ||
      (parameter_size != 0 && parameters == nullptr)) {
    detail = "invalid object, path, or parameters";
    return false;
  }
  std::uintptr_t function{};
  if (!FindObjectAddressByPath(context, function_path, function, &detail)) {
    detail.insert(0, "find function failed: ");
    return false;
  }
  std::uintptr_t vtable{};
  if (!Read(context, object, vtable) || vtable == 0) {
    detail = "read object vtable failed";
    return false;
  }
  std::uintptr_t process_event{};
  if (!Read(context,
            vtable + static_cast<std::uint64_t>(kProcessEventVtableSlot) *
                        sizeof(void *),
            process_event) ||
      process_event == 0) {
    detail = "ProcessEvent vtable slot is unreadable";
    return false;
  }

  using ProcessEventFn = void(__fastcall *)(void *, void *, void *);
  std::array<std::uint8_t, kMaximumUFunctionParameterBytes> buffer{};
  if (parameter_size != 0)
    std::memcpy(buffer.data(), parameters, parameter_size);
  const auto invoke = reinterpret_cast<ProcessEventFn>(process_event);
  invoke(reinterpret_cast<void *>(object), reinterpret_cast<void *>(function),
         parameter_size != 0 ? buffer.data() : nullptr);
  if (output != nullptr && parameter_size != 0)
    std::memcpy(output, buffer.data(), parameter_size);
  detail = "ok function=" + Hex(function) + " process_event=" + Hex(process_event);
  return true;
}

bool GetBoneNameFName(Context &context, const std::uint32_t bone_index,
                      std::array<std::uint8_t, 8> &name) noexcept {
  name.fill(0);
  if (context.runtime.mesh == 0)
    return false;
  std::array<std::uint8_t, 12> parameters{};
  const std::int32_t index = static_cast<std::int32_t>(bone_index);
  std::memcpy(parameters.data(), &index, sizeof(index));
  std::array<std::uint8_t, 12> output{};
  std::string detail;
  if (!CallVirtualUFunction(context, context.runtime.mesh, kFunctionGetBoneNamePath,
                            parameters.data(), parameters.size(), detail,
                            output.data()))
    return false;
  std::memcpy(name.data(), output.data() + 4, name.size());
  return true;
}

bool GetParentBoneFName(Context &context,
                        const std::array<std::uint8_t, 8> &child,
                        std::array<std::uint8_t, 8> &parent) noexcept {
  parent.fill(0);
  if (context.runtime.mesh == 0)
    return false;
  std::array<std::uint8_t, 16> parameters{};
  std::memcpy(parameters.data(), child.data(), child.size());
  std::array<std::uint8_t, 16> output{};
  std::string detail;
  if (!CallVirtualUFunction(context, context.runtime.mesh,
                            kFunctionGetParentBonePath, parameters.data(),
                            parameters.size(), detail, output.data()))
    return false;
  std::memcpy(parent.data(), output.data() + 8, parent.size());
  return true;
}

bool GetBoneIndexFName(Context &context,
                       const std::array<std::uint8_t, 8> &name,
                       std::int32_t &index) noexcept {
  index = -1;
  if (context.runtime.mesh == 0)
    return false;
  std::array<std::uint8_t, 12> parameters{};
  std::memcpy(parameters.data(), name.data(), name.size());
  std::array<std::uint8_t, 12> output{};
  std::string detail;
  if (!CallVirtualUFunction(context, context.runtime.mesh,
                            kFunctionGetBoneIndexPath, parameters.data(),
                            parameters.size(), detail, output.data()))
    return false;
  std::memcpy(&index, output.data() + 8, sizeof(index));
  return true;
}

void RefreshBoneHierarchy(Context &context) noexcept {
  const auto count = context.runtime.local_space_count;
  context.bone_parents.assign(count, -1);
  if (context.bone_names.size() != count)
    return;
  for (std::uint32_t index{}; index != count; ++index) {
    std::array<std::uint8_t, 8> child_fname{};
    if (!GetBoneNameFName(context, index, child_fname))
      continue;
    std::array<std::uint8_t, 8> parent_fname{};
    if (!GetParentBoneFName(context, child_fname, parent_fname))
      continue;
    std::uint32_t parent_name_id{};
    std::memcpy(&parent_name_id, parent_fname.data(), sizeof(parent_name_id));
    std::string parent_name;
    if (!ResolveName(context, parent_name_id, parent_name))
      continue;
    const auto it = std::find(context.bone_names.begin(),
                              context.bone_names.end(), parent_name);
    if (it != context.bone_names.end())
      context.bone_parents[index] =
          static_cast<std::int32_t>(it - context.bone_names.begin());
  }
}

void RefreshBoneHierarchyDirect(Context &context) noexcept {
  const auto count = context.runtime.local_space_count;
  if (count == 0)
    return;
  if (context.bone_parents_ready &&
      context.bone_parents_mesh == context.runtime.mesh &&
      context.bone_parents_count == count)
    return;
  context.bone_parents.assign(count, -1);
  for (std::uint32_t index{}; index != count; ++index) {
    std::array<std::uint8_t, 8> child_fname{};
    if (!GetBoneNameFName(context, index, child_fname))
      continue;
    std::array<std::uint8_t, 8> parent_fname{};
    if (!GetParentBoneFName(context, child_fname, parent_fname))
      continue;
    const std::uint64_t parent_name =
        *reinterpret_cast<const std::uint64_t *>(parent_fname.data());
    if (parent_name == 0)
      continue;
    std::int32_t parent_index = -1;
    if (!GetBoneIndexFName(context, parent_fname, parent_index))
      continue;
    if (parent_index >= 0 &&
        static_cast<std::uint32_t>(parent_index) < count)
      context.bone_parents[index] = parent_index;
  }
  context.bone_parents_mesh = context.runtime.mesh;
  context.bone_parents_count = count;
  context.bone_parents_ready = true;
}

bool ApplyPoseByName(Context &context, const std::uint32_t bone,
                     const std::array<double, 3> &translation,
                     std::string &detail) noexcept {
  detail.clear();
  if (context.runtime.mesh == 0) {
    detail = "local mesh is unavailable";
    return false;
  }
  std::array<std::uint8_t, 8> name{};
  if (!GetBoneNameFName(context, bone, name)) {
    detail = "GetBoneName failed";
    return false;
  }
  std::array<std::uint8_t, 0x28> parameters{};
  std::memcpy(parameters.data(), name.data(), name.size());
  std::memcpy(parameters.data() + 0x08, translation.data(),
              sizeof(double) * 3);
  const std::uint8_t component_space = 1;
  parameters[0x20] = component_space;
  return CallVirtualUFunction(context, context.runtime.mesh,
                              kFunctionSetBoneLocationByNamePath,
                              parameters.data(), parameters.size(), detail);
}

struct Rotator3d {
  double pitch{};
  double yaw{};
  double roll{};
};

bool ApplyBoneRotationByName(Context &context, const std::uint32_t bone,
                             const double pitch, const double yaw,
                             const double roll, std::string &detail) noexcept {
  detail.clear();
  if (context.runtime.mesh == 0) {
    detail = "local mesh is unavailable";
    return false;
  }
  std::array<std::uint8_t, 8> name{};
  if (!GetBoneNameFName(context, bone, name)) {
    detail = "GetBoneName failed";
    return false;
  }
  std::array<std::uint8_t, 0x28> parameters{};
  std::memcpy(parameters.data(), name.data(), name.size());
  const Rotator3d rotation{pitch, yaw, roll};
  std::memcpy(parameters.data() + 0x08, &rotation, sizeof(rotation));
  const std::uint8_t component_space = 1;
  parameters[0x20] = component_space;
  return CallVirtualUFunction(context, context.runtime.mesh,
                              kFunctionSetBoneRotationByNamePath,
                              parameters.data(), parameters.size(), detail);
}

void ApplyPoseOverridesViaUFunction(Context &context) noexcept {
  RuntimeState &state = context.runtime;
  if (!context.pose_override_enabled.load(std::memory_order_acquire) ||
      state.mesh == 0)
    return;
  std::vector<std::array<double, 3>> angles;
  {
    std::lock_guard<std::mutex> lock(context.pose_angles_mutex);
    if (context.bone_angles.size() < state.local_space_count)
      return;
    angles.assign(context.bone_angles.begin(),
                  context.bone_angles.begin() + state.local_space_count);
  }
  for (std::uint32_t bone{}; bone != state.local_space_count; ++bone) {
    const auto &angle = angles[bone];
    if (angle[0] == 0.0 && angle[1] == 0.0 && angle[2] == 0.0)
      continue;
    std::string detail;
    static_cast<void>(ApplyBoneRotationByName(
        context, bone, angle[0], angle[1], angle[2], detail));
  }
  static_cast<void>(ForcePoseMeshObjectUpdate(context));
}

bool CapturePoseBase(Context &context) noexcept {
  const auto mesh = context.runtime.mesh;
  const auto data = context.runtime.local_space_data;
  const auto count = context.runtime.local_space_count;
  if (mesh == 0 || data == 0 || count == 0)
    return false;
  std::lock_guard<std::mutex> lock(context.pose_angles_mutex);
  if (context.pose_base_ready && context.pose_base_mesh == mesh &&
      context.pose_base_locals.size() == count)
    return true;
  std::vector<std::array<double, 12>> base(count);
  for (std::uint32_t bone{}; bone != count; ++bone) {
    std::uintptr_t address{};
    if (!AddAddress(data, static_cast<std::uint64_t>(bone) * kTransformSize,
                    address) ||
        !Read(context, address, base[bone]))
      return false;
  }
  context.pose_base_locals = std::move(base);
  context.pose_base_mesh = mesh;
  context.pose_base_ready = true;
  return true;
}

void ApplyPoseOverridesDirect(Context &context) noexcept {
  RuntimeState &state = context.runtime;
  if (!context.pose_override_enabled.load(std::memory_order_acquire) ||
      state.mesh == 0 || state.local_space_data == 0 ||
      state.local_space_count == 0 || state.component_space_data == 0 ||
      state.component_space_count != state.local_space_count)
    return;
  if (!CapturePoseBase(context))
    return;
  const std::uint32_t count = state.local_space_count;
  std::vector<std::array<double, 12>> base_locals;
  std::vector<std::array<double, 3>> angles;
  {
    std::lock_guard<std::mutex> lock(context.pose_angles_mutex);
    if (context.pose_base_locals.size() != count ||
        context.bone_angles.size() < count)
      return;
    base_locals = context.pose_base_locals;
    angles.assign(context.bone_angles.begin(),
                  context.bone_angles.begin() + count);
  }

  std::array<double, 3> root_offset{
      context.requested_root_offset[0].load(std::memory_order_acquire),
      context.requested_root_offset[1].load(std::memory_order_acquire),
      context.requested_root_offset[2].load(std::memory_order_acquire)};
  const bool has_root_offset =
      root_offset[0] != 0.0 || root_offset[1] != 0.0 || root_offset[2] != 0.0;

  std::vector<Transformd> locals(count);
  bool any_override = false;
  for (std::uint32_t bone{}; bone != count; ++bone) {
    const auto &raw = base_locals[bone];
    locals[bone].rotation = Quatd{raw[0], raw[1], raw[2], raw[3]};
    locals[bone].translation = Vec3d{raw[4], raw[5], raw[6]};
    locals[bone].scale = Vec3d{raw[8], raw[9], raw[10]};
    const auto &angle = angles[bone];
    if (angle[0] == 0.0 && angle[1] == 0.0 && angle[2] == 0.0)
      continue;
    any_override = true;
    const Quatd offset =
        RotatorToQuat(angle[0], angle[1], angle[2]);
    locals[bone].rotation = QuatMultiply(offset, locals[bone].rotation);
  }
  if (!any_override && !has_root_offset)
    return;

  if (context.bone_parents.size() != count)
    return;
  std::vector<Transformd> components(count);
  std::vector<std::uint8_t> marks(count, 0);
  for (std::uint32_t bone{}; bone != count; ++bone)
    static_cast<void>(ComputeBoneComponent(bone, locals, context.bone_parents,
                                           components, marks));

  std::vector<PackedTransform> packed(count);
  for (std::uint32_t bone{}; bone != count; ++bone)
    PackTransform(components[bone], packed[bone]);
  for (std::uint32_t bone{}; bone != count; ++bone) {
    packed[bone].translation[0] += root_offset[0];
    packed[bone].translation[1] += root_offset[1];
    packed[bone].translation[2] += root_offset[2];
  }
  const auto *bytes = reinterpret_cast<const std::uint8_t *>(packed.data());
  const auto byte_count = packed.size() * sizeof(PackedTransform);
  static_cast<void>(WriteBytes(context, state.component_space_data, bytes,
                               byte_count));
  static_cast<void>(WriteBytes(context, state.bone_space_data, bytes,
                               byte_count));
  static_cast<void>(ForcePoseMeshObjectUpdate(context));
}

bool GetBoneCount(Context &context, std::int32_t &count,
                  std::string &detail) noexcept {
  count = 0;
  if (context.runtime.mesh == 0) {
    detail = "local mesh is unavailable";
    return false;
  }
  std::array<std::uint8_t, 4> parameters{};
  std::array<std::uint8_t, 4> output{};
  if (!CallVirtualUFunction(context, context.runtime.mesh,
                            kFunctionGetNumBonesPath, parameters.data(),
                            parameters.size(), detail, output.data())) {
    detail.insert(0, "GetNumBones failed: ");
    return false;
  }
  std::int32_t value{};
  std::memcpy(&value, output.data(), sizeof(value));
  if (value < 0) {
    detail = "GetNumBones returned a negative count";
    return false;
  }
  count = value;
  return true;
}

bool GetBoneName(Context &context, const std::uint32_t bone_index,
                 std::string &name) noexcept {
  name.clear();
  if (context.runtime.mesh == 0)
    return false;
  std::array<std::uint8_t, 12> parameters{};
  const std::int32_t index = static_cast<std::int32_t>(bone_index);
  std::memcpy(parameters.data(), &index, sizeof(index));
  std::array<std::uint8_t, 12> output{};
  std::string detail;
  if (!CallVirtualUFunction(context, context.runtime.mesh,
                            kFunctionGetBoneNamePath, parameters.data(),
                            parameters.size(), detail, output.data()))
    return false;
  std::uint32_t name_id{};
  std::memcpy(&name_id, output.data() + 4, sizeof(name_id));
  if (ResolveName(context, name_id, name))
    return true;
  name = "Bone_" + std::to_string(bone_index);
  return false;
}

bool RefreshBoneNames(Context &context, std::vector<std::string> &names,
                      std::string &detail) noexcept {
  names.clear();
  detail.clear();
  std::int32_t count{};
  if (!GetBoneCount(context, count, detail))
    return false;
  if (count <= 0 || count > 8192) {
    detail = "GetNumBones returned an invalid count";
    return false;
  }
  names.reserve(static_cast<std::size_t>(count));
  for (std::int32_t index{}; index != count; ++index) {
    std::string name;
    static_cast<void>(GetBoneName(context, static_cast<std::uint32_t>(index),
                                  name));
    names.push_back(std::move(name));
  }
  detail = "loaded " + std::to_string(count) + " bone names";
  return true;
}

void MaybeRefreshBoneNames(Context &context) noexcept {
  const auto mesh = context.runtime.mesh;
  const auto count = context.runtime.bone_space_count;
  if (mesh == 0 || count == 0)
    return;
  if (!context.bone_names.empty() && context.bone_names_mesh == mesh &&
      context.bone_names_count == count)
    return;
  if (context.bone_names_attempted && context.bone_names_mesh == mesh &&
      context.bone_names_count == count)
    return;
  context.bone_names_attempted = true;
  std::string detail;
  std::vector<std::string> names;
  if (!RefreshBoneNames(context, names, detail)) {
    context.bone_names.clear();
    return;
  }
  context.bone_names = std::move(names);
  context.bone_names_mesh = mesh;
  context.bone_names_count = count;
  RefreshBoneHierarchy(context);
}

bool ForcePoseCache(Context &context, std::string &detail) noexcept {
  detail.clear();
  if (context.runtime.mesh == 0) {
    detail = "local mesh is unavailable";
    return false;
  }

  std::array<std::uint8_t, 12> bone_name_parameters{};
  const std::int32_t bone_index = 0;
  std::memcpy(bone_name_parameters.data(), &bone_index, sizeof(bone_index));
  std::array<std::uint8_t, 12> bone_name_output{};
  if (!CallVirtualUFunction(context, context.runtime.mesh,
                            kFunctionGetBoneNamePath,
                            bone_name_parameters.data(),
                            bone_name_parameters.size(), detail,
                            bone_name_output.data())) {
    detail.insert(0, "GetBoneName failed: ");
    return false;
  }

  std::array<std::uint8_t, 112> bone_transform_parameters{};
  std::memcpy(bone_transform_parameters.data(), bone_name_output.data() + 4,
              sizeof(std::uint64_t));
  const std::uint8_t transform_space = 2;
  bone_transform_parameters[8] = transform_space;
  std::array<std::uint8_t, 112> bone_transform_output{};
  if (!CallVirtualUFunction(context, context.runtime.mesh,
                            kFunctionGetBoneTransformPath,
                            bone_transform_parameters.data(),
                            bone_transform_parameters.size(), detail,
                            bone_transform_output.data())) {
    detail.insert(0, "GetBoneTransform failed: ");
    return false;
  }

  detail = "pose cache refreshed (bone 0)";
  return true;
}

bool EnsurePoseForcedLod(Context &context, const bool enabled) noexcept {
  RuntimeState &state = context.runtime;
  if (state.mesh == 0)
    return false;
  if (!enabled) {
    if (state.saved_forced_lod && state.forced_lod_applied) {
      std::string detail;
      const std::int32_t original = state.original_forced_lod;
      if (CallVirtualUFunction(context, state.mesh, kFunctionSetForcedLodPath,
                               &original, sizeof(original), detail)) {
        state.forced_lod_applied = false;
        state.saved_forced_lod = false;
        state.original_forced_lod = 0;
      }
    } else {
      state.saved_forced_lod = false;
      state.forced_lod_applied = false;
      state.original_forced_lod = 0;
    }
    return true;
  }
  if (!state.saved_forced_lod) {
    std::int32_t original{};
    if (!Read(context, state.mesh + kMeshForcedLodModelOffset, original))
      return false;
    state.original_forced_lod = original;
    state.saved_forced_lod = true;
    state.forced_lod_applied = false;
  }
  if (state.forced_lod_applied)
    return true;
  const std::int32_t high_lod = 0;
  std::string detail;
  if (!CallVirtualUFunction(context, state.mesh, kFunctionSetForcedLodPath,
                            &high_lod, sizeof(high_lod), detail))
    return false;
  state.forced_lod_applied = true;
  return true;
}

bool EnsurePoseAnimationMode(Context &context, const bool enabled) noexcept {
  RuntimeState &state = context.runtime;
  if (state.mesh == 0)
    return false;
  if (!enabled) {
    if (state.saved_animation_mode && state.animation_mode_applied) {
      const std::uint8_t original = state.original_animation_mode;
      if (!Write(context, state.mesh + kMeshAnimationModeOffset, original))
        return false;
      state.animation_mode_applied = false;
      state.saved_animation_mode = false;
      state.original_animation_mode = 0;
    } else {
      state.saved_animation_mode = false;
      state.animation_mode_applied = false;
      state.original_animation_mode = 0;
    }
    return true;
  }
  if (!state.saved_animation_mode) {
    std::uint8_t original{};
    if (!Read(context, state.mesh + kMeshAnimationModeOffset, original))
      return false;
    state.original_animation_mode = original;
    state.saved_animation_mode = true;
    state.animation_mode_applied = false;
  }
  if (state.animation_mode_applied)
    return true;

  struct SetAnimationModeParameters {
    std::uint8_t mode;
    std::uint8_t force_init;
  };
  const SetAnimationModeParameters parameters{kAnimationModeCustom, 0};
  std::string detail;
  if (CallVirtualUFunction(context, state.mesh, kFunctionSetAnimationModePath,
                           &parameters, sizeof(parameters), detail)) {
    state.animation_mode_applied = true;
    return true;
  }

  // SetAnimationMode can be missing or overridden in stripped builds. Fall back
  // to the direct property write, which is sufficient when no AnimInstance
  // reinitialization is requested.
  const std::uint8_t custom = kAnimationModeCustom;
  if (!Write(context, state.mesh + kMeshAnimationModeOffset, custom))
    return false;
  state.animation_mode_applied = true;
  return true;
}

void SetReflectionStatus(Context &context, const std::string_view message) {
  std::scoped_lock lock(context.state_mutex);
  context.reflection_status.assign(message.data(), message.size());
}

std::wstring Utf8ToWide(const std::string_view value) {
  if (value.empty() ||
      value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
    return {};
  const int required = MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
      nullptr, 0);
  if (required <= 0)
    return {};
  std::wstring result(static_cast<std::size_t>(required), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), result.data(),
                          required) != required)
    return {};
  return result;
}

std::string WideToUtf8(const std::wstring_view value) {
  if (value.empty() ||
      value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
    return {};
  const int required = WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
      nullptr, 0, nullptr, nullptr);
  if (required <= 0)
    return {};
  std::string result(static_cast<std::size_t>(required), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), result.data(), required,
                          nullptr, nullptr) != required)
    return {};
  return result;
}

class ComApartment final {
public:
  ComApartment() noexcept : result_(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
  ~ComApartment() {
    if (SUCCEEDED(result_))
      CoUninitialize();
  }
  [[nodiscard]] bool Usable() const noexcept {
    return SUCCEEDED(result_) || result_ == RPC_E_CHANGED_MODE;
  }
private:
  HRESULT result_{};
};

std::optional<std::filesystem::path> ChooseFolder(
    const std::string_view current_utf8) {
  ComApartment apartment;
  if (!apartment.Usable())
    return std::nullopt;
  ComPtr<IFileOpenDialog> dialog;
  if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                              IID_PPV_ARGS(&dialog))))
    return std::nullopt;
  DWORD options{};
  if (SUCCEEDED(dialog->GetOptions(&options))) {
    static_cast<void>(dialog->SetOptions(options | FOS_PICKFOLDERS |
                                         FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST));
  }
  if (!current_utf8.empty()) {
    const std::wstring current = Utf8ToWide(current_utf8);
    if (!current.empty()) {
      ComPtr<IShellItem> folder;
      if (SUCCEEDED(SHCreateItemFromParsingName(
              current.c_str(), nullptr, IID_PPV_ARGS(&folder))))
        static_cast<void>(dialog->SetFolder(folder.Get()));
    }
  }
  if (FAILED(dialog->Show(nullptr)))
    return std::nullopt;
  ComPtr<IShellItem> selected;
  if (FAILED(dialog->GetResult(&selected)))
    return std::nullopt;
  PWSTR raw{};
  if (FAILED(selected->GetDisplayName(SIGDN_FILESYSPATH, &raw)) || raw == nullptr)
    return std::nullopt;
  std::filesystem::path result(raw);
  CoTaskMemFree(raw);
  return result;
}

std::optional<std::filesystem::path> ChooseFile(
    const std::string_view current_utf8) {
  ComApartment apartment;
  if (!apartment.Usable())
    return std::nullopt;
  ComPtr<IFileOpenDialog> dialog;
  if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                              IID_PPV_ARGS(&dialog))))
    return std::nullopt;
  DWORD options{};
  if (SUCCEEDED(dialog->GetOptions(&options))) {
    static_cast<void>(dialog->SetOptions(options | FOS_FORCEFILESYSTEM |
                                         FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST));
  }
  COMDLG_FILTERSPEC filters[] = {
      {L"JSON", L"*.json"},
      {L"All Files", L"*.*"},
  };
  static_cast<void>(dialog->SetFileTypes(ARRAYSIZE(filters), filters));
  if (!current_utf8.empty()) {
    const std::wstring current = Utf8ToWide(current_utf8);
    if (!current.empty()) {
      ComPtr<IShellItem> folder;
      if (SUCCEEDED(SHCreateItemFromParsingName(
              current.c_str(), nullptr, IID_PPV_ARGS(&folder))))
        static_cast<void>(dialog->SetFolder(folder.Get()));
    }
  }
  if (FAILED(dialog->Show(nullptr)))
    return std::nullopt;
  ComPtr<IShellItem> selected;
  if (FAILED(dialog->GetResult(&selected)))
    return std::nullopt;
  PWSTR raw{};
  if (FAILED(selected->GetDisplayName(SIGDN_FILESYSPATH, &raw)) || raw == nullptr)
    return std::nullopt;
  std::filesystem::path result(raw);
  CoTaskMemFree(raw);
  return result;
}struct PoseFileTaskData final {
  Context *context{};
  std::uint32_t action{};
  std::string document;
  std::string path;
};

void ANOMALY_CALL PoseFileTask(void *value, AnomalyGenerationHandleV1) {
  auto *data = static_cast<PoseFileTaskData *>(value);
  if (data == nullptr)
    return;
  Context *context = data->context;
  if (context == nullptr) {
    delete data;
    return;
  }
  try {
    if (data->action == 1) {
      std::ofstream file(Utf8ToWide(data->path), std::ios::binary);
      if (!file) {
        SetReflectionStatus(*context, "pose export failed: cannot open file");
        delete data;
        return;
      }
      file.write(data->document.data(), static_cast<std::streamsize>(data->document.size()));
      file.close();
      if (!file) {
        SetReflectionStatus(*context, "pose export failed: write error");
      } else {
        SetReflectionStatus(*context, "pose exported");
      }
    } else if (data->action == 2) {
      std::ifstream file(Utf8ToWide(data->path), std::ios::binary);
      if (!file) {
        SetReflectionStatus(*context, "pose import failed: cannot open file");
        delete data;
        return;
      }
      std::string document((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
      if (file.bad() || document.empty() || document.size() > kMaximumPoseSettingsBytes) {
        SetReflectionStatus(*context, "pose import failed: unreadable file");
      } else {
        const auto json = nlohmann::json::parse(document);
        if (!ApplyPoseDocument(*context, json)) {
          SetReflectionStatus(*context, "pose import failed: invalid document");
        } else {
          context->pose_override_enabled.store(true, std::memory_order_release);
          context->pose_settings_dirty.store(true, std::memory_order_release);
          SetReflectionStatus(*context, "pose imported");
        }
      }
    }
  } catch (...) {
    SetReflectionStatus(*context, "pose file action threw an exception");
  }
  delete data;
}void ExecutePoseFileAction(Context &context) noexcept {
  const std::uint32_t action =
      context.pose_file_action_requested.exchange(0, std::memory_order_acquire);
  if (action == 0)
    return;
  if (!SchedulerReady(context.scheduler)) {
    SetReflectionStatus(context, "pose file action failed: scheduler unavailable");
    return;
  }
  auto *data = new (std::nothrow) PoseFileTaskData();
  if (data == nullptr) {
    SetReflectionStatus(context, "pose file action failed: out of memory");
    return;
  }
  data->context = &context;
  data->action = action;
  if (action == 1) {
    std::string name(context.pose_export_name.data());
    if (name.empty())
      name = "pose.json";
    if (name.size() < 5 || name.substr(name.size() - 5) != ".json")
      name += ".json";
    const std::wstring folder = Utf8ToWide(context.pose_export_folder);
    if (folder.empty()) {
      delete data;
      SetReflectionStatus(context, "pose export failed: no folder selected");
      return;
    }
    std::wstring path = folder;
    if (path.back() != L'\\' && path.back() != L'/')
      path.push_back(L'\\');
    path += Utf8ToWide(name);
    data->path = WideToUtf8(path);
    if (data->path.empty()) {
      delete data;
      SetReflectionStatus(context, "pose export failed: invalid path");
      return;
    }
    data->document = BuildPoseDocument(context);
    if (data->document.size() > kMaximumPoseSettingsBytes) {
      delete data;
      SetReflectionStatus(context, "pose export failed: document too large");
      return;
    }
  } else if (action == 2) {
    if (context.pose_import_file.empty()) {
      delete data;
      SetReflectionStatus(context, "pose import failed: no file selected");
      return;
    }
    data->path = context.pose_import_file;
  }
  AnomalyGenerationHandleV1 task{};
  const AnomalyStatusV1 status = context.scheduler->schedule(
      context.scheduler->user, 0, PoseFileTask, data, &task);
  if (status.code != ANOMALY_STATUS_V1_OK || task.id == 0) {
    delete data;
    SetReflectionStatus(context,
                        "pose file action failed: schedule code=" +
                            std::to_string(status.code));
    return;
  }
  SetReflectionStatus(context, action == 1 ? "pose export queued"
                                           : "pose import queued");
}
void EnsureActiveCharacterProfile(Context &context) noexcept {
  if (context.runtime.mesh == 0 || !StorageReady(context.storage))
    return;
  const std::string profile_id = Hex(context.runtime.mesh);
  if (profile_id.empty() || profile_id == context.active_character_id)
    return;
  const bool first_profile = !context.character_profiles_initialized;
  context.active_character_id = profile_id;
  const int loaded = LoadCharacterPoseProfile(context, profile_id);
  if (loaded <= 0 && !first_profile)
    ResetPoseValues(context);
  context.character_profiles_initialized = true;
  context.pose_settings_dirty.store(true, std::memory_order_release);
}

void ExecuteReflectionAction(Context &context) noexcept {
  const std::uint32_t action =
      context.reflection_action_requested.exchange(0, std::memory_order_acquire);
  if (action == 0 || context.runtime.mesh == 0)
    return;
  try {
    bool ok = false;
    std::string detail;
    if (action == 1) {
      const std::uint8_t looping = 1;
      ok = CallVirtualUFunction(context, context.runtime.mesh, kFunctionPlayPath,
                                &looping, sizeof(looping), detail);
    } else if (action == 2) {
      ok = CallVirtualUFunction(context, context.runtime.mesh, kFunctionStopPath,
                                nullptr, 0, detail);
    } else if (action == 3) {
      struct SetPositionParameters {
        float position;
        std::uint8_t fire_notifies;
      };
      SetPositionParameters parameters{};
      parameters.position = 0.0F;
      parameters.fire_notifies = 0;
      ok = CallVirtualUFunction(context, context.runtime.mesh,
                                kFunctionSetPositionPath, &parameters,
                                sizeof(parameters), detail);
    } else if (action == 4) {
      if (context.runtime.character == 0) {
        detail = "local character is unavailable";
      } else {
        ok = CallVirtualUFunction(context, context.runtime.character,
                                  kFunctionRefreshAnimInstancePath, nullptr, 0,
                                  detail);
      }
    } else if (action == 5) {
      ok = ForcePoseCache(context, detail);
    } else if (action == 6) {
      std::vector<std::string> names;
      ok = RefreshBoneNames(context, names, detail);
      if (ok) {
        context.bone_names = std::move(names);
        context.bone_names_mesh = context.runtime.mesh;
        context.bone_names_count = context.runtime.bone_space_count;
        context.bone_names_attempted = true;
        RefreshBoneHierarchy(context);
      }
    }
    const std::string label = action == 1   ? "Play: "
                              : action == 2 ? "Stop: "
                              : action == 3 ? "Seek 0: "
                              : action == 4 ? "Refresh Anim: "
                              : action == 5 ? "Refresh Pose: "
                                            : "Load Bones: ";
    if (action == 5)
      static_cast<void>(ReadPoseArrays(context));
    SetReflectionStatus(context, label + (ok ? detail : detail));
  } catch (...) {
    SetReflectionStatus(context, "UFunction call threw an exception");
  }
}

std::string Hex(const std::uintptr_t value) noexcept {
  std::array<char, 32> buffer{};
  std::snprintf(buffer.data(), buffer.size(), "0x%llX",
                static_cast<unsigned long long>(value));
  return std::string(buffer.data());
}

void SetStatus(RenderSnapshot &snapshot, const std::string_view message) {
  const auto length = (std::min)(message.size(), snapshot.status.size() - 1U);
  std::memcpy(snapshot.status.data(), message.data(), length);
  snapshot.status[length] = '\0';
}

void PublishSnapshot(Context &context, const std::string_view status) {
  RenderSnapshot next{};
  next.active = context.runtime.character != 0 && context.runtime.mesh != 0;
  next.character = context.runtime.character;
  next.mesh = context.runtime.mesh;
  next.anim_instance = context.runtime.anim_instance;
  next.animation_mode = context.runtime.animation_mode;
  next.bone_space_count = context.runtime.bone_space_count;
  next.bone_space_data = context.runtime.bone_space_data;
  next.component_space_count = context.runtime.component_space_count;
  next.component_space_data = context.runtime.component_space_data;
  next.rate_scale = context.runtime.rate_scale;
  next.root_motion_scale = context.runtime.root_motion_scale;
  next.pose_available = context.runtime.bone_space_data != 0 &&
                        context.runtime.bone_space_count != 0 &&
                        context.runtime.component_space_data != 0 &&
                        context.runtime.component_space_count != 0 &&
                        context.runtime.local_space_data != 0 &&
                        context.runtime.local_space_count != 0;
  next.bone_names = context.bone_names;
  next.pose_bone_index =
      context.requested_bone_index.load(std::memory_order_acquire);
  if (context.runtime.component_space_data != 0 &&
      next.pose_bone_index < context.runtime.component_space_count) {
    std::uintptr_t component_transform{};
    static_cast<void>(AddAddress(
        context.runtime.component_space_data,
        static_cast<std::uint64_t>(next.pose_bone_index) * kTransformSize,
        component_transform));
    static_cast<void>(Read(context,
                           component_transform + kTransformTranslationOffset,
                           next.component_translation_readback));
  }
  if (context.runtime.bone_space_data != 0 &&
      next.pose_bone_index < context.runtime.bone_space_count) {
    std::uintptr_t bone_transform{};
    static_cast<void>(AddAddress(
        context.runtime.bone_space_data,
        static_cast<std::uint64_t>(next.pose_bone_index) * kTransformSize,
        bone_transform));
    static_cast<void>(Read(context, bone_transform + kTransformTranslationOffset,
                           next.bone_translation_readback));
  }
  const auto pose_length =
      (std::min)(context.pose_status.size(), next.pose_status.size() - 1U);
  std::memcpy(next.pose_status.data(), context.pose_status.data(), pose_length);
  next.pose_status[pose_length] = '\0';
  SetStatus(next, status);
  std::scoped_lock lock(context.state_mutex);
  const auto length = (std::min)(context.reflection_status.size(),
                                 next.reflection_status.size() - 1U);
  std::memcpy(next.reflection_status.data(),
              context.reflection_status.data(), length);
  next.reflection_status[length] = '\0';
  context.snapshot = next;
}

bool RefreshRuntime(Context &context) noexcept {
  if (context.runtime.g_world_address == 0 && !ResolveGWorld(context))
    return false;
  if (!ResolveLocalCharacter(context))
    return false;
  if (!ReadAnimationState(context))
    return false;
  static_cast<void>(ReadPoseArrays(context));
  EnsurePoseAngleCapacity(context);
  MaybeRefreshBoneNames(context);
  RefreshBoneHierarchyDirect(context);
  static_cast<void>(Read(context,
                         context.runtime.mesh + kMeshGlobalAnimRateScaleOffset,
                         context.runtime.rate_scale));
  static_cast<void>(Read(
      context, context.runtime.character + kCharacterAnimRootMotionScaleOffset,
      context.runtime.root_motion_scale));
  return true;
}

void UpdateRuntime(Context &context) noexcept {
  if (!RefreshRuntime(context)) {
    PublishSnapshot(context, "local player character is unavailable");
    return;
  }

  EnsureActiveCharacterProfile(context);

  const bool freeze_enabled =
      context.freeze_enabled.load(std::memory_order_acquire);
  const bool rate_enabled =
      context.rate_override_enabled.load(std::memory_order_acquire);
  const float rate = context.requested_rate_scale.load(std::memory_order_acquire);
  const bool root_enabled =
      context.root_motion_override_enabled.load(std::memory_order_acquire);
  const float root = context.requested_root_motion_scale.load(
      std::memory_order_acquire);

  ExecuteReflectionAction(context);
  ExecutePoseFileAction(context);

  if (context.pose_reset_requested.exchange(false, std::memory_order_acquire)) {
    static_cast<void>(RestorePose(context));
    static_cast<void>(EnsurePoseAnimationMode(context, false));
    static_cast<void>(EnsurePoseForcedLod(context, false));
    context.pose_override_enabled.store(false, std::memory_order_release);
    ResetPoseValues(context);
    context.pose_settings_dirty.store(true, std::memory_order_release);
  }

  const bool master_enabled =
      context.pose_override_enabled.load(std::memory_order_acquire);
  std::size_t active_joints{};
  {
    std::lock_guard<std::mutex> lock(context.pose_angles_mutex);
    const auto active_count =
        (std::min)(context.bone_angles.size(),
                   static_cast<std::size_t>(context.runtime.local_space_count));
    for (std::size_t index{}; index != active_count; ++index) {
      const auto &angle = context.bone_angles[index];
      if (angle[0] != 0.0 || angle[1] != 0.0 || angle[2] != 0.0)
        ++active_joints;
    }
  }
  const bool has_root_offset =
      context.requested_root_offset[0].load(std::memory_order_acquire) != 0.0 ||
      context.requested_root_offset[1].load(std::memory_order_acquire) != 0.0 ||
      context.requested_root_offset[2].load(std::memory_order_acquire) != 0.0;
  const bool pose_enabled = master_enabled && (active_joints != 0 || has_root_offset);
  const bool pose_available = context.runtime.bone_space_data != 0 &&
                              context.runtime.bone_space_count != 0 &&
                              context.runtime.component_space_data != 0 &&
                              context.runtime.component_space_count != 0 &&
                              context.runtime.local_space_data != 0 &&
                              context.runtime.local_space_count != 0;
  const bool force_ok = ApplyMultiThreadedUpdate(context, pose_enabled);
  const bool pose_requested = pose_enabled && pose_available;
  const bool hook_ok = !pose_requested || EnsurePoseTickHook(context);
  const bool lod_ok = EnsurePoseForcedLod(context, pose_requested);
  const bool freeze = freeze_enabled || pose_requested;
  const bool freeze_ok = ApplyPause(context, freeze);
  const bool rate_ok = ApplyRate(context, rate_enabled, rate);
  const bool root_ok = ApplyRootMotion(context, root_enabled, root);
  const bool mode_ok = EnsurePoseAnimationMode(context, pose_requested);
  if (!pose_requested) {
    static_cast<void>(RestorePose(context));
    static_cast<void>(ReleasePoseTickHook(context));
  }
  if (pose_requested)
    ApplyPoseOverridesDirect(context);
  std::snprintf(context.pose_status.data(), context.pose_status.size(),
                "joints active: %u", static_cast<unsigned>(active_joints));

  bool settings_saved = true;
  if (context.pose_settings_dirty.exchange(false, std::memory_order_acquire))
    settings_saved = PersistPoseSettings(context);

  if (pose_requested && !hook_ok) {
    PublishSnapshot(context,
                    "pose override unavailable: skeletal tick hook failed");
  } else if (pose_requested && !lod_ok) {
    PublishSnapshot(context, "failed to force pose LOD 0");
  } else if (pose_requested && !mode_ok) {
    PublishSnapshot(context, "failed to switch animation mode to custom");
  } else if (!freeze_ok) {
    PublishSnapshot(context, "failed to apply animation pause flag");
  } else if (!rate_ok) {
    PublishSnapshot(context, "failed to apply animation rate scale");
  } else if (!root_ok) {
    PublishSnapshot(context, "failed to apply root motion scale");
  } else if (pose_requested) {
    PublishSnapshot(context, settings_saved
                                 ? "joint pose active (" +
                                       std::to_string(active_joints) + " joints)"
                                 : "pose active; settings save failed");
  } else if (master_enabled && active_joints != 0 && !force_ok) {
    PublishSnapshot(context,
                    "pose override unavailable: AnimInstance is not available");
  } else if (master_enabled && active_joints != 0) {
    PublishSnapshot(context,
                    "pose override pending: waiting for cached pose transforms");
  } else if (!settings_saved) {
    PublishSnapshot(context, "pose settings save failed");
  } else {
    PublishSnapshot(context, "ok");
  }
}

void RestoreAll(Context &context) noexcept {
  static_cast<void>(RestorePose(context));
  static_cast<void>(EnsurePoseAnimationMode(context, false));
  static_cast<void>(EnsurePoseForcedLod(context, false));
  static_cast<void>(RestoreMultiThreadedUpdate(context));
  static_cast<void>(RestoreRootMotion(context));
  static_cast<void>(RestoreRate(context));
  static_cast<void>(RestorePause(context));
}

AnomalyStatusV1 ANOMALY_CALL Load(const AnomalyHostApiV1 *host,
                                  void **plugin_context) {
  if (host == nullptr || plugin_context == nullptr)
    return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
  *plugin_context = nullptr;
  auto *context = new (std::nothrow) Context();
  if (context == nullptr)
    return Status(ANOMALY_STATUS_V1_FAILED);
  context->host = host;
  context->localizer = anomaly::plugins::Localizer(host);
  context->core = Query<AnomalyCoreServiceV1>(host, ANOMALY_CORE_SERVICE_V1_ID,
                                              ANOMALY_CORE_SERVICE_V1_VERSION);
  context->signature =
      Query<AnomalySignatureServiceV1>(host, ANOMALY_SIGNATURE_SERVICE_V1_ID,
                                       ANOMALY_SIGNATURE_SERVICE_V1_VERSION);
  context->names =
      Query<AnomalyUe5NamesServiceV1>(host, ANOMALY_UE5_NAMES_SERVICE_V1_ID,
                                      ANOMALY_UE5_NAMES_SERVICE_V1_VERSION);
  context->objects =
      Query<AnomalyUe5ObjectsServiceV1>(host, ANOMALY_UE5_OBJECTS_SERVICE_V1_ID,
                                        ANOMALY_UE5_OBJECTS_SERVICE_V1_VERSION);
  context->ui = Query<AnomalyUiServiceV1>(host, ANOMALY_UI_SERVICE_V1_ID,
                                          ANOMALY_UI_SERVICE_V1_VERSION);
  context->hook = Query<AnomalyHookServiceV1>(host, ANOMALY_HOOK_SERVICE_V1_ID,
                                              ANOMALY_HOOK_SERVICE_V1_VERSION);
  context->config = Query<AnomalyConfigServiceV1>(host,
                                                  ANOMALY_CONFIG_SERVICE_V1_ID,
                                                  ANOMALY_CONFIG_SERVICE_V1_VERSION);
  context->storage =
      Query<AnomalyStorageServiceV1>(host, ANOMALY_STORAGE_SERVICE_V1_ID,
                                     ANOMALY_STORAGE_SERVICE_V1_VERSION);
  context->scheduler =
      Query<AnomalySchedulerServiceV1>(host, ANOMALY_SCHEDULER_SERVICE_V1_ID,
                                       ANOMALY_SCHEDULER_SERVICE_V1_VERSION);
  if (!SchedulerReady(context->scheduler))
    context->scheduler = nullptr;
  if (!CoreReady(context->core) || !SignatureReady(context->signature) ||
      !NamesReady(context->names) ||
      !ObjectsReady(context->objects) ||
      !UiReady(context->ui) || !HookReady(context->hook) ||
      !ConfigReady(context->config) || !StorageReady(context->storage)) {
    delete context;
    return Status(ANOMALY_STATUS_V1_UNAVAILABLE,
                  "required plugin services are unavailable");
  }
  const auto schema_status = context->config->register_schema(
      context->config->user, anomaly::sdk::StringView(kPoseSettingsSchemaId),
      kPoseSettingsSchemaVersion, Bytes(kPoseSettingsSchema),
      &context->settings_schema);
  if (schema_status.code != ANOMALY_STATUS_V1_OK ||
      context->settings_schema.id == 0 || !LoadPoseSettings(*context)) {
    delete context;
    return Status(ANOMALY_STATUS_V1_FAILED,
                  "character pose settings are invalid");
  }
  *plugin_context = context;
  return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Start(void *plugin_context) {
  auto *context = static_cast<Context *>(plugin_context);
  if (context == nullptr)
    return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
  if (!ResolveGWorld(*context)) {
    return Status(ANOMALY_STATUS_V1_UNAVAILABLE,
                  "GWorld discovery signature is unavailable");
  }
  UpdateRuntime(*context);
  context->reflection_action_requested.store(5, std::memory_order_release);
  return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Stop(void *plugin_context, std::uint32_t) {
  auto *context = static_cast<Context *>(plugin_context);
  if (context == nullptr)
    return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
  static_cast<void>(ReleasePoseTickHook(*context));
  RestoreAll(*context);
  g_active.store(nullptr, std::memory_order_release);
  context->runtime = RuntimeState{};
  RenderSnapshot empty{};
  std::scoped_lock lock(context->state_mutex);
  context->snapshot = empty;
  return anomaly::sdk::Ok();
}

void ANOMALY_CALL Unload(void *plugin_context) {
  auto *context = static_cast<Context *>(plugin_context);
  if (context == nullptr)
    return;
  static_cast<void>(Stop(context, 0));
  if (context->settings_schema.id != 0 && ConfigReady(context->config)) {
    static_cast<void>(context->config->unregister_schema(
        context->config->user, context->settings_schema));
  }
  context->settings_schema = {};
  delete context;
}

void ANOMALY_CALL Update(void *plugin_context, const double) {
  auto *context = static_cast<Context *>(plugin_context);
  if (context == nullptr)
    return;
  try {
    UpdateRuntime(*context);
  } catch (...) {
    RestoreAll(*context);
    PublishSnapshot(*context, "update failed; overrides restored");
  }
}

bool ReadCurrentBoneTranslation(Context &context,
                                const RenderSnapshot &snapshot,
                                const std::uint32_t bone,
                                std::array<double, 3> &translation) noexcept {
  translation = {0.0, 0.0, 0.0};
  if (!CoreReady(context.core) || snapshot.component_space_data == 0 ||
      bone >= snapshot.component_space_count)
    return false;
  std::uintptr_t transform{};
  if (!AddAddress(snapshot.component_space_data,
                  static_cast<std::uint64_t>(bone) * kTransformSize,
                  transform) ||
      !AddAddress(transform, kTransformTranslationOffset, transform))
    return false;
  return Read(context, transform, translation);
}

void ANOMALY_CALL Draw(void *plugin_context, const AnomalyUiServiceV1 *ui) {
  auto *context = static_cast<Context *>(plugin_context);
  if (context == nullptr || !UiReady(ui))
    return;

  RenderSnapshot snapshot{};
  {
    std::scoped_lock lock(context->state_mutex);
    snapshot = context->snapshot;
  }

  const std::string title =
      context->localizer.Text("window.title", "Character Pose");
  int open = 1;
  ui->set_next_window_size(ui->user, 380.0F, 0.0F, 4U);
  const int visible = ui->begin_window(
      ui->user, anomaly::sdk::StringView(title), &open, 0);
  if (visible == 0) {
    ui->end_window(ui->user);
    return;
  }

  const std::string status_label =
      context->localizer.Text("status", "Status");
  const std::string status_text = status_label + ": " + snapshot.status.data();
  ui->text(ui->user, anomaly::sdk::StringView(status_text));

  const std::string character_line =
      "Character " + Hex(snapshot.character) + "  Mesh " + Hex(snapshot.mesh);
  ui->text(ui->user, anomaly::sdk::StringView(character_line));
  const std::string anim_line = "AnimInstance " + Hex(snapshot.anim_instance) +
                                "  Mode " + std::to_string(snapshot.animation_mode);
  ui->text(ui->user, anomaly::sdk::StringView(anim_line));
  const std::string pose_line =
      "Bones " + std::to_string(snapshot.bone_space_count) + " / Component " +
      std::to_string(snapshot.component_space_count);
  ui->text(ui->user, anomaly::sdk::StringView(pose_line));

  ui->separator(ui->user);

  int freeze = context->freeze_enabled.load(std::memory_order_acquire) ? 1 : 0;
  const std::string freeze_label =
      context->localizer.Text("freeze", "Pause animation");
  if (ui->checkbox(ui->user, anomaly::sdk::StringView(freeze_label), &freeze) !=
      0) {
    context->freeze_enabled.store(freeze != 0, std::memory_order_release);
  }

  int rate_enabled =
      context->rate_override_enabled.load(std::memory_order_acquire) ? 1 : 0;
  float rate = context->requested_rate_scale.load(std::memory_order_acquire);
  const std::string rate_toggle =
      context->localizer.Text("rate.toggle", "Override animation rate");
  if (ui->checkbox(ui->user, anomaly::sdk::StringView(rate_toggle),
                   &rate_enabled) != 0) {
    context->rate_override_enabled.store(rate_enabled != 0,
                                         std::memory_order_release);
  }
  const std::string rate_label =
      context->localizer.Text("rate", "Rate scale");
  if (ui->slider_float(ui->user, anomaly::sdk::StringView(rate_label), &rate,
                       0.0F, 3.0F) != 0) {
    context->requested_rate_scale.store(rate, std::memory_order_release);
  }

  ui->separator(ui->user);

  int pose_enabled =
      context->pose_override_enabled.load(std::memory_order_acquire) ? 1 : 0;
  const std::string pose_toggle =
      context->localizer.Text("pose.toggle", "Override joint pose");
  if (ui->checkbox(ui->user, anomaly::sdk::StringView(pose_toggle),
                   &pose_enabled) != 0) {
    context->pose_override_enabled.store(pose_enabled != 0,
                                         std::memory_order_release);
  }

  auto bone = context->requested_bone_index.load(std::memory_order_acquire);
  std::string selected_name = "None";
  if (bone < snapshot.bone_names.size())
    selected_name = snapshot.bone_names[bone];
  const std::string selected_label =
      context->localizer.Text("pose.bone.selected", "Selected bone");
  const std::string selected_line =
      selected_label + ": " + std::to_string(bone) + " " + selected_name;
  ui->text(ui->user, anomaly::sdk::StringView(selected_line));
  const std::string pose_status_line = std::string(snapshot.pose_status.data());
  ui->text(ui->user, anomaly::sdk::StringView(pose_status_line));

  const bool can_text_input =
      HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::input_text)>(
          ui, offsetof(AnomalyUiServiceV1, input_text)) &&
      ui->input_text != nullptr;
  const bool can_bone_list =
      can_text_input &&
      HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::begin_child)>(
          ui, offsetof(AnomalyUiServiceV1, begin_child)) &&
      ui->begin_child != nullptr &&
      HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::end_child)>(
          ui, offsetof(AnomalyUiServiceV1, end_child)) &&
      ui->end_child != nullptr &&
      HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::filter_match)>(
          ui, offsetof(AnomalyUiServiceV1, filter_match)) &&
      ui->filter_match != nullptr;

  if (can_bone_list) {
    const std::string filter_label =
        context->localizer.Text("pose.filter", "Bone filter");
    static_cast<void>(ui->input_text(
        ui->user, anomaly::sdk::StringView(filter_label),
        context->bone_filter.data(), context->bone_filter.size(),
        ANOMALY_UI_TEXT_INPUT_V1_NONE));

    const auto set_filter = [&](const char *value) {
      std::snprintf(context->bone_filter.data(), context->bone_filter.size(),
                    "%s", value);
    };
    int quick_button_index = 0;
    const auto quick_button = [&](const char *value, const std::string &label) {
      if (ui->button(ui->user, anomaly::sdk::StringView(label), 56.0F, 0.0F) != 0)
        set_filter(value);
      ++quick_button_index;
      if (quick_button_index % 6 != 0)
        ui->same_line(ui->user, 0.0F, 4.0F);
    };
    quick_button("arm", context->localizer.Text("filter.arm", "Arm"));
    quick_button("forearm", context->localizer.Text("filter.elbow", "Elbow"));
    quick_button("hand", context->localizer.Text("filter.hand", "Hand"));
    quick_button("thigh", context->localizer.Text("filter.thigh", "Thigh"));
    quick_button("calf", context->localizer.Text("filter.knee", "Knee"));
    quick_button("foot", context->localizer.Text("filter.foot", "Foot"));
    quick_button("clavicle", context->localizer.Text("filter.shoulder", "Shoulder"));
    quick_button("neck", context->localizer.Text("filter.neck", "Neck"));
    quick_button("head", context->localizer.Text("filter.head", "Head"));
    quick_button("spine", context->localizer.Text("filter.spine", "Spine"));
    quick_button("pelvis", context->localizer.Text("filter.pelvis", "Pelvis"));
    quick_button("", context->localizer.Text("filter.all", "All"));

    if (ui->begin_child(ui->user, anomaly::sdk::StringView("bone-list"), 0.0F,
                        240.0F, 0U) != 0) {
      if (snapshot.bone_names.empty()) {
        const std::string empty_label = context->localizer.Text(
            "pose.bones.empty", "Bone names not loaded; press Load Bones.");
        ui->text(ui->user, anomaly::sdk::StringView(empty_label));
      } else {
        const std::string_view filter(context->bone_filter.data());
        for (std::size_t index{}; index != snapshot.bone_names.size(); ++index) {
          if (ui->filter_match(ui->user, anomaly::sdk::StringView(filter),
                               anomaly::sdk::StringView(
                                   snapshot.bone_names[index])) == 0)
            continue;
          const std::string bone_item =
              std::to_string(index) + " " + snapshot.bone_names[index];
          if (ui->button(ui->user, anomaly::sdk::StringView(bone_item), 0.0F,
                         0.0F) != 0) {
            context->requested_bone_index.store(
                static_cast<std::uint32_t>(index), std::memory_order_release);
          }
        }
      }
      ui->end_child(ui->user);
    }
  } else {
    const std::string bone_label =
        context->localizer.Text("pose.bone", "Bone index");
    double bone_value = static_cast<double>(bone);
    if (ui->input_double(ui->user, anomaly::sdk::StringView(bone_label),
                         &bone_value, 1.0, 8.0) != 0) {
      if (bone_value < 0.0)
        bone_value = 0.0;
      if (bone_value > static_cast<double>(kMaximumBoneIndex))
        bone_value = static_cast<double>(kMaximumBoneIndex);
      context->requested_bone_index.store(
          static_cast<std::uint32_t>(bone_value), std::memory_order_release);
    }
  }

  float pitch = 0.0F;
  float yaw = 0.0F;
  float roll = 0.0F;
  {
    std::lock_guard<std::mutex> lock(context->pose_angles_mutex);
    if (bone < context->bone_angles.size()) {
      pitch = static_cast<float>(context->bone_angles[bone][0]);
      yaw = static_cast<float>(context->bone_angles[bone][1]);
      roll = static_cast<float>(context->bone_angles[bone][2]);
    }
  }

  bool apply_pose_now = false;
  const auto changed_angle = [&]() {
    context->pose_override_enabled.store(true, std::memory_order_release);
    context->pose_settings_dirty.store(true, std::memory_order_release);
    {
      std::lock_guard<std::mutex> lock(context->pose_angles_mutex);
      if (bone >= context->bone_angles.size())
        context->bone_angles.resize(static_cast<std::size_t>(bone) + 1);
      context->bone_angles[bone] = {pitch, yaw, roll};
    }
    apply_pose_now = true;
  };

  float root_x = static_cast<float>(
      context->requested_root_offset[0].load(std::memory_order_acquire));
  float root_y = static_cast<float>(
      context->requested_root_offset[1].load(std::memory_order_acquire));
  float root_z = static_cast<float>(
      context->requested_root_offset[2].load(std::memory_order_acquire));
  const auto changed_root_offset = [&]() {
    context->pose_override_enabled.store(true, std::memory_order_release);
    context->pose_settings_dirty.store(true, std::memory_order_release);
    context->requested_root_offset[0].store(root_x, std::memory_order_release);
    context->requested_root_offset[1].store(root_y, std::memory_order_release);
    context->requested_root_offset[2].store(root_z, std::memory_order_release);
    apply_pose_now = true;
  };

  const std::string pitch_label =
      context->localizer.Text("pose.pitch", "Pitch");
  if (ui->slider_float(ui->user, anomaly::sdk::StringView(pitch_label), &pitch,
                       -180.0F, 180.0F) != 0)
    changed_angle();
  ui->same_line(ui->user, 0.0F, 4.0F);
  const std::string pitch_reset =
      context->localizer.Label("pose.reset.pitch", "重置", "reset-pitch");
  if (ui->button(ui->user, anomaly::sdk::StringView(pitch_reset), 42.0F,
                 0.0F) != 0) {
    pitch = 0.0F;
    changed_angle();
  }

  const std::string yaw_label =
      context->localizer.Text("pose.yaw", "Yaw");
  if (ui->slider_float(ui->user, anomaly::sdk::StringView(yaw_label), &yaw,
                       -180.0F, 180.0F) != 0)
    changed_angle();
  ui->same_line(ui->user, 0.0F, 4.0F);
  const std::string yaw_reset =
      context->localizer.Label("pose.reset.yaw", "重置", "reset-yaw");
  if (ui->button(ui->user, anomaly::sdk::StringView(yaw_reset), 42.0F,
                 0.0F) != 0) {
    yaw = 0.0F;
    changed_angle();
  }

  const std::string roll_label =
      context->localizer.Text("pose.roll", "Roll");
  if (ui->slider_float(ui->user, anomaly::sdk::StringView(roll_label), &roll,
                       -180.0F, 180.0F) != 0)
    changed_angle();
  ui->same_line(ui->user, 0.0F, 4.0F);
  const std::string roll_reset =
      context->localizer.Label("pose.reset.roll", "重置", "reset-roll");
  if (ui->button(ui->user, anomaly::sdk::StringView(roll_reset), 42.0F,
                 0.0F) != 0) {
    roll = 0.0F;
    changed_angle();
  }

  ui->separator(ui->user);
  const std::string body_x_label =
      context->localizer.Text("pose.body.x", "X");
  if (ui->slider_float(ui->user, anomaly::sdk::StringView(body_x_label),
                       &root_x, -1000.0F, 1000.0F) != 0)
    changed_root_offset();
  ui->same_line(ui->user, 0.0F, 4.0F);
  const std::string body_x_reset =
      context->localizer.Label("pose.reset.body.x", "重置", "reset-body-x");
  if (ui->button(ui->user, anomaly::sdk::StringView(body_x_reset), 42.0F,
                 0.0F) != 0) {
    root_x = 0.0F;
    changed_root_offset();
  }

  const std::string body_y_label =
      context->localizer.Text("pose.body.y", "Y");
  if (ui->slider_float(ui->user, anomaly::sdk::StringView(body_y_label),
                       &root_y, -1000.0F, 1000.0F) != 0)
    changed_root_offset();
  ui->same_line(ui->user, 0.0F, 4.0F);
  const std::string body_y_reset =
      context->localizer.Label("pose.reset.body.y", "重置", "reset-body-y");
  if (ui->button(ui->user, anomaly::sdk::StringView(body_y_reset), 42.0F,
                 0.0F) != 0) {
    root_y = 0.0F;
    changed_root_offset();
  }

  const std::string body_z_label =
      context->localizer.Text("pose.body.z", "Z");
  if (ui->slider_float(ui->user, anomaly::sdk::StringView(body_z_label),
                       &root_z, -1000.0F, 1000.0F) != 0)
    changed_root_offset();
  ui->same_line(ui->user, 0.0F, 4.0F);
  const std::string body_z_reset =
      context->localizer.Label("pose.reset.body.z", "重置", "reset-body-z");
  if (ui->button(ui->user, anomaly::sdk::StringView(body_z_reset), 42.0F,
                 0.0F) != 0) {
    root_z = 0.0F;
    changed_root_offset();
  }

  if (apply_pose_now)
    ApplyPoseOverridesDirect(*context);
  ui->same_line(ui->user, 0.0F, 6.0F);
  const std::string reset_label =
      context->localizer.Text("pose.reset", "Reset All");
  const bool can_confirm_popup =
      HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::open_popup)>(
          ui, offsetof(AnomalyUiServiceV1, open_popup)) &&
      ui->open_popup != nullptr &&
      HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::begin_popup_modal)>(
          ui, offsetof(AnomalyUiServiceV1, begin_popup_modal)) &&
      ui->begin_popup_modal != nullptr &&
      HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::end_popup)>(
          ui, offsetof(AnomalyUiServiceV1, end_popup)) &&
      ui->end_popup != nullptr &&
      HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::close_current_popup)>(
          ui, offsetof(AnomalyUiServiceV1, close_current_popup)) &&
      ui->close_current_popup != nullptr;
  if (ui->button(ui->user, anomaly::sdk::StringView(reset_label), 70.0F,
                 0.0F) != 0) {
    if (can_confirm_popup)
      ui->open_popup(ui->user, anomaly::sdk::StringView("pose-reset-confirm"));
    else
      context->pose_reset_requested.store(true, std::memory_order_release);
  }

  ui->separator(ui->user);
  const std::string action_label =
      context->localizer.Text("action.status", "Action");
  const std::string action_text =
      action_label + ": " + std::string(snapshot.reflection_status.data());
  ui->text(ui->user, anomaly::sdk::StringView(action_text));
  const std::string refresh_anim_label =
      context->localizer.Text("action.refresh_anim", "Refresh Anim");
  if (ui->button(ui->user, anomaly::sdk::StringView(refresh_anim_label), 80.0F,
                 0.0F) != 0)
    context->reflection_action_requested.store(4, std::memory_order_release);
  ui->same_line(ui->user, 0.0F, 6.0F);
  const std::string load_bones_label =
      context->localizer.Text("action.load_bones", "Load Bones");
  if (ui->button(ui->user, anomaly::sdk::StringView(load_bones_label), 80.0F,
                 0.0F) != 0)
    context->reflection_action_requested.store(6, std::memory_order_release);
  if (context->pose_export_name[0] == '\0') {
    std::snprintf(context->pose_export_name.data(), context->pose_export_name.size(),
                "pose.json");
  }
  ui->text(ui->user, anomaly::sdk::StringView(context->localizer.Text("pose.file.name", "File name")));
  ui->same_line(ui->user, 0.0F, 6.0F);
  ui->input_text(ui->user, anomaly::sdk::StringView("##pose-export-name"),
                 context->pose_export_name.data(),
                 context->pose_export_name.size(), 0);
  ui->same_line(ui->user, 0.0F, 6.0F);
  const std::string choose_folder_label =
      context->localizer.Text("pose.choose.folder", "Choose folder");
  if (ui->button(ui->user, anomaly::sdk::StringView(choose_folder_label), 90.0F,
                 0.0F) != 0) {
    const auto selected = ChooseFolder(context->pose_export_folder);
    if (selected) {
      const std::string folder_utf8 = WideToUtf8(selected->native());
      if (!folder_utf8.empty())
        context->pose_export_folder = folder_utf8;
    }
  }
  ui->same_line(ui->user, 0.0F, 6.0F);
  const std::string export_label =
      context->localizer.Text("pose.export", "Export");
  if (ui->button(ui->user, anomaly::sdk::StringView(export_label), 60.0F,
                 0.0F) != 0)
    context->pose_file_action_requested.store(1, std::memory_order_release);

  ui->text(ui->user, anomaly::sdk::StringView(context->localizer.Text("pose.import.file", "Import file")));
  ui->same_line(ui->user, 0.0F, 6.0F);
  const std::string choose_file_label =
      context->localizer.Text("pose.choose.file", "Choose file");
  if (ui->button(ui->user, anomaly::sdk::StringView(choose_file_label), 90.0F,
                 0.0F) != 0) {
    const auto selected = ChooseFile(context->pose_import_file);
    if (selected) {
      const std::string file_utf8 = WideToUtf8(selected->native());
      if (!file_utf8.empty())
        context->pose_import_file = file_utf8;
    }
  }
  ui->same_line(ui->user, 0.0F, 6.0F);
  const std::string import_label =
      context->localizer.Text("pose.import", "Import");
  if (ui->button(ui->user, anomaly::sdk::StringView(import_label), 60.0F,
                 0.0F) != 0)
    context->pose_file_action_requested.store(2, std::memory_order_release);

  if (can_confirm_popup) {
    int confirm_open = 1;
    const std::string confirm_id = "pose-reset-confirm";
    if (ui->begin_popup_modal(ui->user, anomaly::sdk::StringView(confirm_id),
                              &confirm_open, 0U) != 0) {
      const std::string confirm_text = context->localizer.Text(
          "pose.reset.confirm", "Reset all bone and body offsets?");
      ui->text(ui->user, anomaly::sdk::StringView(confirm_text));
      const std::string confirm_yes =
          context->localizer.Text("pose.reset.confirm.yes", "Reset");
      if (ui->button(ui->user, anomaly::sdk::StringView(confirm_yes), 90.0F,
                     0.0F) != 0) {
        context->pose_reset_requested.store(true, std::memory_order_release);
        ui->close_current_popup(ui->user);
      }
      ui->same_line(ui->user, 0.0F, 6.0F);
      const std::string confirm_cancel =
          context->localizer.Text("pose.reset.confirm.cancel", "Cancel");
      if (ui->button(ui->user, anomaly::sdk::StringView(confirm_cancel), 90.0F,
                     0.0F) != 0)
        ui->close_current_popup(ui->user);
      ui->end_popup(ui->user);
    }
  }

  if (!snapshot.pose_available) {
    const std::string warning = context->localizer.Text(
        "pose.unavailable", "Pose edit is inactive until the authoritative bone-space pose buffer is populated.");
    ui->text(ui->user, anomaly::sdk::StringView(warning));
  }

  ui->end_window(ui->user);
}

}  // namespace

ANOMALY_SDK_EXPORT AnomalyStatusV1 ANOMALY_CALL
AnomalyPluginEntryV1(AnomalyPluginDescriptorV1 *descriptor) {
  if (descriptor == nullptr || descriptor->struct_size < sizeof(*descriptor))
    return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
  *descriptor = {sizeof(*descriptor),
                 ANOMALY_PLUGIN_API_V1_MAJOR,
                 ANOMALY_PLUGIN_API_V1_MINOR,
                 anomaly::sdk::StringView("anomaly.builtin.better-pose"),
                 anomaly::sdk::StringView("Better Pose"),
                 anomaly::sdk::StringView("Anomaly"),
                 anomaly::sdk::StringView("1.0.0"),
                 Load,
                 Start,
                 Stop,
                 Unload,
                 Update,
                 Draw};
  return anomaly::sdk::Ok();
}
