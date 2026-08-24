#include "anomaly/sdk/cpp.hpp"
#include "anomaly/sdk/services/core.h"
#include "anomaly/sdk/services/interop.h"
#include "camera_blur_fix_profile.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <new>
#include <string_view>

namespace {

using namespace camera_blur_fix_profile;

struct Context final {
  const AnomalyCoreServiceV1 *core{};
  const AnomalySignatureServiceV1 *signature{};
  std::uintptr_t g_world_address{};
  std::uintptr_t patched_manager{};
  float saved_fade_speed{};
  float saved_fade_distance{};
  float saved_hide_distance{};
  std::uintptr_t saved_pitch_curve{};
  float saved_normal_fade_distance{};
  float saved_normal_hide_distance{};
  bool saved_state{};
  bool logged_world{};
  bool logged_patch{};
};

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

void Log(Context &context, const std::uint32_t level,
         const std::string_view message) noexcept {
  if (context.core != nullptr && context.core->log != nullptr)
    context.core->log(context.core->user, level,
                      anomaly::sdk::StringView(message));
}

template <typename T>
bool Read(Context &context, const std::uintptr_t address, T &value) noexcept {
  if (!CoreReady(context.core) || address == 0) return false;
  AnomalyMutableByteSpanV1 destination{
      reinterpret_cast<std::uint8_t *>(&value), sizeof(value)};
  return context.core->read_memory(context.core->user, address, destination)
             .code == ANOMALY_STATUS_V1_OK;
}

template <typename T>
bool Write(Context &context, const std::uintptr_t address,
           const T &value) noexcept {
  if (!CoreReady(context.core) || address == 0) return false;
  const AnomalyByteSpanV1 source{
      reinterpret_cast<const std::uint8_t *>(&value), sizeof(value)};
  return context.core->write_memory(context.core->user, address, source).code ==
         ANOMALY_STATUS_V1_OK;
}

bool AddAddress(const std::uintptr_t base, const std::uint64_t offset,
                std::uintptr_t &result) noexcept {
  if (base == 0 || offset > (std::numeric_limits<std::uintptr_t>::max)() - base)
    return false;
  result = base + static_cast<std::uintptr_t>(offset);
  return true;
}

bool ResolveGWorld(Context &context) noexcept {
  if (!SignatureReady(context.signature)) return false;
  std::uintptr_t instruction{};
  if (context.signature->resolve(
          context.signature->user, anomaly::sdk::StringView("HTGame.exe"),
          anomaly::sdk::StringView(".text"),
          anomaly::sdk::StringView(kGWorldPattern), &instruction)
          .code != ANOMALY_STATUS_V1_OK ||
      instruction == 0)
    return false;
  std::int32_t displacement{};
  if (!Read(context, instruction + kGWorldDisplacementOffset, displacement))
    return false;
  const auto resolved = static_cast<std::intptr_t>(instruction) +
                        kGWorldInstructionSize + displacement;
  if (resolved <= 0) return false;
  context.g_world_address = static_cast<std::uintptr_t>(resolved);
  return true;
}

bool ReadPointerAt(Context &context, const std::uintptr_t base,
                   const std::uint32_t offset,
                   std::uintptr_t &value) noexcept {
  std::uintptr_t address{};
  return AddAddress(base, offset, address) && Read(context, address, value) &&
         value != 0;
}

bool ResolveCameraManager(Context &context,
                          std::uintptr_t &camera_manager) noexcept {
  camera_manager = 0;
  std::uintptr_t world{};
  std::uintptr_t game_instance{};
  std::uintptr_t local_players{};
  std::uintptr_t local_player{};
  std::uintptr_t controller{};
  return Read(context, context.g_world_address, world) &&
         ReadPointerAt(context, world, kWorldGameInstanceOffset,
                       game_instance) &&
         ReadPointerAt(context, game_instance, kGameInstanceLocalPlayersOffset,
                       local_players) &&
         Read(context, local_players, local_player) && local_player != 0 &&
         ReadPointerAt(context, local_player, kLocalPlayerControllerOffset,
                       controller) &&
         ReadPointerAt(context, controller, kControllerCameraManagerOffset,
                       camera_manager);
}

template <typename T>
bool WriteAt(Context &context, const std::uintptr_t base,
             const std::uint32_t offset, const T &value) noexcept {
  std::uintptr_t address{};
  return AddAddress(base, offset, address) && Write(context, address, value);
}

bool WriteNormalSetting(Context &context, const std::uintptr_t manager,
                        const std::uint32_t offset, const float value) noexcept {
  std::uintptr_t settings{};
  return AddAddress(manager, kNormalCameraSettingsOffset, settings) &&
         WriteAt(context, settings, offset, value);
}

bool RestoreState(Context &context) noexcept {
  if (!context.saved_state || context.patched_manager == 0) return true;
  const auto manager = context.patched_manager;
  bool ok = WriteAt(context, manager, kPlayerFadeSpeedOffset,
                    context.saved_fade_speed);
  ok = WriteAt(context, manager, kPlayerFadeDistanceSquareOffset,
               context.saved_fade_distance) && ok;
  ok = WriteAt(context, manager, kPlayerHideDistanceSquareOffset,
               context.saved_hide_distance) && ok;
  ok = WriteAt(context, manager, kPlayerPitchFadeCurveOffset,
               context.saved_pitch_curve) && ok;
  ok = WriteNormalSetting(context, manager,
                          kNormalPlayerFadeDistanceTargetOffset,
                          context.saved_normal_fade_distance) && ok;
  ok = WriteNormalSetting(context, manager,
                          kNormalPlayerHideDistanceTargetOffset,
                          context.saved_normal_hide_distance) && ok;
  if (ok) {
    context.patched_manager = 0;
    context.saved_state = false;
  }
  return ok;
}

bool SaveState(Context &context, const std::uintptr_t manager) noexcept {
  if (context.saved_state && context.patched_manager == manager) return true;
  if (context.saved_state && !RestoreState(context)) return false;
  std::uintptr_t settings{};
  std::uintptr_t fade_address{};
  std::uintptr_t hide_address{};
  if (!AddAddress(manager, kNormalCameraSettingsOffset, settings) ||
      !AddAddress(settings, kNormalPlayerFadeDistanceTargetOffset,
                  fade_address) ||
      !AddAddress(settings, kNormalPlayerHideDistanceTargetOffset,
                  hide_address) ||
      !Read(context, manager + kPlayerFadeSpeedOffset,
            context.saved_fade_speed) ||
      !Read(context, manager + kPlayerFadeDistanceSquareOffset,
            context.saved_fade_distance) ||
      !Read(context, manager + kPlayerHideDistanceSquareOffset,
            context.saved_hide_distance) ||
      !Read(context, manager + kPlayerPitchFadeCurveOffset,
            context.saved_pitch_curve) ||
      !Read(context, fade_address, context.saved_normal_fade_distance) ||
      !Read(context, hide_address, context.saved_normal_hide_distance))
    return false;
  context.patched_manager = manager;
  context.saved_state = true;
  return true;
}

bool Apply(Context &context, const std::uintptr_t manager) noexcept {
  if (!SaveState(context, manager)) return false;
  constexpr float kDisabledDistance = 0.0F;
  bool ok = WriteAt(context, manager, kPlayerFadeSpeedOffset,
                    context.saved_fade_speed);
  ok = WriteAt(context, manager, kPlayerFadeDistanceSquareOffset,
               kDisabledDistance) && ok;
  ok = WriteAt(context, manager, kPlayerHideDistanceSquareOffset,
               kDisabledDistance) && ok;
  const std::uintptr_t no_curve = 0;
  ok = WriteAt(context, manager, kPlayerPitchFadeCurveOffset, no_curve) && ok;
  ok = WriteNormalSetting(context, manager,
                          kNormalPlayerFadeDistanceTargetOffset,
                          kDisabledDistance) && ok;
  ok = WriteNormalSetting(context, manager,
                          kNormalPlayerHideDistanceTargetOffset,
                          kDisabledDistance) && ok;
  if (!ok) return false;
  if (!context.logged_patch) {
    char message[160]{};
    std::snprintf(message, sizeof(message),
                  "anti-blur applied manager=0x%llX source=0",
                  static_cast<unsigned long long>(manager));
    Log(context, ANOMALY_CORE_LOG_LEVEL_V1_INFO, message);
    context.logged_patch = true;
  }
  return true;
}

AnomalyStatusV1 Load(const AnomalyHostApiV1 *host, void **plugin_context) {
  if (host == nullptr || plugin_context == nullptr)
    return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
  *plugin_context = nullptr;
  auto *context = new (std::nothrow) Context();
  if (context == nullptr) return Status(ANOMALY_STATUS_V1_FAILED);
  context->core = Query<AnomalyCoreServiceV1>(
      host, ANOMALY_CORE_SERVICE_V1_ID, ANOMALY_CORE_SERVICE_V1_VERSION);
  context->signature = Query<AnomalySignatureServiceV1>(
      host, ANOMALY_SIGNATURE_SERVICE_V1_ID,
      ANOMALY_SIGNATURE_SERVICE_V1_VERSION);
  if (!CoreReady(context->core) || !SignatureReady(context->signature)) {
    delete context;
    return Status(ANOMALY_STATUS_V1_UNAVAILABLE,
                  "core and signature services are unavailable");
  }
  *plugin_context = context;
  return anomaly::sdk::Ok();
}

AnomalyStatusV1 Start(void *plugin_context) noexcept {
  auto *context = static_cast<Context *>(plugin_context);
  if (context == nullptr) return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
  context->g_world_address = 0;
  context->patched_manager = 0;
  context->saved_state = false;
  context->logged_world = false;
  context->logged_patch = false;
  Log(*context, ANOMALY_CORE_LOG_LEVEL_V1_INFO, "anti-blur started");
  return anomaly::sdk::Ok();
}

AnomalyStatusV1 Stop(void *plugin_context, std::uint32_t) noexcept {
  auto *context = static_cast<Context *>(plugin_context);
  if (context != nullptr) static_cast<void>(RestoreState(*context));
  return anomaly::sdk::Ok();
}

void Unload(void *plugin_context) noexcept {
  auto *context = static_cast<Context *>(plugin_context);
  if (context == nullptr) return;
  static_cast<void>(Stop(context, 0));
  delete context;
}

void Update(void *plugin_context, double) noexcept {
  auto *context = static_cast<Context *>(plugin_context);
  if (context == nullptr) return;
  try {
    if (context->g_world_address == 0 && !ResolveGWorld(*context)) {
      if (!context->logged_world) {
        Log(*context, ANOMALY_CORE_LOG_LEVEL_V1_WARNING,
            "anti-blur could not resolve GWorld");
        context->logged_world = true;
      }
      return;
    }
    std::uintptr_t camera_manager{};
    if (ResolveCameraManager(*context, camera_manager)) {
      static_cast<void>(Apply(*context, camera_manager));
    } else {
      context->g_world_address = 0;
    }
  } catch (...) {
  }
}

}  // namespace

ANOMALY_SDK_EXPORT AnomalyStatusV1 ANOMALY_CALL AnomalyPluginEntryV1(
    AnomalyPluginDescriptorV1 *descriptor) {
  if (descriptor == nullptr || descriptor->struct_size < sizeof(*descriptor))
    return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
  *descriptor = {
      sizeof(*descriptor), ANOMALY_PLUGIN_API_V1_MAJOR,
      ANOMALY_PLUGIN_API_V1_MINOR,
      anomaly::sdk::StringView("anomaly.local.nte.camera-blur-fix"),
      anomaly::sdk::StringView("\xE5\x8F\x8D\xE8\x99\x9A\xE5\x8C\x96"),
      anomaly::sdk::StringView("Anomaly"),
      anomaly::sdk::StringView("1.0.0"), Load, Start, Stop, Unload, Update,
      nullptr};
  return anomaly::sdk::Ok();
}
