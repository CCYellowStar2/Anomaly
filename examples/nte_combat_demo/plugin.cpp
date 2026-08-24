#include "anomaly/sdk/cpp.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <string_view>

namespace {

constexpr std::uint32_t kSkillPageCapacity = 8;
constexpr std::size_t kRecentDamageCapacity = 12;
constexpr std::size_t kMaximumDrainPerUpdate = 64;
constexpr std::size_t kMaximumResolvedNameBytes = 1024;

struct DamageRow {
    std::array<char, 192> summary{};
    std::array<char, 512> source{};
    std::array<char, 1024> participants{};
};

struct SkillRow {
    std::array<char, 256> name{};
    std::array<char, 384> summary{};
    std::array<char, 128> activation_label{};
    AnomalyGenerationHandleV1 ability_class{};
    AnomalyNteSkillInvocationRequestV1 activation{sizeof(activation)};
    std::uint64_t skill_id{};
    bool skill_current{};
    bool can_activate{};
};

struct RenderSnapshot {
    std::uint32_t combat_status{ANOMALY_STATUS_V1_UNAVAILABLE};
    std::array<char, 192> combat_header{};
    bool has_combatant{};
    AnomalyNteCombatantSnapshotV1 combatant{sizeof(combatant)};
    std::array<char, 256> hp{};
    std::array<char, 256> state{};
    std::array<char, 256> outgoing{};
    std::array<char, 256> incoming{};
    bool statistics_initialized{};

    std::uint32_t damage_status{ANOMALY_STATUS_V1_UNAVAILABLE};
    std::array<char, 192> damage_header{};
    std::uint64_t latest_damage_sequence{};
    AnomalyGenerationHandleV1 damage_world{};
    std::array<DamageRow, kRecentDamageCapacity> damage_rows{};
    std::size_t damage_row_count{};

    std::uint32_t skills_status{ANOMALY_STATUS_V1_UNAVAILABLE};
    std::array<char, 192> skills_header{};
    std::uint64_t skill_generation{};
    std::uint64_t skill_sequence{};
    std::uint32_t skill_offset{};
    std::uint32_t skill_total{};
    std::uint32_t skill_next_offset{};
    std::array<SkillRow, kSkillPageCapacity> skill_rows{};
    std::size_t skill_row_count{};

    bool invocation_available{};
    bool has_activation_result{};
    std::array<char, 256> activation_result{};
};

struct PendingActivation {
    AnomalyNteSkillInvocationRequestV1 request{sizeof(request)};
    std::uint64_t skill_id{};
};

struct Context {
    const AnomalyHostApiV1* host{};
    const AnomalyUiServiceV1* ui{};
    std::mutex state_mutex;
    RenderSnapshot snapshot;
    PendingActivation pending_activation;
    bool activation_queued{};
    std::uint32_t requested_skill_offset{};
    std::uint64_t damage_cursor{};
} g_context;

template <typename Struct, typename Field>
bool HasField(const Struct* value, const std::size_t offset) noexcept {
    return value != nullptr && value->struct_size >= offset + sizeof(Field);
}

const char* StatusName(const std::uint32_t code) noexcept {
    switch (code) {
    case ANOMALY_STATUS_V1_OK: return "OK";
    case ANOMALY_STATUS_V1_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
    case ANOMALY_STATUS_V1_UNAVAILABLE: return "UNAVAILABLE";
    case ANOMALY_STATUS_V1_NOT_FOUND: return "NOT_FOUND";
    case ANOMALY_STATUS_V1_BUFFER_TOO_SMALL: return "BUFFER_TOO_SMALL";
    case ANOMALY_STATUS_V1_FAILED: return "FAILED";
    case ANOMALY_STATUS_V1_TIMEOUT: return "TIMEOUT";
    case ANOMALY_STATUS_V1_PERMISSION_DENIED: return "PERMISSION_DENIED";
    case ANOMALY_STATUS_V1_CONFLICT: return "CONFLICT";
    case ANOMALY_STATUS_V1_CANCELLED: return "CANCELLED";
    default: return "UNKNOWN_STATUS";
    }
}

bool SameHandle(
    const AnomalyGenerationHandleV1 left,
    const AnomalyGenerationHandleV1 right) noexcept {
    return left.id == right.id && left.generation == right.generation;
}

bool CombatMethodsAvailable(const AnomalyNteCombatServiceV1* service) noexcept {
    return HasField<AnomalyNteCombatServiceV1,
               decltype(AnomalyNteCombatServiceV1::participant_path_utf8)>(
               service, offsetof(AnomalyNteCombatServiceV1, participant_path_utf8)) &&
        service->current_combatant != nullptr &&
        service->latest_damage_sequence != nullptr &&
        service->next_damage_event != nullptr &&
        service->statistics != nullptr &&
        service->source_name_utf8 != nullptr &&
        service->participant_path_utf8 != nullptr;
}

bool SkillMethodsAvailable(const AnomalyNteSkillsServiceV1* service) noexcept {
    return HasField<AnomalyNteSkillsServiceV1,
               decltype(AnomalyNteSkillsServiceV1::snapshot_by_handle)>(
               service, offsetof(AnomalyNteSkillsServiceV1, snapshot_by_handle)) &&
        service->frame != nullptr && service->page != nullptr &&
        service->ability_path_utf8 != nullptr;
}

bool InvocationMethodsAvailable(
    const AnomalyNteSkillInvocationServiceV1* service) noexcept {
    return HasField<AnomalyNteSkillInvocationServiceV1,
               decltype(AnomalyNteSkillInvocationServiceV1::activate)>(
               service, offsetof(AnomalyNteSkillInvocationServiceV1, activate)) &&
        service->activate != nullptr;
}

bool IsSizingStatus(const AnomalyStatusV1 status) noexcept {
    return status.code == ANOMALY_STATUS_V1_OK ||
        status.code == ANOMALY_STATUS_V1_BUFFER_TOO_SMALL;
}

std::string ResolveDamageSource(
    const AnomalyNteCombatServiceV1* service,
    const std::uint64_t source_id) {
    if (source_id == 0) return "unknown-source";
    std::size_t size{};
    if (!IsSizingStatus(service->source_name_utf8(
            service->user, source_id, nullptr, &size)) ||
        size <= 1 || size > kMaximumResolvedNameBytes) {
        return "unknown-source";
    }
    std::string value(size, '\0');
    if (service->source_name_utf8(
            service->user, source_id, value.data(), &size).code !=
        ANOMALY_STATUS_V1_OK) {
        return "unknown-source";
    }
    if (const auto end = value.find('\0'); end != std::string::npos) value.resize(end);
    return value.empty() ? "unknown-source" : value;
}

std::string ResolveDamageParticipant(
    const AnomalyNteCombatServiceV1* service,
    const AnomalyGenerationHandleV1 participant) {
    if (participant.id == 0) return "unknown-participant";
    std::size_t size{};
    if (!IsSizingStatus(service->participant_path_utf8(
            service->user, participant, nullptr, &size)) ||
        size <= 1 || size > kMaximumResolvedNameBytes) {
        return "unknown-participant";
    }
    std::string value(size, '\0');
    if (service->participant_path_utf8(
            service->user, participant, value.data(), &size).code !=
        ANOMALY_STATUS_V1_OK) {
        return "unknown-participant";
    }
    if (const auto end = value.find('\0'); end != std::string::npos) value.resize(end);
    return value.empty() ? "unknown-participant" : value;
}

std::string ResolveAbilityPath(
    const AnomalyNteSkillsServiceV1* service,
    const AnomalyGenerationHandleV1 ability_class) {
    if (ability_class.id == 0) return {};
    std::size_t size{};
    if (!IsSizingStatus(service->ability_path_utf8(
            service->user, ability_class, nullptr, &size)) ||
        size <= 1 || size > kMaximumResolvedNameBytes) {
        return {};
    }
    std::string value(size, '\0');
    if (service->ability_path_utf8(
            service->user, ability_class, value.data(), &size).code !=
        ANOMALY_STATUS_V1_OK) {
        return {};
    }
    if (const auto end = value.find('\0'); end != std::string::npos) value.resize(end);
    return value;
}

std::string ShortAbilityName(const std::string& path, const std::uint64_t skill_id) {
    if (path.empty()) return "Skill #" + std::to_string(skill_id);
    const std::size_t separator = path.find_last_of("./:");
    const std::string_view leaf = separator == std::string::npos
        ? std::string_view(path)
        : std::string_view(path).substr(separator + 1);
    constexpr std::size_t kMaximumLabelBytes = 72;
    if (leaf.size() <= kMaximumLabelBytes) return std::string(leaf);
    return std::string(leaf.substr(0, kMaximumLabelBytes - 3)) + "...";
}

DamageRow FormatDamageRow(
    const AnomalyNteCombatServiceV1* service,
    const AnomalyNteDamageEventV1& event) {
    const std::string source = ResolveDamageSource(service, event.source_id);
    const std::string attacker = ResolveDamageParticipant(service, event.attacker);
    const std::string victim = ResolveDamageParticipant(service, event.victim);

    DamageRow row;
    std::snprintf(
        row.summary.data(), row.summary.size(), "#%llu damage=%lld tick=%llu",
        static_cast<unsigned long long>(event.sequence),
        static_cast<long long>(event.final_damage),
        static_cast<unsigned long long>(event.tick_sequence));
    std::snprintf(
        row.source.data(), row.source.size(), "source=%s [0x%llX]",
        source.c_str(), static_cast<unsigned long long>(event.source_id));
    std::snprintf(
        row.participants.data(), row.participants.size(),
        "attacker=%s [%llu:%llu]  victim=%s [%llu:%llu]",
        attacker.c_str(), static_cast<unsigned long long>(event.attacker.id),
        static_cast<unsigned long long>(event.attacker.generation), victim.c_str(),
        static_cast<unsigned long long>(event.victim.id),
        static_cast<unsigned long long>(event.victim.generation));
    return row;
}

void PushDamageRow(RenderSnapshot& snapshot, const DamageRow& row) noexcept {
    const std::size_t new_count = (std::min)(
        snapshot.damage_row_count + 1U, snapshot.damage_rows.size());
    for (std::size_t index = new_count; index > 1; --index) {
        snapshot.damage_rows[index - 1] = snapshot.damage_rows[index - 2];
    }
    snapshot.damage_rows[0] = row;
    snapshot.damage_row_count = new_count;
}

bool DrainDamage(
    const AnomalyNteCombatServiceV1* combat,
    RenderSnapshot& snapshot) {
    const std::uint64_t latest = combat->latest_damage_sequence(combat->user);
    snapshot.damage_status = ANOMALY_STATUS_V1_OK;
    snapshot.latest_damage_sequence = latest;
    if (latest == g_context.damage_cursor) return false;

    bool accepted{};
    bool rebuilt_window{};
    if (latest < g_context.damage_cursor) {
        g_context.damage_cursor = 0;
        snapshot.damage_row_count = 0;
        snapshot.damage_world = {};
        rebuilt_window = true;
    }

    for (std::size_t index{}; index < kMaximumDrainPerUpdate; ++index) {
        AnomalyNteDamageEventV1 event{sizeof(event)};
        const AnomalyStatusV1 status = combat->next_damage_event(
            combat->user, g_context.damage_cursor, &event);
        if (status.code == ANOMALY_STATUS_V1_OK) {
            if (event.sequence <= g_context.damage_cursor) {
                snapshot.damage_status = ANOMALY_STATUS_V1_FAILED;
                break;
            }
            if (snapshot.damage_world.id != 0 &&
                !SameHandle(snapshot.damage_world, event.world)) {
                snapshot.damage_row_count = 0;
            }
            snapshot.damage_world = event.world;
            g_context.damage_cursor = event.sequence;
            PushDamageRow(snapshot, FormatDamageRow(combat, event));
            accepted = true;
            continue;
        }
        if (status.code == ANOMALY_STATUS_V1_NOT_FOUND) {
            if (!rebuilt_window && g_context.damage_cursor != 0 &&
                latest > g_context.damage_cursor) {
                g_context.damage_cursor = 0;
                snapshot.damage_row_count = 0;
                snapshot.damage_world = {};
                rebuilt_window = true;
                continue;
            }
            break;
        }
        snapshot.damage_status = status.code;
        break;
    }
    return accepted;
}

bool ReadStatistics(
    const AnomalyNteCombatServiceV1* combat,
    const AnomalyNteCombatantSnapshotV1& combatant,
    const std::uint32_t direction,
    AnomalyNteCombatStatisticsV1& statistics) {
    AnomalyNteCombatStatisticsRequestV1 request{sizeof(request)};
    request.world = combatant.world;
    request.character = combatant.character;
    request.direction = direction;
    statistics = {sizeof(statistics)};
    return combat->statistics(combat->user, &request, &statistics).code ==
        ANOMALY_STATUS_V1_OK;
}

bool UpdateCombat(
    const AnomalyNteCombatServiceV1* combat,
    RenderSnapshot& snapshot) {
    if (!CombatMethodsAvailable(combat)) {
        snapshot.combat_status = ANOMALY_STATUS_V1_UNAVAILABLE;
        snapshot.damage_status = ANOMALY_STATUS_V1_UNAVAILABLE;
        snapshot.has_combatant = false;
        return false;
    }

    const bool damage_changed = DrainDamage(combat, snapshot);
    AnomalyNteCombatantSnapshotV1 combatant{sizeof(combatant)};
    const AnomalyStatusV1 status = combat->current_combatant(combat->user, &combatant);
    snapshot.combat_status = status.code;
    const bool valid = status.code == ANOMALY_STATUS_V1_OK &&
        (combatant.flags & ANOMALY_NTE_COMBATANT_V1_VALID) != 0 &&
        (combatant.flags & ANOMALY_NTE_COMBATANT_V1_STALE) == 0;
    if (!valid) {
        snapshot.has_combatant = false;
        snapshot.statistics_initialized = false;
        return false;
    }

    const bool combatant_changed = !snapshot.has_combatant ||
        !SameHandle(snapshot.combatant.world, combatant.world) ||
        !SameHandle(snapshot.combatant.character, combatant.character);
    snapshot.has_combatant = true;
    snapshot.combatant = combatant;

    const double hp_percent = combatant.max_hp > 0.0
        ? std::clamp(combatant.hp / combatant.max_hp * 100.0, 0.0, 100.0)
        : 0.0;
    std::snprintf(
        snapshot.hp.data(), snapshot.hp.size(),
        "HP %.1f / %.1f (%.1f%%)  Shield %.1f",
        combatant.hp, combatant.max_hp, hp_percent, combatant.shield);
    std::snprintf(
        snapshot.state.data(), snapshot.state.size(), "State %s  Sample %llu%s",
        (combatant.flags & ANOMALY_NTE_COMBATANT_V1_DEAD) != 0 ? "DEAD" : "ALIVE",
        static_cast<unsigned long long>(combatant.sequence),
        (combatant.flags & ANOMALY_NTE_COMBATANT_V1_PARTIAL) != 0 ? "  PARTIAL" : "");

    if (damage_changed || combatant_changed || !snapshot.statistics_initialized) {
        AnomalyNteCombatStatisticsV1 outgoing{sizeof(outgoing)};
        AnomalyNteCombatStatisticsV1 incoming{sizeof(incoming)};
        const bool has_outgoing = ReadStatistics(
            combat, combatant, ANOMALY_NTE_COMBAT_DIRECTION_V1_AS_ATTACKER, outgoing);
        const bool has_incoming = ReadStatistics(
            combat, combatant, ANOMALY_NTE_COMBAT_DIRECTION_V1_AS_VICTIM, incoming);
        snapshot.statistics_initialized = true;
        if (has_outgoing) {
            std::snprintf(
                snapshot.outgoing.data(), snapshot.outgoing.size(),
                "Outgoing: %llu hits / %lld final",
                static_cast<unsigned long long>(outgoing.hit_count),
                static_cast<long long>(outgoing.final_damage_total));
        } else {
            std::snprintf(
                snapshot.outgoing.data(), snapshot.outgoing.size(),
                "Outgoing statistics: UNAVAILABLE");
        }
        if (has_incoming) {
            std::snprintf(
                snapshot.incoming.data(), snapshot.incoming.size(),
                "Incoming: %llu hits / %lld final",
                static_cast<unsigned long long>(incoming.hit_count),
                static_cast<long long>(incoming.final_damage_total));
        } else {
            std::snprintf(
                snapshot.incoming.data(), snapshot.incoming.size(),
                "Incoming statistics: UNAVAILABLE");
        }
    }
    return true;
}

const SkillRow* FindPreviousSkill(
    const std::array<SkillRow, kSkillPageCapacity>& rows,
    const std::size_t count,
    const AnomalyGenerationHandleV1 ability_class) noexcept {
    for (std::size_t index{}; index < count; ++index) {
        if (SameHandle(rows[index].ability_class, ability_class)) return &rows[index];
    }
    return nullptr;
}

void UpdateSkillActivation(
    SkillRow& row,
    const AnomalyNteSkillSnapshotV1& skill,
    const AnomalyNteCombatantSnapshotV1* combatant) noexcept {
    row.activation = {};
    row.activation.struct_size = sizeof(row.activation);
    row.skill_id = skill.handle.id;
    row.activation.character = skill.character;
    row.activation.skill = skill.handle;
    if (combatant != nullptr) row.activation.world = combatant->world;
    row.skill_current =
        (skill.flags & ANOMALY_NTE_SKILL_V1_VALID) != 0 &&
        (skill.flags & ANOMALY_NTE_SKILL_V1_STALE) == 0;
    row.can_activate = combatant != nullptr && row.skill_current;
    std::snprintf(
        row.activation_label.data(), row.activation_label.size(),
        "Activate##skill-%llu", static_cast<unsigned long long>(row.skill_id));
}

void UpdateSkills(
    const AnomalyNteSkillsServiceV1* skills,
    const AnomalyNteCombatantSnapshotV1* combatant,
    const std::uint32_t requested_offset,
    RenderSnapshot& snapshot) {
    if (!SkillMethodsAvailable(skills)) {
        snapshot.skills_status = ANOMALY_STATUS_V1_UNAVAILABLE;
        snapshot.skill_row_count = 0;
        snapshot.skill_total = 0;
        return;
    }

    AnomalyNteSkillFrameV1 frame{sizeof(frame)};
    const AnomalyStatusV1 frame_status = skills->frame(skills->user, &frame);
    snapshot.skills_status = frame_status.code;
    if (frame_status.code != ANOMALY_STATUS_V1_OK) {
        snapshot.skill_row_count = 0;
        snapshot.skill_total = 0;
        return;
    }

    std::uint32_t offset = requested_offset;
    if (snapshot.skill_generation != frame.generation) offset = 0;
    if (offset >= frame.skill_count && frame.skill_count != 0) {
        offset = ((frame.skill_count - 1U) / kSkillPageCapacity) * kSkillPageCapacity;
    }
    if (snapshot.skill_generation == frame.generation &&
        snapshot.skill_sequence == frame.sequence &&
        snapshot.skill_offset == offset) {
        for (std::size_t index{}; index < snapshot.skill_row_count; ++index) {
            SkillRow& row = snapshot.skill_rows[index];
            row.activation.world = combatant != nullptr
                ? combatant->world
                : AnomalyGenerationHandleV1{};
            row.can_activate = combatant != nullptr && row.skill_current;
        }
        return;
    }

    std::array<AnomalyNteSkillSnapshotV1, kSkillPageCapacity> skills_page{};
    for (auto& skill : skills_page) skill.struct_size = sizeof(skill);
    AnomalyNteSkillPageRequestV1 request{sizeof(request)};
    request.generation = frame.generation;
    request.offset = offset;
    request.capacity = kSkillPageCapacity;
    AnomalyNteSkillPageResultV1 page{sizeof(page)};
    AnomalyStatusV1 page_status = skills->page(
        skills->user, &request, skills_page.data(), &page);
    if (page_status.code == ANOMALY_STATUS_V1_NOT_FOUND) {
        request.generation = 0;
        request.offset = 0;
        offset = 0;
        page = {sizeof(page)};
        page_status = skills->page(skills->user, &request, skills_page.data(), &page);
    }
    snapshot.skills_status = page_status.code;
    if (page_status.code != ANOMALY_STATUS_V1_OK) {
        snapshot.skill_row_count = 0;
        snapshot.skill_total = 0;
        return;
    }

    const auto previous_rows = snapshot.skill_rows;
    const std::size_t previous_count = snapshot.skill_row_count;
    snapshot.skill_row_count = (std::min)(
        static_cast<std::size_t>(page.returned), snapshot.skill_rows.size());
    for (std::size_t index{}; index < snapshot.skill_row_count; ++index) {
        const AnomalyNteSkillSnapshotV1& skill = skills_page[index];
        SkillRow row;
        row.ability_class = skill.ability_class;
        if (const SkillRow* previous = FindPreviousSkill(
                previous_rows, previous_count, skill.ability_class)) {
            row.name = previous->name;
        } else {
            const std::string name = ShortAbilityName(
                ResolveAbilityPath(skills, skill.ability_class), skill.handle.id);
            std::snprintf(row.name.data(), row.name.size(), "%s", name.c_str());
        }
        if ((skill.flags & ANOMALY_NTE_SKILL_V1_COOLDOWN_VALID) != 0) {
            std::snprintf(
                row.summary.data(), row.summary.size(),
                "%s  level=%d input=%d cooldown=%.2f/%.2f%s",
                row.name.data(), skill.level, skill.input_id,
                skill.cooldown_remaining_seconds, skill.cooldown_duration_seconds,
                (skill.flags & ANOMALY_NTE_SKILL_V1_ACTIVE) != 0 ? " ACTIVE" : "");
        } else {
            std::snprintf(
                row.summary.data(), row.summary.size(),
                "%s  level=%d input=%d cooldown=unavailable%s",
                row.name.data(), skill.level, skill.input_id,
                (skill.flags & ANOMALY_NTE_SKILL_V1_ACTIVE) != 0 ? " ACTIVE" : "");
        }
        UpdateSkillActivation(row, skill, combatant);
        snapshot.skill_rows[index] = row;
    }
    snapshot.skill_generation = page.generation;
    snapshot.skill_sequence = page.sequence;
    snapshot.skill_offset = offset;
    snapshot.skill_total = page.total_skills;
    snapshot.skill_next_offset = page.next_offset;
}

void FormatHeaders(RenderSnapshot& snapshot) noexcept {
    std::snprintf(
        snapshot.combat_header.data(), snapshot.combat_header.size(),
        "Combat snapshot: %s", StatusName(snapshot.combat_status));
    std::snprintf(
        snapshot.damage_header.data(), snapshot.damage_header.size(),
        "Damage stream: %s  latest=%llu", StatusName(snapshot.damage_status),
        static_cast<unsigned long long>(snapshot.latest_damage_sequence));
    std::snprintf(
        snapshot.skills_header.data(), snapshot.skills_header.size(),
        "Skills: %s  granted=%u", StatusName(snapshot.skills_status),
        snapshot.skill_total);
}

void ResetState() {
    g_context.damage_cursor = 0;
    std::scoped_lock lock(g_context.state_mutex);
    g_context.snapshot = {};
    FormatHeaders(g_context.snapshot);
    g_context.pending_activation = {};
    g_context.activation_queued = false;
    g_context.requested_skill_offset = 0;
}

void QueueSkillOffset(const std::uint32_t offset) {
    std::scoped_lock lock(g_context.state_mutex);
    g_context.requested_skill_offset = offset;
}

void QueueActivation(const SkillRow& row) {
    std::scoped_lock lock(g_context.state_mutex);
    if (g_context.activation_queued) return;
    g_context.pending_activation.request = row.activation;
    g_context.pending_activation.skill_id = row.skill_id;
    g_context.activation_queued = true;
}

bool DrawActionButton(
    const AnomalyUiServiceV1* ui,
    const char* label,
    const bool enabled) {
    if (HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::button_enabled)>(
            ui, offsetof(AnomalyUiServiceV1, button_enabled)) &&
        ui->button_enabled != nullptr) {
        return ui->button_enabled(
                   ui->user, anomaly::sdk::StringView(label), 0.0F, 0.0F,
                   enabled ? 1 : 0) != 0;
    }
    return enabled && ui->button != nullptr &&
        ui->button(ui->user, anomaly::sdk::StringView(label), 0.0F, 0.0F) != 0;
}

AnomalyStatusV1 ANOMALY_CALL Load(const AnomalyHostApiV1* host, void** context) {
    if (context == nullptr) return {ANOMALY_STATUS_V1_INVALID_ARGUMENT, 0, {}};
    const auto ui = anomaly::sdk::Host(host).Query<AnomalyUiServiceV1>(
        ANOMALY_UI_SERVICE_V1_ID, ANOMALY_UI_SERVICE_V1_VERSION);
    if (!ui || ui->begin_window == nullptr || ui->end_window == nullptr ||
        ui->text == nullptr) {
        return {ANOMALY_STATUS_V1_UNAVAILABLE, 0, {}};
    }
    g_context.host = host;
    g_context.ui = ui.get();
    ResetState();
    *context = &g_context;
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Start(void* context) {
    if (context != &g_context) return {ANOMALY_STATUS_V1_INVALID_ARGUMENT, 0, {}};
    ResetState();
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Stop(void*, std::uint32_t) {
    ResetState();
    return anomaly::sdk::Ok();
}

void ANOMALY_CALL Unload(void*) {
    ResetState();
    g_context.host = nullptr;
    g_context.ui = nullptr;
}

void ANOMALY_CALL Update(void* context, double) {
    if (context != &g_context || g_context.host == nullptr) return;

    RenderSnapshot next;
    PendingActivation activation;
    bool has_activation{};
    std::uint32_t requested_offset{};
    {
        std::scoped_lock lock(g_context.state_mutex);
        next = g_context.snapshot;
        requested_offset = g_context.requested_skill_offset;
        if (g_context.activation_queued) {
            activation = g_context.pending_activation;
            g_context.activation_queued = false;
            has_activation = true;
        }
    }

    const anomaly::sdk::Host host(g_context.host);
    const auto combat = host.Query<AnomalyNteCombatServiceV1>(
        ANOMALY_NTE_COMBAT_SERVICE_V1_ID, ANOMALY_NTE_COMBAT_SERVICE_V1_VERSION);
    const bool has_combatant = UpdateCombat(combat.get(), next);
    const AnomalyNteCombatantSnapshotV1* combatant = has_combatant
        ? &next.combatant
        : nullptr;

    const auto skills = host.Query<AnomalyNteSkillsServiceV1>(
        ANOMALY_NTE_SKILLS_SERVICE_V1_ID, ANOMALY_NTE_SKILLS_SERVICE_V1_VERSION);
    UpdateSkills(skills.get(), combatant, requested_offset, next);

    const auto invocation = host.Query<AnomalyNteSkillInvocationServiceV1>(
        ANOMALY_NTE_SKILL_INVOCATION_SERVICE_V1_ID,
        ANOMALY_NTE_SKILL_INVOCATION_SERVICE_V1_VERSION);
    next.invocation_available = InvocationMethodsAvailable(invocation.get());
    if (has_activation) {
        AnomalyStatusV1 status{ANOMALY_STATUS_V1_UNAVAILABLE, 0, {}};
        AnomalyNteSkillInvocationResultV1 result{sizeof(result)};
        if (next.invocation_available) {
            status = invocation->activate(
                invocation->user, &activation.request, &result);
        }
        next.has_activation_result = true;
        std::snprintf(
            next.activation_result.data(), next.activation_result.size(),
            "Skill #%llu activation: %s / accepted=%u / tick=%llu",
            static_cast<unsigned long long>(activation.skill_id),
            StatusName(status.code),
            status.code == ANOMALY_STATUS_V1_OK ? result.accepted : 0,
            static_cast<unsigned long long>(
                status.code == ANOMALY_STATUS_V1_OK ? result.tick_sequence : 0));
    }

    FormatHeaders(next);

    std::scoped_lock lock(g_context.state_mutex);
    g_context.snapshot = next;
    if (g_context.requested_skill_offset == requested_offset) {
        g_context.requested_skill_offset = next.skill_offset;
    }
}

void ANOMALY_CALL Draw(void*, const AnomalyUiServiceV1* ui) {
    if (ui == nullptr) ui = g_context.ui;
    if (ui == nullptr || ui->begin_window == nullptr || ui->end_window == nullptr ||
        ui->text == nullptr) {
        return;
    }

    RenderSnapshot snapshot;
    {
        std::scoped_lock lock(g_context.state_mutex);
        snapshot = g_context.snapshot;
    }

    int open = 1;
    anomaly::sdk::UiWindow window(ui, "NTE Combat Demo", &open);
    if (!window) return;

    ui->text(ui->user, anomaly::sdk::StringView(snapshot.combat_header.data()));
    if (snapshot.has_combatant) {
        ui->text(ui->user, anomaly::sdk::StringView(snapshot.hp.data()));
        ui->text(ui->user, anomaly::sdk::StringView(snapshot.state.data()));
        ui->text(ui->user, anomaly::sdk::StringView(snapshot.outgoing.data()));
        ui->text(ui->user, anomaly::sdk::StringView(snapshot.incoming.data()));
    }

    ui->text(ui->user, anomaly::sdk::StringView(snapshot.damage_header.data()));
    if (snapshot.damage_row_count == 0) {
        ui->text(ui->user, anomaly::sdk::StringView("No retained character damage events"));
    }
    for (std::size_t index{}; index < snapshot.damage_row_count; ++index) {
        const DamageRow& row = snapshot.damage_rows[index];
        ui->text(ui->user, anomaly::sdk::StringView(row.summary.data()));
        ui->text(ui->user, anomaly::sdk::StringView(row.source.data()));
        ui->text(ui->user, anomaly::sdk::StringView(row.participants.data()));
    }

    if (HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::separator)>(
            ui, offsetof(AnomalyUiServiceV1, separator)) && ui->separator != nullptr) {
        ui->separator(ui->user);
    }
    ui->text(ui->user, anomaly::sdk::StringView(snapshot.skills_header.data()));
    if (snapshot.skills_status == ANOMALY_STATUS_V1_OK) {
        if (DrawActionButton(
                ui, "Previous skill page",
                snapshot.skill_offset >= kSkillPageCapacity)) {
            QueueSkillOffset(snapshot.skill_offset - kSkillPageCapacity);
        }
        if (HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::same_line)>(
                ui, offsetof(AnomalyUiServiceV1, same_line)) && ui->same_line != nullptr) {
            ui->same_line(ui->user, 0.0F, 8.0F);
        }
        if (DrawActionButton(
                ui, "Next skill page",
                snapshot.skill_next_offset < snapshot.skill_total)) {
            QueueSkillOffset(snapshot.skill_next_offset);
        }
    }
    for (std::size_t index{}; index < snapshot.skill_row_count; ++index) {
        const SkillRow& row = snapshot.skill_rows[index];
        ui->text(ui->user, anomaly::sdk::StringView(row.summary.data()));
        if (DrawActionButton(
                ui, row.activation_label.data(),
                snapshot.invocation_available && row.can_activate)) {
            QueueActivation(row);
        }
    }
    if (snapshot.has_activation_result) {
        ui->text(
            ui->user, anomaly::sdk::StringView(snapshot.activation_result.data()));
    }
}

}  // namespace

ANOMALY_SDK_EXPORT AnomalyStatusV1 ANOMALY_CALL AnomalyPluginEntryV1(
    AnomalyPluginDescriptorV1* descriptor) {
    if (descriptor == nullptr || descriptor->struct_size < sizeof(*descriptor)) {
        return {ANOMALY_STATUS_V1_INVALID_ARGUMENT, 0, {}};
    }
    *descriptor = {
        sizeof(*descriptor), ANOMALY_PLUGIN_API_V1_MAJOR, ANOMALY_PLUGIN_API_V1_MINOR,
        anomaly::sdk::StringView("anomaly.example.nte-combat-demo"),
        anomaly::sdk::StringView("NTE Combat Demo"),
        anomaly::sdk::StringView("Anomaly"), anomaly::sdk::StringView("1.1.0"),
        Load, Start, Stop, Unload, Update, Draw};
    return anomaly::sdk::Ok();
}
