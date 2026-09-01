#pragma once

#include "anomaly/hook_manager.hpp"

#include <array>
#include <chrono>
#include <functional>
#include <memory>
#include <vector>

namespace anomaly {

inline constexpr std::size_t kUe5CombatExecFunctionCapacity = 14;

struct Ue5CombatExecFunctionTarget {
    void* function{};
    void* target{};
};

struct Ue5DamageFunctionTargets {
    void* character_on_damaged{};
    std::array<Ue5CombatExecFunctionTarget, kUe5CombatExecFunctionCapacity>
        combat_exec_functions{};
    std::size_t combat_exec_function_count{};
};

class Ue5DamageFunctionHook final {
public:
    using Callback = std::function<void(
        std::uintptr_t damage_event,
        std::uintptr_t victim,
        std::uintptr_t attacker,
        std::uintptr_t damage_causer)>;
    using ExecCallback = std::function<void(
        std::uintptr_t function,
        std::uintptr_t receiver,
        std::uintptr_t stack)>;

    explicit Ue5DamageFunctionHook(
        Callback callback, ExecCallback exec_callback = {});
    Ue5DamageFunctionHook(
        std::unique_ptr<HookBackend> backend,
        Callback callback,
        ExecCallback exec_callback = {});
    ~Ue5DamageFunctionHook();

    Ue5DamageFunctionHook(const Ue5DamageFunctionHook&) = delete;
    Ue5DamageFunctionHook& operator=(const Ue5DamageFunctionHook&) = delete;

    [[nodiscard]] bool Start(Ue5DamageFunctionTargets targets);
    bool Stop(
        std::chrono::milliseconds timeout = std::chrono::seconds(5)) noexcept;
    [[nodiscard]] bool Attempted() const noexcept;
    [[nodiscard]] bool Started() const noexcept;
    [[nodiscard]] std::vector<HookRecordView> Snapshot() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace anomaly
