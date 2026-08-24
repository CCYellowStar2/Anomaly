#pragma once

#include "anomaly/hook_manager.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <vector>

namespace anomaly {

struct Ue5DamageFunctionTargets {
    void* character_on_damaged{};
};

class Ue5DamageFunctionHook final {
public:
    using Callback = std::function<void(
        std::uintptr_t damage_event,
        std::uintptr_t victim,
        std::uintptr_t attacker,
        std::uintptr_t damage_causer)>;

    explicit Ue5DamageFunctionHook(Callback callback);
    Ue5DamageFunctionHook(
        std::unique_ptr<HookBackend> backend,
        Callback callback);
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
