#pragma once

#include "anomaly/hook_manager.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace anomaly {

// AHUD-only ingress. It is kept separate from the shared UObject ProcessEvent
// detour because NTE dispatches AHUD frames through AActor::ProcessEvent; the
// generic UObject detour remains the single SDK fan-out point.
class Ue5ActorProcessEventHook final {
public:
    using Callback = std::function<void(
        std::uintptr_t object,
        std::uintptr_t function,
        void* parameters)>;

    explicit Ue5ActorProcessEventHook(Callback callback);
    Ue5ActorProcessEventHook(
        std::unique_ptr<HookBackend> backend, Callback callback);
    ~Ue5ActorProcessEventHook();

    Ue5ActorProcessEventHook(const Ue5ActorProcessEventHook&) = delete;
    Ue5ActorProcessEventHook& operator=(const Ue5ActorProcessEventHook&) = delete;

    [[nodiscard]] bool Start(void* target);
    bool Stop(
        std::chrono::milliseconds timeout = std::chrono::seconds(5)) noexcept;
    [[nodiscard]] bool Started() const noexcept;
    [[nodiscard]] std::vector<HookRecordView> Snapshot() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace anomaly
