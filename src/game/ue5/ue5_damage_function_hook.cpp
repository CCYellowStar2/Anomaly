#include "anomaly/ue5_damage_function_hook.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

namespace anomaly {
namespace {

inline constexpr std::string_view kOwner = "anomaly.nte.damage-native";
inline constexpr std::uint64_t kGeneration = 1;

}  // namespace

class Ue5DamageFunctionHook::Impl final {
public:
    using NativeFunction = void(__fastcall*)(
        void*, const void*, void*, void*, void*);
    using ExecFunction = void(__fastcall*)(void*, void*, void*);

    Impl(
        std::unique_ptr<HookBackend> backend,
        Callback callback,
        ExecCallback exec_callback)
        : hooks_(std::move(backend)), callback_(std::move(callback)),
          exec_callback_(std::move(exec_callback)) {
        if (!callback_) {
            throw std::invalid_argument("Ue5DamageFunctionHook requires a callback");
        }
    }

    bool Start(const Ue5DamageFunctionTargets targets) {
        std::scoped_lock stop_lock(stop_mutex_);
        if (attempted_.exchange(true, std::memory_order_acq_rel) ||
            targets.character_on_damaged == nullptr ||
            targets.combat_exec_function_count > kUe5CombatExecFunctionCapacity ||
            started_.load(std::memory_order_acquire) || owner_registered_) {
            return false;
        }
        std::scoped_lock process_lock(process_mutex_);
        if (active_.load(std::memory_order_acquire) != nullptr) return false;

        target_ = targets.character_on_damaged;
        original_ = nullptr;
        if (!hooks_.Create(
                std::string(kOwner), kGeneration, "character-on-damaged",
                target_, reinterpret_cast<void*>(&Thunk),
                reinterpret_cast<void**>(&original_))) {
            target_ = nullptr;
            return false;
        }
        owner_registered_ = true;
        exec_count_ = targets.combat_exec_function_count;
        for (std::size_t index{}; index < exec_count_; ++index) {
            const auto& entry = targets.combat_exec_functions[index];
            if (entry.function == nullptr || entry.target == nullptr ||
                !hooks_.Create(
                    std::string(kOwner), kGeneration,
                    "combat-exec-" + std::to_string(index),
                    entry.target,
                    reinterpret_cast<void*>(ThunkForSlot(index)),
                    reinterpret_cast<void**>(&exec_originals_[index]))) {
                static_cast<void>(hooks_.RemoveOwner(kOwner, kGeneration));
                owner_registered_ = false;
                ClearTarget();
                return false;
            }
            exec_functions_[index] = entry.function;
            exec_targets_[index] = entry.target;
        }
        passthrough_.store(
            reinterpret_cast<NativeFunction>(target_), std::memory_order_release);
        for (std::size_t index{}; index < exec_count_; ++index) {
            exec_passthroughs_[index].store(
                reinterpret_cast<ExecFunction>(exec_targets_[index]),
                std::memory_order_release);
        }
        active_.store(this, std::memory_order_release);
        if (!hooks_.EnableOwner(kOwner, kGeneration)) {
            if (hooks_.RemoveOwner(kOwner, kGeneration)) {
                owner_registered_ = false;
                Impl* expected = this;
                static_cast<void>(active_.compare_exchange_strong(
                    expected, nullptr, std::memory_order_acq_rel));
                ClearTarget();
            }
            return false;
        }
        started_.store(true, std::memory_order_release);
        return true;
    }

    bool Stop(const std::chrono::milliseconds timeout) noexcept {
        std::scoped_lock stop_lock(stop_mutex_);
        static_cast<void>(started_.exchange(false, std::memory_order_acq_rel));
        if (!owner_registered_) return true;
        const auto bounded_timeout =
            (std::max)(timeout, std::chrono::milliseconds::zero());
        const bool detours_disabled = hooks_.DisableOwner(kOwner, kGeneration);
        if (!detours_disabled &&
            !hooks_.RemoveOwner(kOwner, kGeneration, bounded_timeout)) {
            return false;
        }
        {
            std::scoped_lock process_lock(process_mutex_);
            Impl* expected = this;
            static_cast<void>(active_.compare_exchange_strong(
                expected, nullptr, std::memory_order_acq_rel));
        }
        if (detours_disabled &&
            !hooks_.RemoveOwner(kOwner, kGeneration, bounded_timeout)) {
            return false;
        }
        owner_registered_ = false;
        ClearTarget();
        return true;
    }

    [[nodiscard]] bool Started() const noexcept {
        return started_.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool Attempted() const noexcept {
        return attempted_.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::vector<HookRecordView> Snapshot() const {
        return hooks_.Snapshot();
    }

private:
    void ClearTarget() noexcept {
        original_ = nullptr;
        target_ = nullptr;
        passthrough_.store(nullptr, std::memory_order_release);
        for (std::size_t index{}; index < kUe5CombatExecFunctionCapacity; ++index) {
            exec_originals_[index] = nullptr;
            exec_functions_[index] = nullptr;
            exec_targets_[index] = nullptr;
            exec_passthroughs_[index].store(nullptr, std::memory_order_release);
        }
        exec_count_ = 0;
    }

    static void Dispatch(
        void* const delegate,
        const void* const damage_event,
        void* const victim,
        void* const attacker,
        void* const damage_causer) noexcept {
        Impl* self{};
        NativeFunction original{};
        PluginScope::CallbackLease lease;
        {
            std::scoped_lock process_lock(process_mutex_);
            self = active_.load(std::memory_order_acquire);
            if (self != nullptr) {
                original = self->original_;
                if (original != nullptr) {
                    lease = self->hooks_.AcquireCallback(
                        kOwner, kGeneration, self->target_);
                }
                if (!lease) self = nullptr;
            }
            if (self == nullptr) {
                original = passthrough_.load(std::memory_order_acquire);
            }
        }
        if (original == nullptr) return;
        if (self != nullptr) {
            try {
                self->callback_(
                    reinterpret_cast<std::uintptr_t>(damage_event),
                    reinterpret_cast<std::uintptr_t>(victim),
                    reinterpret_cast<std::uintptr_t>(attacker),
                    reinterpret_cast<std::uintptr_t>(damage_causer));
            } catch (...) {
            }
        }
        original(delegate, damage_event, victim, attacker, damage_causer);
    }

    static void __fastcall Thunk(
        void* delegate,
        const void* damage_event,
        void* victim,
        void* attacker,
        void* damage_causer) {
        Dispatch(delegate, damage_event, victim, attacker, damage_causer);
    }

    static void DispatchExec(
        const std::size_t slot,
        void* const object,
        void* const stack,
        void* const result) noexcept {
        Impl* self{};
        ExecFunction original{};
        PluginScope::CallbackLease lease;
        {
            std::scoped_lock process_lock(process_mutex_);
            self = active_.load(std::memory_order_acquire);
            if (self != nullptr && slot < self->exec_count_) {
                original = self->exec_originals_[slot];
                if (original != nullptr) {
                    lease = self->hooks_.AcquireCallback(
                        kOwner, kGeneration, self->exec_targets_[slot]);
                }
                if (!lease) self = nullptr;
            } else {
                self = nullptr;
            }
            if (self == nullptr) {
                original = exec_passthroughs_[slot].load(std::memory_order_acquire);
            }
        }
        if (original == nullptr) return;
        if (self != nullptr && self->exec_callback_) {
            try {
                self->exec_callback_(
                    reinterpret_cast<std::uintptr_t>(self->exec_functions_[slot]),
                    reinterpret_cast<std::uintptr_t>(object),
                    reinterpret_cast<std::uintptr_t>(stack));
            } catch (...) {
            }
        }
        original(object, stack, result);
    }

    template <std::size_t Slot>
    static void __fastcall ExecThunk(void* object, void* stack, void* result) {
        DispatchExec(Slot, object, stack, result);
    }

    static ExecFunction ThunkForSlot(const std::size_t slot) noexcept {
        switch (slot) {
        case 0: return &ExecThunk<0>;
        case 1: return &ExecThunk<1>;
        case 2: return &ExecThunk<2>;
        case 3: return &ExecThunk<3>;
        case 4: return &ExecThunk<4>;
        case 5: return &ExecThunk<5>;
        case 6: return &ExecThunk<6>;
        case 7: return &ExecThunk<7>;
        case 8: return &ExecThunk<8>;
        case 9: return &ExecThunk<9>;
        case 10: return &ExecThunk<10>;
        case 11: return &ExecThunk<11>;
        case 12: return &ExecThunk<12>;
        case 13: return &ExecThunk<13>;
        default: return nullptr;
        }
    }

    HookManager hooks_;
    Callback callback_;
    ExecCallback exec_callback_;
    NativeFunction original_{};
    void* target_{};
    std::array<ExecFunction, kUe5CombatExecFunctionCapacity> exec_originals_{};
    std::array<void*, kUe5CombatExecFunctionCapacity> exec_functions_{};
    std::array<void*, kUe5CombatExecFunctionCapacity> exec_targets_{};
    std::size_t exec_count_{};
    std::atomic_bool started_{};
    std::atomic_bool attempted_{};
    bool owner_registered_{};
    std::mutex stop_mutex_;
    static std::atomic<Impl*> active_;
    static std::atomic<NativeFunction> passthrough_;
    static std::array<std::atomic<ExecFunction>, kUe5CombatExecFunctionCapacity>
        exec_passthroughs_;
    static std::mutex process_mutex_;
};

std::atomic<Ue5DamageFunctionHook::Impl*> Ue5DamageFunctionHook::Impl::active_{};
std::atomic<Ue5DamageFunctionHook::Impl::NativeFunction>
    Ue5DamageFunctionHook::Impl::passthrough_{};
std::array<
    std::atomic<Ue5DamageFunctionHook::Impl::ExecFunction>,
    kUe5CombatExecFunctionCapacity>
    Ue5DamageFunctionHook::Impl::exec_passthroughs_{};
std::mutex Ue5DamageFunctionHook::Impl::process_mutex_;

Ue5DamageFunctionHook::Ue5DamageFunctionHook(
    Callback callback, ExecCallback exec_callback)
    : Ue5DamageFunctionHook(
          CreateMinHookBackend(), std::move(callback), std::move(exec_callback)) {}

Ue5DamageFunctionHook::Ue5DamageFunctionHook(
    std::unique_ptr<HookBackend> backend,
    Callback callback,
    ExecCallback exec_callback)
    : impl_(std::make_unique<Impl>(
          std::move(backend), std::move(callback), std::move(exec_callback))) {}

Ue5DamageFunctionHook::~Ue5DamageFunctionHook() {
    if (impl_ != nullptr && !impl_->Stop(std::chrono::milliseconds::zero())) {
        static_cast<void>(impl_.release());
    }
}

bool Ue5DamageFunctionHook::Start(const Ue5DamageFunctionTargets targets) {
    return impl_->Start(targets);
}

bool Ue5DamageFunctionHook::Stop(
    const std::chrono::milliseconds timeout) noexcept {
    return impl_->Stop(timeout);
}

bool Ue5DamageFunctionHook::Attempted() const noexcept {
    return impl_->Attempted();
}

bool Ue5DamageFunctionHook::Started() const noexcept {
    return impl_->Started();
}

std::vector<HookRecordView> Ue5DamageFunctionHook::Snapshot() const {
    return impl_->Snapshot();
}

}  // namespace anomaly
