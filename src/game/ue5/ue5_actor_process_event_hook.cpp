#include "anomaly/ue5_actor_process_event_hook.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace anomaly {
namespace {

inline constexpr std::string_view kOwner = "anomaly.ue5.actor-process-event";
inline constexpr std::uint64_t kGeneration = 1;

}  // namespace

class Ue5ActorProcessEventHook::Impl final {
public:
    using ProcessEventFunction = void(__fastcall*)(void*, void*, void*);

    Impl(std::unique_ptr<HookBackend> backend, Callback callback)
        : hooks_(std::move(backend)), callback_(std::move(callback)) {
        if (!callback_) {
            throw std::invalid_argument(
                "Ue5ActorProcessEventHook requires callback");
        }
    }

    bool Start(void* target) {
        std::scoped_lock stop_lock(stop_mutex_);
        if (target == nullptr || started_.load(std::memory_order_acquire)) return false;
        if (owner_registered_) return false;
        std::scoped_lock process_lock(process_mutex_);
        if (active_.load(std::memory_order_acquire) != nullptr) return false;
        original_ = nullptr;
        if (!hooks_.Create(
                std::string(kOwner), kGeneration, "actor-process-event", target,
                reinterpret_cast<void*>(&ProcessEventThunk),
                reinterpret_cast<void**>(&original_))) {
            return false;
        }
        owner_registered_ = true;
        passthrough_.store(
            reinterpret_cast<ProcessEventFunction>(target),
            std::memory_order_release);
        active_.store(this, std::memory_order_release);
        if (!hooks_.EnableOwner(kOwner, kGeneration)) {
            if (hooks_.RemoveOwner(kOwner, kGeneration)) {
                owner_registered_ = false;
                Impl* expected = this;
                static_cast<void>(active_.compare_exchange_strong(
                    expected, nullptr, std::memory_order_acq_rel));
                original_ = nullptr;
            }
            return false;
        }
        target_ = target;
        started_.store(true, std::memory_order_release);
        return true;
    }

    bool Stop(const std::chrono::milliseconds timeout) noexcept {
        std::scoped_lock stop_lock(stop_mutex_);
        static_cast<void>(started_.exchange(false, std::memory_order_acq_rel));
        if (!owner_registered_) return true;
        const auto bounded_timeout =
            (std::max)(timeout, std::chrono::milliseconds::zero());
        const bool detour_disabled = hooks_.DisableOwner(kOwner, kGeneration);
        if (!detour_disabled) {
            if (!hooks_.RemoveOwner(kOwner, kGeneration, bounded_timeout)) return false;
        }
        if (detour_disabled) {
            std::scoped_lock process_lock(process_mutex_);
            Impl* expected = this;
            static_cast<void>(active_.compare_exchange_strong(
                expected, nullptr, std::memory_order_acq_rel));
        }
        if (detour_disabled &&
            !hooks_.RemoveOwner(kOwner, kGeneration, bounded_timeout)) {
            return false;
        }
        if (!detour_disabled) {
            std::scoped_lock process_lock(process_mutex_);
            Impl* expected = this;
            static_cast<void>(active_.compare_exchange_strong(
                expected, nullptr, std::memory_order_acq_rel));
        }
        owner_registered_ = false;
        original_ = nullptr;
        target_ = nullptr;
        return true;
    }

    [[nodiscard]] bool Started() const noexcept {
        return started_.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::vector<HookRecordView> Snapshot() const {
        return hooks_.Snapshot();
    }

private:
    static void __fastcall ProcessEventThunk(
        void* object,
        void* function,
        void* parameters) {
        Impl* self{};
        ProcessEventFunction original{};
        PluginScope::CallbackLease lease;
        {
            std::scoped_lock process_lock(process_mutex_);
            self = active_.load(std::memory_order_acquire);
            if (self != nullptr && self->original_ != nullptr) {
                lease = self->hooks_.AcquireCallback(kOwner, kGeneration);
                if (lease) original = self->original_;
                else self = nullptr;
            }
            if (self == nullptr) {
                original = passthrough_.load(std::memory_order_acquire);
            }
        }

        if (original == nullptr) return;
        original(object, function, parameters);
        if (self == nullptr) return;
        try {
            self->callback_(
                reinterpret_cast<std::uintptr_t>(object),
                reinterpret_cast<std::uintptr_t>(function),
                parameters);
        } catch (...) {
        }
    }

    HookManager hooks_;
    Callback callback_;
    ProcessEventFunction original_{};
    void* target_{};
    std::atomic_bool started_{};
    bool owner_registered_{};
    std::mutex stop_mutex_;
    static std::atomic<Impl*> active_;
    static std::atomic<ProcessEventFunction> passthrough_;
    static std::mutex process_mutex_;
};

std::atomic<Ue5ActorProcessEventHook::Impl*> Ue5ActorProcessEventHook::Impl::active_{};
std::atomic<Ue5ActorProcessEventHook::Impl::ProcessEventFunction>
    Ue5ActorProcessEventHook::Impl::passthrough_{};
std::mutex Ue5ActorProcessEventHook::Impl::process_mutex_;

Ue5ActorProcessEventHook::Ue5ActorProcessEventHook(Callback callback)
    : Ue5ActorProcessEventHook(
          CreateMinHookBackend(), std::move(callback)) {}

Ue5ActorProcessEventHook::Ue5ActorProcessEventHook(
    std::unique_ptr<HookBackend> backend,
    Callback callback)
    : impl_(std::make_unique<Impl>(
          std::move(backend), std::move(callback))) {}

Ue5ActorProcessEventHook::~Ue5ActorProcessEventHook() {
    if (impl_ != nullptr && !impl_->Stop(std::chrono::milliseconds::zero())) {
        static_cast<void>(impl_.release());
    }
}

bool Ue5ActorProcessEventHook::Start(void* target) {
    return impl_->Start(target);
}

bool Ue5ActorProcessEventHook::Stop(const std::chrono::milliseconds timeout) noexcept {
    return impl_->Stop(timeout);
}

bool Ue5ActorProcessEventHook::Started() const noexcept {
    return impl_->Started();
}

std::vector<HookRecordView> Ue5ActorProcessEventHook::Snapshot() const {
    return impl_->Snapshot();
}

}  // namespace anomaly
