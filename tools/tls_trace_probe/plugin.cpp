#include "anomaly/sdk/cpp.hpp"

#include <windows.h>
#include <sspi.h>
#include <bcrypt.h>
#include <intrin.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {

constexpr std::size_t kRingCapacity = 512;
constexpr std::size_t kMaximumHistoryRecords = 192;
constexpr std::size_t kMaximumBuffers = 64;
constexpr std::size_t kBufferHeadSize = 48;
constexpr std::size_t kMaximumPayload = 8192;
constexpr std::uint32_t kFlushIntervalMilliseconds = 250;
constexpr std::uint64_t kUnixEpochFileTimeTicks = 116444736000000000ULL;
constexpr std::uint64_t kFileTimeTicksPerMillisecond = 10000ULL;

enum class TlsOperation : std::uint16_t {
    Encrypt = 1,
    Decrypt = 2,
};

struct BufferSlot final {
    std::uint32_t type{};
    std::uint32_t size{};
    std::array<std::uint8_t, kBufferHeadSize> head{};
    std::uint16_t head_size{};
};

struct BufferList final {
    std::array<BufferSlot, kMaximumBuffers> items{};
    std::uint8_t count{};
};

struct TraceRecord final {
    std::uint64_t sequence{};
    std::uint64_t qpc{};
    std::uint32_t thread_id{};
    std::uint64_t return_address{};
    std::uint64_t context_low{};
    std::uint64_t context_high{};
    std::uint16_t operation{};
    std::int32_t status{};
    BufferList before{};
    BufferList after{};
    std::array<std::uint8_t, kMaximumPayload> payload{};
    std::uint16_t payload_size{};
};

static_assert(std::is_trivially_copyable_v<TraceRecord>);

template <typename T, std::size_t Capacity>
class BoundedMpmcRing final {
    static_assert(Capacity != 0 && (Capacity & (Capacity - 1U)) == 0);

    struct Cell final {
        std::atomic<std::size_t> sequence{};
        T value{};
    };

public:
    BoundedMpmcRing() noexcept {
        for (std::size_t index = 0; index < Capacity; ++index) {
            cells_[index].sequence.store(index, std::memory_order_relaxed);
        }
    }

    [[nodiscard]] bool Push(const T& value) noexcept {
        std::size_t position = enqueue_position_.load(std::memory_order_relaxed);
        for (;;) {
            Cell& cell = cells_[position & (Capacity - 1U)];
            const std::size_t sequence = cell.sequence.load(std::memory_order_acquire);
            const std::intptr_t difference = static_cast<std::intptr_t>(sequence) -
                static_cast<std::intptr_t>(position);
            if (difference == 0) {
                if (enqueue_position_.compare_exchange_weak(
                        position, position + 1U, std::memory_order_relaxed)) {
                    cell.value = value;
                    cell.sequence.store(position + 1U, std::memory_order_release);
                    return true;
                }
            } else if (difference < 0) {
                return false;
            } else {
                position = enqueue_position_.load(std::memory_order_relaxed);
            }
        }
    }

    [[nodiscard]] bool Pop(T& value) noexcept {
        std::size_t position = dequeue_position_.load(std::memory_order_relaxed);
        for (;;) {
            Cell& cell = cells_[position & (Capacity - 1U)];
            const std::size_t sequence = cell.sequence.load(std::memory_order_acquire);
            const std::intptr_t difference = static_cast<std::intptr_t>(sequence) -
                static_cast<std::intptr_t>(position + 1U);
            if (difference == 0) {
                if (dequeue_position_.compare_exchange_weak(
                        position, position + 1U, std::memory_order_relaxed)) {
                    value = cell.value;
                    cell.sequence.store(position + Capacity, std::memory_order_release);
                    return true;
                }
            } else if (difference < 0) {
                return false;
            } else {
                position = dequeue_position_.load(std::memory_order_relaxed);
            }
        }
    }

private:
    std::array<Cell, Capacity> cells_{};
    std::atomic<std::size_t> enqueue_position_{};
    std::atomic<std::size_t> dequeue_position_{};
};

struct Context final {
    const AnomalyHookServiceV1* hook{};
    const AnomalyStorageServiceV1* storage{};
    const AnomalySchedulerServiceV1* scheduler{};
    AnomalyGenerationHandleV1 hook_encrypt{};
    AnomalyGenerationHandleV1 hook_decrypt{};
    AnomalyGenerationHandleV1 hook_sch_encrypt{};
    AnomalyGenerationHandleV1 hook_sch_decrypt{};
    std::array<std::uint8_t, 16> capture_id{};
    std::uint64_t qpc_frequency{};
    std::uint64_t started_qpc{};
    std::uint64_t started_utc_unix_milliseconds{};
    std::uint64_t ended_qpc{};
    std::uint64_t ended_utc_unix_milliseconds{};
    std::atomic_bool capture_open{};
    std::atomic_bool stop_started{};
    BoundedMpmcRing<TraceRecord, kRingCapacity> ring;
    std::atomic<std::uint64_t> next_sequence{};
    std::atomic<std::uint64_t> records_enqueued{};
    std::atomic<std::uint64_t> ring_dropped{};
    std::atomic<std::uint64_t> scheduling_failures{};
    std::mutex persistence_mutex;
    std::mutex flush_mutex;
    AnomalyGenerationHandleV1 flush_task{};
    std::vector<TraceRecord> history;
    std::uint64_t records_drained{};
    std::uint64_t records_recorded{};
    std::uint64_t history_dropped{};
    std::uint64_t persistence_attempts{};
    std::uint64_t persistence_successes{};
    std::uint64_t persistence_failures{};
    bool finalization_requested{};
    bool hook_quiesced{};

    void Record(TraceRecord record) noexcept {
        record.sequence = next_sequence.fetch_add(1U, std::memory_order_relaxed) + 1U;
        if (ring.Push(record)) {
            records_enqueued.fetch_add(1U, std::memory_order_relaxed);
        } else {
            ring_dropped.fetch_add(1U, std::memory_order_relaxed);
        }
    }

    void Drain() {
        TraceRecord record;
        while (ring.Pop(record)) {
            ++records_drained;
            history.push_back(record);
            ++records_recorded;
            if (history.size() > kMaximumHistoryRecords) {
                ++history_dropped;
                history.erase(history.begin());
            }
        }
    }
};

std::atomic<Context*> g_active{};
std::atomic<const AnomalyHookServiceV1*> g_hook_service{};
std::atomic<std::uint64_t> g_hook_id{};
std::atomic<std::uint64_t> g_hook_generation{};

using EncryptFn = SECURITY_STATUS(SEC_ENTRY*)(PCtxtHandle, ULONG, PSecBufferDesc, ULONG);
using DecryptFn = SECURITY_STATUS(SEC_ENTRY*)(
    PCtxtHandle, PSecBufferDesc, ULONG, PULONG);

std::atomic<EncryptFn> g_encrypt_original{};
std::atomic<DecryptFn> g_decrypt_original{};
std::atomic<EncryptFn> g_sch_encrypt_original{};
std::atomic<DecryptFn> g_sch_decrypt_original{};

constexpr AnomalyStatusV1 Status(const std::uint32_t code, const char* message = nullptr) noexcept {
    return {code, 0, {message, message == nullptr ? 0U : std::strlen(message)}};
}

template <typename Service>
const Service* Query(const AnomalyHostApiV1* host, const char* id) noexcept {
    return anomaly::sdk::Host(host).Query<Service>(id, 1).get();
}

std::uint64_t QueryPerformanceCounterValue() noexcept {
    LARGE_INTEGER value{};
    static_cast<void>(QueryPerformanceCounter(&value));
    return static_cast<std::uint64_t>(value.QuadPart);
}

std::uint64_t QueryPerformanceFrequencyValue() noexcept {
    LARGE_INTEGER value{};
    return QueryPerformanceFrequency(&value) == FALSE
        ? 0U
        : static_cast<std::uint64_t>(value.QuadPart);
}

std::uint64_t QueryUnixTimeMilliseconds() noexcept {
    FILETIME file_time{};
    GetSystemTimePreciseAsFileTime(&file_time);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = file_time.dwLowDateTime;
    ticks.HighPart = file_time.dwHighDateTime;
    if (ticks.QuadPart < kUnixEpochFileTimeTicks) return 0;
    return (ticks.QuadPart - kUnixEpochFileTimeTicks) / kFileTimeTicksPerMillisecond;
}

void SnapshotBuffers(PSecBufferDesc desc, BufferList& out) noexcept {
    out = {};
    if (desc == nullptr) return;
    __try {
        if (desc->pBuffers == nullptr || desc->cBuffers == 0) return;
        const ULONG bounded = (std::min)(
            desc->cBuffers, static_cast<ULONG>(kMaximumBuffers));
        out.count = static_cast<std::uint8_t>(bounded);
        for (ULONG index = 0; index < bounded; ++index) {
            SecBuffer& buffer = desc->pBuffers[index];
            BufferSlot& slot = out.items[index];
            slot.type = buffer.BufferType;
            slot.size = buffer.cbBuffer;
            slot.head_size = 0;
            if (buffer.pvBuffer != nullptr && buffer.cbBuffer != 0) {
                const ULONG head = (std::min)(
                    buffer.cbBuffer, static_cast<ULONG>(kBufferHeadSize));
                std::memcpy(slot.head.data(), buffer.pvBuffer, head);
                slot.head_size = static_cast<std::uint16_t>(head);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out.count = 0;
    }
}

void CaptureDataBytes(
    PSecBufferDesc desc, const bool include_extra,
    std::array<std::uint8_t, kMaximumPayload>& payload,
    std::uint16_t& payload_size) noexcept {
    payload.fill(0);
    payload_size = 0;
    if (desc == nullptr) return;
    __try {
        if (desc->pBuffers == nullptr || desc->cBuffers == 0) return;
        const ULONG bounded = (std::min)(
            desc->cBuffers, static_cast<ULONG>(kMaximumBuffers));
        for (ULONG index = 0; index < bounded; ++index) {
            SecBuffer& buffer = desc->pBuffers[index];
            const bool relevant = buffer.BufferType == SECBUFFER_DATA ||
                (include_extra && buffer.BufferType == SECBUFFER_EXTRA);
            if (!relevant || buffer.pvBuffer == nullptr || buffer.cbBuffer == 0) continue;
            const std::size_t remaining = kMaximumPayload - payload_size;
            if (remaining == 0) return;
            const ULONG take = (std::min)(
                buffer.cbBuffer, static_cast<ULONG>(remaining));
            std::memcpy(payload.data() + payload_size, buffer.pvBuffer, take);
            payload_size = static_cast<std::uint16_t>(payload_size + take);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        payload_size = 0;
    }
}

void ContextBits(PCtxtHandle context, std::uint64_t& low, std::uint64_t& high) noexcept {
    low = 0;
    high = 0;
    if (context == nullptr) return;
    __try {
        const auto* const slots = reinterpret_cast<const std::uint64_t*>(context);
        low = slots[0];
        high = slots[1];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

Context* BeginCapture(
    const AnomalyHookServiceV1*& service, AnomalyGenerationHandleV1& lease) noexcept {
    Context* const context = g_active.load(std::memory_order_acquire);
    service = g_hook_service.load(std::memory_order_acquire);
    if (context == nullptr || !context->capture_open.load(std::memory_order_acquire) ||
        service == nullptr || service->begin_callback == nullptr ||
        service->end_callback == nullptr) {
        return nullptr;
    }
    lease = {g_hook_id.load(std::memory_order_acquire),
        g_hook_generation.load(std::memory_order_acquire)};
    AnomalyGenerationHandleV1 callback_lease{};
    if (lease.id == 0 || service->begin_callback(service->user, lease, &callback_lease).code !=
            ANOMALY_STATUS_V1_OK) {
        return nullptr;
    }
    lease = callback_lease;
    if (!context->capture_open.load(std::memory_order_acquire)) {
        static_cast<void>(service->end_callback(service->user, lease));
        lease = {};
        return nullptr;
    }
    return context;
}

void EndCapture(
    const AnomalyHookServiceV1* service, const AnomalyGenerationHandleV1 lease) noexcept {
    if (service != nullptr && service->end_callback != nullptr && lease.id != 0) {
        static_cast<void>(service->end_callback(service->user, lease));
    }
}

void FinishRecord(Context& context, const TraceRecord& record) noexcept {
    context.Record(record);
}

SECURITY_STATUS SEC_ENTRY EncryptDetour(
    const PCtxtHandle context, const ULONG quality, const PSecBufferDesc message,
    const ULONG sequence) {
    const std::uint64_t qpc = QueryPerformanceCounterValue();
    const void* const return_address = _ReturnAddress();
    const AnomalyHookServiceV1* service{};
    AnomalyGenerationHandleV1 lease{};
    Context* const capture = BeginCapture(service, lease);
    const EncryptFn original = g_encrypt_original.load(std::memory_order_acquire);
    if (original == nullptr) {
        if (capture != nullptr) EndCapture(service, lease);
        return SEC_E_INVALID_HANDLE;
    }
    TraceRecord record{};
    record.qpc = qpc;
    record.thread_id = GetCurrentThreadId();
    record.return_address = reinterpret_cast<std::uintptr_t>(return_address);
    record.operation = static_cast<std::uint16_t>(TlsOperation::Encrypt);
    ContextBits(context, record.context_low, record.context_high);
    SnapshotBuffers(message, record.before);
    CaptureDataBytes(message, false, record.payload, record.payload_size);
    const SECURITY_STATUS result = original(context, quality, message, sequence);
    record.status = static_cast<std::int32_t>(result);
    SnapshotBuffers(message, record.after);
    if (capture != nullptr) {
        FinishRecord(*capture, record);
        EndCapture(service, lease);
    }
    return result;
}

SECURITY_STATUS SEC_ENTRY DecryptDetour(
    const PCtxtHandle context, const PSecBufferDesc message, const ULONG sequence,
    PULONG quality) {
    const std::uint64_t qpc = QueryPerformanceCounterValue();
    const void* const return_address = _ReturnAddress();
    const AnomalyHookServiceV1* service{};
    AnomalyGenerationHandleV1 lease{};
    Context* const capture = BeginCapture(service, lease);
    const DecryptFn original = g_decrypt_original.load(std::memory_order_acquire);
    if (original == nullptr) {
        if (capture != nullptr) EndCapture(service, lease);
        return SEC_E_INVALID_HANDLE;
    }
    TraceRecord record{};
    record.qpc = qpc;
    record.thread_id = GetCurrentThreadId();
    record.return_address = reinterpret_cast<std::uintptr_t>(return_address);
    record.operation = static_cast<std::uint16_t>(TlsOperation::Decrypt);
    ContextBits(context, record.context_low, record.context_high);
    SnapshotBuffers(message, record.before);
    const SECURITY_STATUS result = original(context, message, sequence, quality);
    record.status = static_cast<std::int32_t>(result);
    SnapshotBuffers(message, record.after);
    CaptureDataBytes(message, true, record.payload, record.payload_size);
    if (capture != nullptr) {
        FinishRecord(*capture, record);
        EndCapture(service, lease);
    }
    return result;
}

SECURITY_STATUS SEC_ENTRY SchEncryptDetour(
    const PCtxtHandle context, const ULONG quality, const PSecBufferDesc message,
    const ULONG sequence) {
    const std::uint64_t qpc = QueryPerformanceCounterValue();
    const void* const return_address = _ReturnAddress();
    const AnomalyHookServiceV1* service{};
    AnomalyGenerationHandleV1 lease{};
    Context* const capture = BeginCapture(service, lease);
    const EncryptFn original = g_sch_encrypt_original.load(std::memory_order_acquire);
    if (original == nullptr) {
        if (capture != nullptr) EndCapture(service, lease);
        return SEC_E_INVALID_HANDLE;
    }
    TraceRecord record{};
    record.qpc = qpc;
    record.thread_id = GetCurrentThreadId();
    record.return_address = reinterpret_cast<std::uintptr_t>(return_address);
    record.operation = static_cast<std::uint16_t>(TlsOperation::Encrypt);
    ContextBits(context, record.context_low, record.context_high);
    SnapshotBuffers(message, record.before);
    CaptureDataBytes(message, false, record.payload, record.payload_size);
    const SECURITY_STATUS result = original(context, quality, message, sequence);
    record.status = static_cast<std::int32_t>(result);
    SnapshotBuffers(message, record.after);
    if (capture != nullptr) {
        FinishRecord(*capture, record);
        EndCapture(service, lease);
    }
    return result;
}

SECURITY_STATUS SEC_ENTRY SchDecryptDetour(
    const PCtxtHandle context, const PSecBufferDesc message, const ULONG sequence,
    PULONG quality) {
    const std::uint64_t qpc = QueryPerformanceCounterValue();
    const void* const return_address = _ReturnAddress();
    const AnomalyHookServiceV1* service{};
    AnomalyGenerationHandleV1 lease{};
    Context* const capture = BeginCapture(service, lease);
    const DecryptFn original = g_sch_decrypt_original.load(std::memory_order_acquire);
    if (original == nullptr) {
        if (capture != nullptr) EndCapture(service, lease);
        return SEC_E_INVALID_HANDLE;
    }
    TraceRecord record{};
    record.qpc = qpc;
    record.thread_id = GetCurrentThreadId();
    record.return_address = reinterpret_cast<std::uintptr_t>(return_address);
    record.operation = static_cast<std::uint16_t>(TlsOperation::Decrypt);
    ContextBits(context, record.context_low, record.context_high);
    SnapshotBuffers(message, record.before);
    const SECURITY_STATUS result = original(context, message, sequence, quality);
    record.status = static_cast<std::int32_t>(result);
    SnapshotBuffers(message, record.after);
    CaptureDataBytes(message, true, record.payload, record.payload_size);
    if (capture != nullptr) {
        FinishRecord(*capture, record);
        EndCapture(service, lease);
    }
    return result;
}

void AppendHex(std::string& output, const std::uint64_t value, const std::size_t digits = 16U) {
    static constexpr char hex[] = "0123456789abcdef";
    for (std::size_t index = 0; index < digits; ++index) {
        const unsigned shift = static_cast<unsigned>((digits - index - 1U) * 4U);
        output.push_back(hex[(value >> shift) & 0xfU]);
    }
}

void AppendCaptureId(std::string& output, const std::array<std::uint8_t, 16>& capture_id) {
    static constexpr char hex[] = "0123456789abcdef";
    for (const std::uint8_t value : capture_id) {
        output.push_back(hex[value >> 4U]);
        output.push_back(hex[value & 0x0fU]);
    }
}

void AppendBufferList(std::string& output, const BufferList& list) {
    output.push_back('[');
    for (std::size_t index = 0; index < list.count; ++index) {
        if (index != 0) output.push_back(',');
        const BufferSlot& slot = list.items[index];
        output += "{\"type\":" + std::to_string(slot.type);
        output += ",\"size\":" + std::to_string(slot.size);
        output += ",\"head\":\"";
        static constexpr char hex[] = "0123456789abcdef";
        for (std::size_t byte = 0; byte < slot.head_size; ++byte) {
            output.push_back(hex[slot.head[byte] >> 4U]);
            output.push_back(hex[slot.head[byte] & 0x0fU]);
        }
        output += "\"}";
    }
    output.push_back(']');
}

std::string Serialize(
    const Context& context, const std::uint64_t persisted_records,
    const std::uint64_t persisted_max_sequence, const std::uint64_t persistence_successes,
    const bool final_persist_succeeded) {
    std::string output;
    output.reserve(1024U + context.history.size() * 1280U);
    output += "{\"schemaVersion\":2,\"captureId\":\"";
    AppendCaptureId(output, context.capture_id);
    output += "\",\"pluginId\":\"anomaly.diagnostics.tls.secur32\"";
    output += ",\"clock\":{\"qpcFrequency\":" + std::to_string(context.qpc_frequency);
    output += ",\"startedQpc\":" + std::to_string(context.started_qpc);
    output += ",\"startedUtcUnixMilliseconds\":" +
        std::to_string(context.started_utc_unix_milliseconds);
    output += ",\"endedQpc\":" + std::to_string(context.ended_qpc);
    output += ",\"endedUtcUnixMilliseconds\":" +
        std::to_string(context.ended_utc_unix_milliseconds) + "}";
    output += ",\"state\":{\"finalizationRequested\":";
    output += context.finalization_requested ? "true" : "false";
    output += ",\"finalized\":";
    output += final_persist_succeeded ? "true" : "false";
    output += ",\"hookQuiesced\":";
    output += context.hook_quiesced ? "true" : "false";
    output += ",\"captureOpen\":";
    output += context.capture_open.load(std::memory_order_relaxed) ? "true" : "false";
    output += "}";
    output += ",\"integrity\":{\"recordsObserved\":" +
        std::to_string(context.next_sequence.load(std::memory_order_relaxed));
    output += ",\"recordsEnqueued\":" +
        std::to_string(context.records_enqueued.load(std::memory_order_relaxed));
    output += ",\"recordsDrained\":" + std::to_string(context.records_drained);
    output += ",\"recordsRecorded\":" + std::to_string(context.records_recorded);
    output += ",\"recordsPersisted\":" + std::to_string(persisted_records);
    output += ",\"persistedMaxSequence\":" + std::to_string(persisted_max_sequence);
    output += ",\"ringDropped\":" +
        std::to_string(context.ring_dropped.load(std::memory_order_relaxed));
    output += ",\"historyDropped\":" + std::to_string(context.history_dropped);
    output += ",\"persistenceAttempts\":" + std::to_string(context.persistence_attempts);
    output += ",\"persistenceSuccesses\":" + std::to_string(persistence_successes);
    output += ",\"persistenceFailures\":" + std::to_string(context.persistence_failures);
    output += ",\"schedulingFailures\":" +
        std::to_string(context.scheduling_failures.load(std::memory_order_relaxed)) + "}";
    output += ",\"events\":[";
    bool first = true;
    for (const TraceRecord& record : context.history) {
        if (!first) output.push_back(',');
        first = false;
        output += "{\"sequence\":" + std::to_string(record.sequence);
        output += ",\"qpc\":" + std::to_string(record.qpc);
        output += ",\"threadId\":" + std::to_string(record.thread_id);
        output += ",\"returnAddress\":\"0x";
        AppendHex(output, record.return_address);
        output += "\",\"contextLo\":\"0x";
        AppendHex(output, record.context_low);
        output += "\",\"contextHi\":\"0x";
        AppendHex(output, record.context_high);
        output += "\",\"operation\":\"";
        output += record.operation == static_cast<std::uint16_t>(TlsOperation::Encrypt)
            ? "encrypt" : "decrypt";
        output += "\",\"status\":" + std::to_string(record.status);
        output += ",\"before\":";
        AppendBufferList(output, record.before);
        output += ",\"after\":";
        AppendBufferList(output, record.after);
        output += ",\"payload\":\"";
        static constexpr char hex[] = "0123456789abcdef";
        for (std::size_t index = 0; index < record.payload_size; ++index) {
            const std::uint8_t byte = record.payload[index];
            output.push_back(hex[byte >> 4U]);
            output.push_back(hex[byte & 0x0fU]);
        }
        output.push_back('"');
        output += "}";
    }
    output += "]}";
    return output;
}

bool Persist(Context& context, const bool final_snapshot, const bool hook_quiesced) {
    std::scoped_lock lock(context.persistence_mutex);
    context.Drain();
    if (final_snapshot) {
        const std::uint64_t qpc_before_clock = QueryPerformanceCounterValue();
        context.ended_utc_unix_milliseconds = QueryUnixTimeMilliseconds();
        const std::uint64_t qpc_after_clock = QueryPerformanceCounterValue();
        context.ended_qpc = qpc_before_clock + (qpc_after_clock - qpc_before_clock) / 2U;
        context.finalization_requested = true;
        context.hook_quiesced = hook_quiesced;
    }
    ++context.persistence_attempts;
    const std::uint64_t persisted_max_sequence =
        context.history.empty() ? 0U : context.history.back().sequence;
    const std::uint64_t persistence_successes = context.persistence_successes + 1U;
    const bool final_persist_succeeded = final_snapshot && hook_quiesced;
    const std::string document = Serialize(
        context, context.records_recorded, persisted_max_sequence, persistence_successes,
        final_persist_succeeded);
    const AnomalyByteSpanV1 bytes{
        reinterpret_cast<const std::uint8_t*>(document.data()), document.size()};
    const bool written = context.storage != nullptr && context.storage->write_atomic != nullptr &&
        context.storage->write_atomic(
            context.storage->user, anomaly::sdk::StringView("secur32-trace.json"), bytes).code ==
            ANOMALY_STATUS_V1_OK;
    if (written) {
        context.persistence_successes = persistence_successes;
    } else {
        ++context.persistence_failures;
    }
    return written;
}

void ScheduleFlush(Context* context, const std::uint32_t delay_milliseconds);

void ANOMALY_CALL FlushTask(void* user, const AnomalyGenerationHandleV1 task) {
    auto* const context = static_cast<Context*>(user);
    if (context == nullptr) return;
    {
        std::scoped_lock lock(context->flush_mutex);
        if (context->flush_task.id == task.id) context->flush_task = {};
    }
    if (context->stop_started.load(std::memory_order_acquire)) return;
    static_cast<void>(Persist(*context, false, false));
    if (context->stop_started.load(std::memory_order_acquire)) return;
    ScheduleFlush(context, kFlushIntervalMilliseconds);
}

void ScheduleFlush(Context* context, const std::uint32_t delay_milliseconds) {
    if (context == nullptr || context->stop_started.load(std::memory_order_acquire) ||
        context->scheduler == nullptr || context->scheduler->schedule == nullptr) {
        return;
    }
    AnomalyGenerationHandleV1 task{};
    if (context->scheduler->schedule(
            context->scheduler->user, delay_milliseconds, FlushTask, context, &task).code !=
        ANOMALY_STATUS_V1_OK) {
        context->scheduling_failures.fetch_add(1U, std::memory_order_relaxed);
        return;
    }
    bool cancel{};
    {
        std::scoped_lock lock(context->flush_mutex);
        if (context->stop_started.load(std::memory_order_acquire)) {
            cancel = true;
        } else {
            context->flush_task = task;
        }
    }
    if (cancel && context->scheduler->cancel != nullptr) {
        static_cast<void>(context->scheduler->cancel(context->scheduler->user, task));
    }
}

void CancelFlush(Context& context) noexcept {
    AnomalyGenerationHandleV1 task{};
    {
        std::scoped_lock lock(context.flush_mutex);
        task = context.flush_task;
        context.flush_task = {};
    }
    if (task.id != 0 && context.scheduler != nullptr && context.scheduler->cancel != nullptr) {
        static_cast<void>(context.scheduler->cancel(context.scheduler->user, task));
    }
}

bool ReleaseHook(Context& context, AnomalyGenerationHandleV1& handle) noexcept {
    if (handle.id == 0) return true;
    if (context.hook == nullptr || context.hook->release == nullptr) return false;
    const AnomalyStatusV1 status = context.hook->release(context.hook->user, handle);
    if (status.code != ANOMALY_STATUS_V1_OK && status.code != ANOMALY_STATUS_V1_NOT_FOUND) {
        return false;
    }
    handle = {};
    return true;
}

AnomalyStatusV1 ANOMALY_CALL Load(const AnomalyHostApiV1* host, void** plugin_context) {
    if (host == nullptr || plugin_context == nullptr) {
        return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "host is invalid");
    }
    const auto* const storage = Query<AnomalyStorageServiceV1>(host, ANOMALY_STORAGE_SERVICE_V1_ID);
    const auto* const scheduler = Query<AnomalySchedulerServiceV1>(host, ANOMALY_SCHEDULER_SERVICE_V1_ID);
    const auto* const hook = Query<AnomalyHookServiceV1>(host, ANOMALY_HOOK_SERVICE_V1_ID);
    if (storage == nullptr || scheduler == nullptr || hook == nullptr) {
        return Status(ANOMALY_STATUS_V1_UNAVAILABLE, "trace services are unavailable");
    }
    auto* const context = new (std::nothrow) Context();
    if (context == nullptr) return Status(ANOMALY_STATUS_V1_FAILED, "trace context allocation failed");
    context->storage = storage;
    context->scheduler = scheduler;
    context->hook = hook;
    *plugin_context = context;
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Start(void* plugin_context) {
    auto* const context = static_cast<Context*>(plugin_context);
    if (context == nullptr || context->hook == nullptr || context->hook->create == nullptr ||
        g_active.load(std::memory_order_acquire) != nullptr) {
        return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "trace context is invalid");
    }
    const auto resolve = [](const wchar_t* module_name, const char* name) noexcept {
        const HMODULE module = GetModuleHandleW(module_name);
        return module == nullptr
            ? std::uintptr_t{}
            : reinterpret_cast<std::uintptr_t>(GetProcAddress(module, name));
    };
    const std::uintptr_t encrypt_target = resolve(L"secur32.dll", "EncryptMessage");
    const std::uintptr_t decrypt_target = resolve(L"secur32.dll", "DecryptMessage");
    const std::uintptr_t sch_encrypt_target = resolve(L"schannel.dll", "EncryptMessage");
    const std::uintptr_t sch_decrypt_target = resolve(L"schannel.dll", "DecryptMessage");
    if (encrypt_target == 0 || decrypt_target == 0 || BCryptGenRandom(
            nullptr, context->capture_id.data(), static_cast<ULONG>(context->capture_id.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return Status(ANOMALY_STATUS_V1_UNAVAILABLE, "Secur32 trace target is unavailable");
    }
    bool sch_encrypt_hooked = false;
    bool sch_decrypt_hooked = false;
    const auto create_hook = [&](const std::uintptr_t target, void* const detour,
                                 const char* const label,
                                 void (*const store_original)(std::uintptr_t),
                                 AnomalyGenerationHandleV1& handle) noexcept {
        AnomalyHookRequestV1 request{};
        request.struct_size = sizeof(request);
        request.kind = ANOMALY_HOOK_V1_FUNCTION;
        request.target = target;
        request.detour = detour;
        request.label = anomaly::sdk::StringView(label);
        std::uintptr_t original{};
        if (context->hook->create(
                context->hook->user, &request, &original, &handle).code !=
                ANOMALY_STATUS_V1_OK ||
            original == 0 || handle.id == 0) {
            return false;
        }
        store_original(original);
        return true;
    };
    const auto release_all = [&]() noexcept {
        std::uintptr_t unused = 0;
        if (sch_decrypt_hooked) {
            sch_decrypt_hooked = false;
            static_cast<void>(ReleaseHook(*context, context->hook_sch_decrypt));
            g_sch_decrypt_original.store(nullptr, std::memory_order_release);
        }
        if (sch_encrypt_hooked) {
            sch_encrypt_hooked = false;
            static_cast<void>(ReleaseHook(*context, context->hook_sch_encrypt));
            g_sch_encrypt_original.store(nullptr, std::memory_order_release);
        }
        static_cast<void>(ReleaseHook(*context, context->hook_decrypt));
        static_cast<void>(ReleaseHook(*context, context->hook_encrypt));
        g_encrypt_original.store(nullptr, std::memory_order_release);
        g_decrypt_original.store(nullptr, std::memory_order_release);
        static_cast<void>(unused);
    };
    if (!create_hook(
            encrypt_target, reinterpret_cast<void*>(&EncryptDetour),
            "secur32-encrypt-trace",
            [](const std::uintptr_t original) {
                g_encrypt_original.store(
                    reinterpret_cast<EncryptFn>(original), std::memory_order_release);
            },
            context->hook_encrypt)) {
        return Status(ANOMALY_STATUS_V1_FAILED, "Secur32 EncryptMessage hook creation failed");
    }
    if (!create_hook(
            decrypt_target, reinterpret_cast<void*>(&DecryptDetour),
            "secur32-decrypt-trace",
            [](const std::uintptr_t original) {
                g_decrypt_original.store(
                    reinterpret_cast<DecryptFn>(original), std::memory_order_release);
            },
            context->hook_decrypt)) {
        release_all();
        return Status(ANOMALY_STATUS_V1_FAILED, "Secur32 DecryptMessage hook creation failed");
    }
    if (sch_encrypt_target != 0 && sch_encrypt_target != encrypt_target) {
        if (!create_hook(
                sch_encrypt_target, reinterpret_cast<void*>(&SchEncryptDetour),
                "schannel-encrypt-trace",
                [](const std::uintptr_t original) {
                    g_sch_encrypt_original.store(
                        reinterpret_cast<EncryptFn>(original), std::memory_order_release);
                },
                context->hook_sch_encrypt)) {
            release_all();
            return Status(ANOMALY_STATUS_V1_FAILED, "Schannel EncryptMessage hook creation failed");
        }
        sch_encrypt_hooked = true;
    } else {
        g_sch_encrypt_original.store(nullptr, std::memory_order_release);
    }
    if (sch_decrypt_target != 0 && sch_decrypt_target != decrypt_target) {
        if (!create_hook(
                sch_decrypt_target, reinterpret_cast<void*>(&SchDecryptDetour),
                "schannel-decrypt-trace",
                [](const std::uintptr_t original) {
                    g_sch_decrypt_original.store(
                        reinterpret_cast<DecryptFn>(original), std::memory_order_release);
                },
                context->hook_sch_decrypt)) {
            release_all();
            return Status(ANOMALY_STATUS_V1_FAILED, "Schannel DecryptMessage hook creation failed");
        }
        sch_decrypt_hooked = true;
    } else {
        g_sch_decrypt_original.store(nullptr, std::memory_order_release);
    }
    context->qpc_frequency = QueryPerformanceFrequencyValue();
    const std::uint64_t qpc_before_clock = QueryPerformanceCounterValue();
    context->started_utc_unix_milliseconds = QueryUnixTimeMilliseconds();
    const std::uint64_t qpc_after_clock = QueryPerformanceCounterValue();
    context->started_qpc = qpc_before_clock + (qpc_after_clock - qpc_before_clock) / 2U;
    g_hook_service.store(context->hook, std::memory_order_release);
    g_hook_id.store(context->hook_encrypt.id, std::memory_order_release);
    g_hook_generation.store(context->hook_encrypt.generation, std::memory_order_release);
    context->capture_open.store(true, std::memory_order_release);
    g_active.store(context, std::memory_order_release);
    ScheduleFlush(context, 0);
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Stop(void* plugin_context, std::uint32_t) {
    auto* const context = static_cast<Context*>(plugin_context);
    if (context == nullptr) return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "trace context is invalid");
    if (context->stop_started.exchange(true, std::memory_order_acq_rel)) return anomaly::sdk::Ok();
    context->capture_open.store(false, std::memory_order_release);
    Context* expected = context;
    static_cast<void>(g_active.compare_exchange_strong(
        expected, nullptr, std::memory_order_acq_rel));
    CancelFlush(*context);
    const bool encrypt_quiesced = ReleaseHook(*context, context->hook_encrypt);
    const bool decrypt_quiesced = ReleaseHook(*context, context->hook_decrypt);
    const bool sch_encrypt_quiesced = ReleaseHook(*context, context->hook_sch_encrypt);
    const bool sch_decrypt_quiesced = ReleaseHook(*context, context->hook_sch_decrypt);
    const bool hook_quiesced =
        encrypt_quiesced && decrypt_quiesced && sch_encrypt_quiesced && sch_decrypt_quiesced;
    g_encrypt_original.store(nullptr, std::memory_order_release);
    g_decrypt_original.store(nullptr, std::memory_order_release);
    g_sch_encrypt_original.store(nullptr, std::memory_order_release);
    g_sch_decrypt_original.store(nullptr, std::memory_order_release);
    g_hook_id.store(0, std::memory_order_release);
    g_hook_generation.store(0, std::memory_order_release);
    g_hook_service.store(nullptr, std::memory_order_release);
    const bool persisted = Persist(*context, true, hook_quiesced);
    if (!hook_quiesced) {
        return Status(ANOMALY_STATUS_V1_FAILED, "trace hook did not quiesce");
    }
    return persisted
        ? anomaly::sdk::Ok()
        : Status(ANOMALY_STATUS_V1_FAILED, "trace final persistence failed");
}

void ANOMALY_CALL Unload(void* plugin_context) {
    if (Stop(plugin_context, 0).code == ANOMALY_STATUS_V1_OK) {
        delete static_cast<Context*>(plugin_context);
    }
}

}  // namespace

ANOMALY_SDK_EXPORT AnomalyStatusV1 ANOMALY_CALL AnomalyPluginEntryV1(
    AnomalyPluginDescriptorV1* descriptor) {
    if (descriptor == nullptr || descriptor->struct_size < sizeof(*descriptor)) {
        return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "descriptor is invalid");
    }
    *descriptor = {
        sizeof(*descriptor), ANOMALY_PLUGIN_API_V1_MAJOR, ANOMALY_PLUGIN_API_V1_MINOR,
        anomaly::sdk::StringView("anomaly.diagnostics.tls.secur32"),
        anomaly::sdk::StringView("Secur32 TLS plaintext trace"),
        anomaly::sdk::StringView("Anomaly"), anomaly::sdk::StringView("0.1.0"),
        Load, Start, Stop, Unload, nullptr, nullptr};
    return anomaly::sdk::Ok();
}
