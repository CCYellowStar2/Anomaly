#include "anomaly/sdk/cpp.hpp"

#include <windows.h>
#include <winhttp.h>
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
constexpr std::size_t kMaximumUrlCharacters = 512;
constexpr std::size_t kMaximumHeaderCharacters = 512;
constexpr std::size_t kMaximumPayload = 8192;
constexpr std::uint32_t kFlushIntervalMilliseconds = 250;
constexpr std::uint64_t kUnixEpochFileTimeTicks = 116444736000000000ULL;
constexpr std::uint64_t kFileTimeTicksPerMillisecond = 10000ULL;

enum class HttpOperation : std::uint16_t {
    SendRequest = 1,
    ReceiveResponse = 2,
    WriteData = 3,
    ReadData = 4,
};

struct TraceRecord final {
    std::uint64_t sequence{};
    std::uint64_t qpc{};
    std::uint32_t thread_id{};
    std::uint64_t return_address{};
    std::uint64_t handle_bits{};
    std::uint16_t operation{};
    std::int32_t status{};
    std::uint32_t size{};
    std::array<wchar_t, kMaximumUrlCharacters> url{};
    std::uint16_t url_size{};
    std::array<wchar_t, kMaximumHeaderCharacters> headers{};
    std::uint16_t headers_size{};
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
    AnomalyGenerationHandleV1 hook_send_request{};
    AnomalyGenerationHandleV1 hook_receive_response{};
    AnomalyGenerationHandleV1 hook_write_data{};
    AnomalyGenerationHandleV1 hook_read_data{};
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

using SendRequestFn = BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
using ReceiveResponseFn = BOOL(WINAPI*)(HINTERNET, LPVOID);
using WriteDataFn = BOOL(WINAPI*)(HINTERNET, LPCVOID, DWORD, LPDWORD);
using ReadDataFn = BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);

std::atomic<SendRequestFn> g_send_request_original{};
std::atomic<ReceiveResponseFn> g_receive_response_original{};
std::atomic<WriteDataFn> g_write_data_original{};
std::atomic<ReadDataFn> g_read_data_original{};

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

void CaptureUrl(
    const HINTERNET request, std::array<wchar_t, kMaximumUrlCharacters>& out,
    std::uint16_t& out_size) noexcept {
    out.fill(0);
    out_size = 0;
    if (request == nullptr) return;
    __try {
        constexpr DWORD option = WINHTTP_OPTION_URL;
        DWORD available = static_cast<DWORD>(out.size() * sizeof(wchar_t));
        wchar_t buffer[kMaximumUrlCharacters]{};
        if (WinHttpQueryOption(request, option, buffer, &available) != TRUE || available == 0) {
            return;
        }
        if (available > (kMaximumUrlCharacters - 1U) * sizeof(wchar_t)) {
            available = (kMaximumUrlCharacters - 1U) * sizeof(wchar_t);
        }
        const std::size_t characters = available / sizeof(wchar_t);
        std::memcpy(out.data(), buffer, characters * sizeof(wchar_t));
        out_size = static_cast<std::uint16_t>(characters);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out_size = 0;
    }
}

void CaptureWide(
    const wchar_t* source, const std::size_t source_characters,
    std::array<wchar_t, kMaximumHeaderCharacters>& out, std::uint16_t& out_size) noexcept {
    out_size = 0;
    if (source == nullptr || source_characters == 0) return;
    const std::size_t take = (std::min)(source_characters, out.size() - 1U);
    __try {
        std::memcpy(out.data(), source, take * sizeof(wchar_t));
        out_size = static_cast<std::uint16_t>(take);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out_size = 0;
    }
}

void CapturePayload(
    const void* buffer, const std::size_t bytes,
    std::array<std::uint8_t, kMaximumPayload>& out, std::uint16_t& out_size) noexcept {
    out.fill(0);
    out_size = 0;
    if (buffer == nullptr || bytes == 0) return;
    const std::size_t take = (std::min)(bytes, out.size());
    __try {
        std::memcpy(out.data(), buffer, take);
        out_size = static_cast<std::uint16_t>(take);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out_size = 0;
    }
}

void HandleBits(const HINTERNET handle, std::uint64_t& out) noexcept {
    out = reinterpret_cast<std::uintptr_t>(handle);
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
BOOL WINAPI SendRequestDetour(
    const HINTERNET request, const LPCWSTR headers, const DWORD headers_length,
    const LPVOID optional, const DWORD optional_length, const DWORD total_length,
    const DWORD_PTR context) {
    const std::uint64_t qpc = QueryPerformanceCounterValue();
    const void* const return_address = _ReturnAddress();
    const AnomalyHookServiceV1* service{};
    AnomalyGenerationHandleV1 lease{};
    Context* const capture = BeginCapture(service, lease);
    const SendRequestFn original = g_send_request_original.load(std::memory_order_acquire);
    if (original == nullptr) {
        if (capture != nullptr) EndCapture(service, lease);
        return FALSE;
    }
    TraceRecord record{};
    record.qpc = qpc;
    record.thread_id = GetCurrentThreadId();
    record.return_address = reinterpret_cast<std::uintptr_t>(return_address);
    record.operation = static_cast<std::uint16_t>(HttpOperation::SendRequest);
    HandleBits(request, record.handle_bits);
    CaptureUrl(request, record.url, record.url_size);
    CaptureWide(headers, headers_length / sizeof(wchar_t), record.headers, record.headers_size);
    if (optional_length > 0) {
        CapturePayload(optional, optional_length, record.payload, record.payload_size);
    }
    record.size = total_length;
    const BOOL result = original(
        request, headers, headers_length, optional, optional_length, total_length, context);
    record.status = static_cast<std::int32_t>(GetLastError());
    if (capture != nullptr) {
        FinishRecord(*capture, record);
        EndCapture(service, lease);
    }
    return result;
}

BOOL WINAPI ReceiveResponseDetour(const HINTERNET request, const LPVOID reserved) {
    const std::uint64_t qpc = QueryPerformanceCounterValue();
    const void* const return_address = _ReturnAddress();
    const AnomalyHookServiceV1* service{};
    AnomalyGenerationHandleV1 lease{};
    Context* const capture = BeginCapture(service, lease);
    const ReceiveResponseFn original =
        g_receive_response_original.load(std::memory_order_acquire);
    if (original == nullptr) {
        if (capture != nullptr) EndCapture(service, lease);
        return FALSE;
    }
    TraceRecord record{};
    record.qpc = qpc;
    record.thread_id = GetCurrentThreadId();
    record.return_address = reinterpret_cast<std::uintptr_t>(return_address);
    record.operation = static_cast<std::uint16_t>(HttpOperation::ReceiveResponse);
    HandleBits(request, record.handle_bits);
    CaptureUrl(request, record.url, record.url_size);
    __try {
        DWORD status_code = 0;
        DWORD available = sizeof(status_code);
        if (WinHttpQueryHeaders(
                request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &available,
                WINHTTP_NO_HEADER_INDEX) == TRUE) {
            record.size = status_code;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    const BOOL result = original(request, reserved);
    record.status = static_cast<std::int32_t>(GetLastError());
    if (capture != nullptr) {
        FinishRecord(*capture, record);
        EndCapture(service, lease);
    }
    return result;
}

BOOL WINAPI WriteDataDetour(
    const HINTERNET request, const LPCVOID buffer, const DWORD bytes, const LPDWORD written) {
    const std::uint64_t qpc = QueryPerformanceCounterValue();
    const void* const return_address = _ReturnAddress();
    const AnomalyHookServiceV1* service{};
    AnomalyGenerationHandleV1 lease{};
    Context* const capture = BeginCapture(service, lease);
    const WriteDataFn original = g_write_data_original.load(std::memory_order_acquire);
    if (original == nullptr) {
        if (capture != nullptr) EndCapture(service, lease);
        return FALSE;
    }
    TraceRecord record{};
    record.qpc = qpc;
    record.thread_id = GetCurrentThreadId();
    record.return_address = reinterpret_cast<std::uintptr_t>(return_address);
    record.operation = static_cast<std::uint16_t>(HttpOperation::WriteData);
    HandleBits(request, record.handle_bits);
    CaptureUrl(request, record.url, record.url_size);
    record.size = bytes;
    CapturePayload(buffer, bytes, record.payload, record.payload_size);
    const BOOL result = original(request, buffer, bytes, written);
    record.status = static_cast<std::int32_t>(GetLastError());
    if (capture != nullptr) {
        FinishRecord(*capture, record);
        EndCapture(service, lease);
    }
    return result;
}

BOOL WINAPI ReadDataDetour(
    const HINTERNET request, const LPVOID buffer, const DWORD bytes, const LPDWORD read) {
    const std::uint64_t qpc = QueryPerformanceCounterValue();
    const void* const return_address = _ReturnAddress();
    const AnomalyHookServiceV1* service{};
    AnomalyGenerationHandleV1 lease{};
    Context* const capture = BeginCapture(service, lease);
    const ReadDataFn original = g_read_data_original.load(std::memory_order_acquire);
    if (original == nullptr) {
        if (capture != nullptr) EndCapture(service, lease);
        return FALSE;
    }
    TraceRecord record{};
    record.qpc = qpc;
    record.thread_id = GetCurrentThreadId();
    record.return_address = reinterpret_cast<std::uintptr_t>(return_address);
    record.operation = static_cast<std::uint16_t>(HttpOperation::ReadData);
    HandleBits(request, record.handle_bits);
    CaptureUrl(request, record.url, record.url_size);
    record.size = bytes;
    const BOOL result = original(request, buffer, bytes, read);
    record.status = static_cast<std::int32_t>(GetLastError());
    DWORD got = 0;
    __try {
        if (result != FALSE && read != nullptr) got = *read;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        got = 0;
    }
    CapturePayload(buffer, got, record.payload, record.payload_size);
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

void AppendQuotedUtf8(
    std::string& output, const wchar_t* text, const std::uint16_t size) {
    output.push_back('"');
    for (std::size_t index = 0; index < size; ++index) {
        const std::uint32_t codepoint = static_cast<std::uint32_t>(text[index]);
        if (codepoint == '"' || codepoint == '\\') output.push_back('\\');
        if (codepoint >= 0x20U && codepoint < 0x7FU) {
            output.push_back(static_cast<char>(codepoint));
        } else if (codepoint != 0) {
            output += "\\u";
            static constexpr char hex[] = "0123456789abcdef";
            output.push_back(hex[(codepoint >> 12U) & 0xfU]);
            output.push_back(hex[(codepoint >> 8U) & 0xfU]);
            output.push_back(hex[(codepoint >> 4U) & 0xfU]);
            output.push_back(hex[codepoint & 0xfU]);
        } else {
            break;
        }
    }
    output.push_back('"');
}

std::string Serialize(
    const Context& context, const std::uint64_t persisted_records,
    const std::uint64_t persisted_max_sequence, const std::uint64_t persistence_successes,
    const bool final_persist_succeeded) {
    std::string output;
    output.reserve(1024U + context.history.size() * 1400U);
    output += "{\"schemaVersion\":2,\"captureId\":\"";
    AppendCaptureId(output, context.capture_id);
    output += "\",\"pluginId\":\"anomaly.diagnostics.http.winhttp\"";
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
        output += ",\"returnAddress\":\"";
        AppendHex(output, record.return_address);
        output += "\",\"handle\":\"";
        AppendHex(output, record.handle_bits);
        output += "\",\"operation\":\"";
        switch (static_cast<HttpOperation>(record.operation)) {
            case HttpOperation::SendRequest: output += "sendRequest"; break;
            case HttpOperation::ReceiveResponse: output += "receiveResponse"; break;
            case HttpOperation::WriteData: output += "writeData"; break;
            case HttpOperation::ReadData: output += "readData"; break;
            default: output += "unknown"; break;
        }
        output += "\",\"status\":" + std::to_string(record.status);
        output += ",\"size\":" + std::to_string(record.size);
        output += ",\"url\":";
        AppendQuotedUtf8(output, record.url.data(), record.url_size);
        output += ",\"headers\":";
        AppendQuotedUtf8(output, record.headers.data(), record.headers_size);
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
            context.storage->user, anomaly::sdk::StringView("winhttp-trace.json"), bytes).code ==
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
    const auto resolve = [](const char* name) noexcept {
        const HMODULE module = GetModuleHandleW(L"winhttp.dll");
        return module == nullptr
            ? std::uintptr_t{}
            : reinterpret_cast<std::uintptr_t>(GetProcAddress(module, name));
    };
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
        static_cast<void>(ReleaseHook(*context, context->hook_read_data));
        static_cast<void>(ReleaseHook(*context, context->hook_write_data));
        static_cast<void>(ReleaseHook(*context, context->hook_receive_response));
        static_cast<void>(ReleaseHook(*context, context->hook_send_request));
        g_send_request_original.store(nullptr, std::memory_order_release);
        g_receive_response_original.store(nullptr, std::memory_order_release);
        g_write_data_original.store(nullptr, std::memory_order_release);
        g_read_data_original.store(nullptr, std::memory_order_release);
    };
    const std::uintptr_t send_request_target = resolve("WinHttpSendRequest");
    const std::uintptr_t receive_response_target = resolve("WinHttpReceiveResponse");
    const std::uintptr_t write_data_target = resolve("WinHttpWriteData");
    const std::uintptr_t read_data_target = resolve("WinHttpReadData");
    if (send_request_target == 0 || receive_response_target == 0 ||
        write_data_target == 0 || read_data_target == 0) {
        return Status(ANOMALY_STATUS_V1_UNAVAILABLE, "WinHTTP trace target is unavailable");
    }
    if (BCryptGenRandom(
            nullptr, context->capture_id.data(), static_cast<ULONG>(context->capture_id.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return Status(ANOMALY_STATUS_V1_UNAVAILABLE, "capture id generation failed");
    }
    if (!create_hook(
            send_request_target, reinterpret_cast<void*>(&SendRequestDetour),
            "winhttp-sendrequest-trace",
            [](const std::uintptr_t original) {
                g_send_request_original.store(
                    reinterpret_cast<SendRequestFn>(original), std::memory_order_release);
            },
            context->hook_send_request)) {
        return Status(ANOMALY_STATUS_V1_FAILED, "WinHttpSendRequest hook creation failed");
    }
    if (!create_hook(
            receive_response_target, reinterpret_cast<void*>(&ReceiveResponseDetour),
            "winhttp-receiveresponse-trace",
            [](const std::uintptr_t original) {
                g_receive_response_original.store(
                    reinterpret_cast<ReceiveResponseFn>(original), std::memory_order_release);
            },
            context->hook_receive_response)) {
        release_all();
        return Status(ANOMALY_STATUS_V1_FAILED, "WinHttpReceiveResponse hook creation failed");
    }
    if (!create_hook(
            write_data_target, reinterpret_cast<void*>(&WriteDataDetour),
            "winhttp-writedata-trace",
            [](const std::uintptr_t original) {
                g_write_data_original.store(
                    reinterpret_cast<WriteDataFn>(original), std::memory_order_release);
            },
            context->hook_write_data)) {
        release_all();
        return Status(ANOMALY_STATUS_V1_FAILED, "WinHttpWriteData hook creation failed");
    }
    if (!create_hook(
            read_data_target, reinterpret_cast<void*>(&ReadDataDetour),
            "winhttp-readdata-trace",
            [](const std::uintptr_t original) {
                g_read_data_original.store(
                    reinterpret_cast<ReadDataFn>(original), std::memory_order_release);
            },
            context->hook_read_data)) {
        release_all();
        return Status(ANOMALY_STATUS_V1_FAILED, "WinHttpReadData hook creation failed");
    }
    context->qpc_frequency = QueryPerformanceFrequencyValue();
    const std::uint64_t qpc_before_clock = QueryPerformanceCounterValue();
    context->started_utc_unix_milliseconds = QueryUnixTimeMilliseconds();
    const std::uint64_t qpc_after_clock = QueryPerformanceCounterValue();
    context->started_qpc = qpc_before_clock + (qpc_after_clock - qpc_before_clock) / 2U;
    g_hook_service.store(context->hook, std::memory_order_release);
    g_hook_id.store(context->hook_send_request.id, std::memory_order_release);
    g_hook_generation.store(context->hook_send_request.generation, std::memory_order_release);
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
    const bool send_request_quiesced = ReleaseHook(*context, context->hook_send_request);
    const bool receive_response_quiesced = ReleaseHook(*context, context->hook_receive_response);
    const bool write_data_quiesced = ReleaseHook(*context, context->hook_write_data);
    const bool read_data_quiesced = ReleaseHook(*context, context->hook_read_data);
    const bool hook_quiesced = send_request_quiesced && receive_response_quiesced &&
        write_data_quiesced && read_data_quiesced;
    g_send_request_original.store(nullptr, std::memory_order_release);
    g_receive_response_original.store(nullptr, std::memory_order_release);
    g_write_data_original.store(nullptr, std::memory_order_release);
    g_read_data_original.store(nullptr, std::memory_order_release);
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
        anomaly::sdk::StringView("anomaly.diagnostics.http.winhttp"),
        anomaly::sdk::StringView("WinHTTP plaintext HTTP trace"),
        anomaly::sdk::StringView("Anomaly"), anomaly::sdk::StringView("0.1.0"),
        Load, Start, Stop, Unload, nullptr, nullptr};
    return anomaly::sdk::Ok();
}
