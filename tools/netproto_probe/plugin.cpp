// NetProtoPipelineTrace: traces pre/post PacketHandler pipeline packets and UDP/TCP connection internals.
#include "anomaly/sdk/cpp.hpp"

#include <windows.h>
#include <cstdio>
#include <bcrypt.h>
#include <intrin.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <new>
#include <string>
#include <vector>

namespace {

constexpr std::size_t kRingCapacity = 2048;
constexpr std::size_t kMaximumHistoryRecords = 1024;
constexpr std::size_t kPayloadCapacity = 1536;
constexpr std::size_t kExtraCapacity = 512;
constexpr std::uint32_t kFlushIntervalMilliseconds = 5000;
constexpr std::uint64_t kUnixEpochFileTimeTicks = 116444736000000000ULL;
constexpr std::uint64_t kFileTimeTicksPerMillisecond = 10000ULL;

inline bool IsUserMemory(std::uint64_t address) {
    return address != 0 && address < 0x0000800000000000ULL;
}

constexpr wchar_t kBeaconPath[] =
    L"C:\\Users\\owo\\Documents\\.SoucreCode\\Anomaly\\.build\\windows-vs2022\\game-package\\"
    L"Anomaly\\state\\plugins\\anomaly.diagnostics.netproto.pipeline\\beacon.txt";

inline void Beacon(const char* tag, const char* text) {
    __try {
        HANDLE handle = CreateFileW(kBeaconPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle != INVALID_HANDLE_VALUE) {
            char line[512]{};
            int written = _snprintf_s(line, sizeof(line), _TRUNCATE, "%s %s\n", tag, text);
            if (written > 0) {
                DWORD bytes_written = 0;
                (void)WriteFile(handle, line, static_cast<DWORD>(written), &bytes_written, nullptr);
            }
            CloseHandle(handle);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

inline void BeaconQ(const char* tag, const char* text, std::uint64_t value) {
    char line[512]{};
    _snprintf_s(line, sizeof(line), _TRUNCATE, "%s 0x%llX", text, static_cast<unsigned long long>(value));
    Beacon(tag, line);
}

// Hooked game functions (RVAs from the 5.6.1-0+UE5-HT-1.3 build, live client as of 2026-09-09 21:27 patch; old 9/5 addresses in parentheses).
constexpr std::uint64_t kRvaLowLevelSendInner = 0x14604CFF0 - 0x140000000; // sub_14604CFF0 (was 0x14604CF20)
constexpr std::uint64_t kRvaPacketHandler      = 0x142766EA0 - 0x140000000; // sub_142766EA0
constexpr std::uint64_t kRvaRecvPump           = 0x14604A820 - 0x140000000; // sub_14604A820
constexpr std::uint64_t kRvaConnTick           = 0x146030820 - 0x140000000; // sub_146030820
constexpr std::uint64_t kRvaRecvDispatch       = 0x146041E60 - 0x140000000; // sub_146041E60
constexpr std::uint64_t kRvaReceivePacket       = 0x1444DFE40 - 0x140000000; // sub_1444DFE40 (S2C packet entry)
constexpr std::uint64_t kRvaHeaderRead          = 0x144510980 - 0x140000000; // sub_144510980 (packet header reader)
constexpr std::uint64_t kRvaStatusAck           = 0x1444DFAD0 - 0x140000000; // sub_1444DFAD0 (status/ack tail)
constexpr std::uint64_t kRvaWriteHeader         = 0x1445240F0 - 0x140000000; // sub_1445240F0 (was 0x1445241E0, packet header writer)
constexpr std::uint64_t kRvaBunchProcess        = 0x1444CCC10 - 0x140000000; // sub_1444CCC10 (was 0x1444CCD00, bunch processor)
constexpr std::uint64_t kRvaChannelRecv         = 0x1441D36E0 - 0x140000000; // UActorChannel vtable slot 91 (bunch receiver)
constexpr std::uint64_t kRvaSendBunch           = 0x1441DD920 - 0x140000000; // UChannel::SendBunch (was 0x1441DDA60)
constexpr std::uint64_t kRvaFieldHeader         = 0x1441E9040 - 0x140000000; // UChannel::WriteFieldHeaderAndPayload (was 0x1441E9180)
constexpr std::uint64_t kRvaWriteInt            = 0x141632E90 - 0x140000000; // FBitWriter::WriteInt(value,max) (was 0x141632E70)
constexpr std::uint64_t kRvaWriteBit            = 0x141630F00 - 0x140000000; // FBitWriter::WriteBit (was 0x141630EE0)
constexpr std::uint64_t kRvaSerializeBits        = 0x14162E3C0 - 0x140000000; // FBitWriter::SerializeBits(void*,NumBits) (was 0x14162E3A0)
constexpr std::uint64_t kRvaSerializeInt         = 0x14162E760 - 0x140000000; // FBitWriter::SerializeInt(uint32*,Max) (was 0x14162E740)
constexpr std::uint64_t kRvaProcessRPC           = 0x14450F8C0 - 0x140000000; // UChannel::ProcessRemoteFunctionForChannelPrivate (RPC params entry; was 0x14450F9B0)
constexpr std::size_t kHookCount = 10;

using LowLevelSendFn = std::uint64_t(__fastcall*)(std::uintptr_t, std::uintptr_t, int, std::uintptr_t);
using PacketHandlerFn = std::uintptr_t(__fastcall*)(
    std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uint32_t,
    std::uintptr_t, char, std::uintptr_t);
using RecvPumpFn = unsigned char(__fastcall*)(std::uintptr_t);
using ConnTickFn = void(__fastcall*)(std::uintptr_t);
using RecvDispatchFn = void(__fastcall*)(std::uintptr_t, std::uintptr_t, std::uintptr_t,
                                         std::uint32_t, std::uintptr_t);
using ReceivePacketFn = std::uint64_t(__fastcall*)(std::uintptr_t, std::uintptr_t*, char, char);
using HeaderReadFn = char(__fastcall*)(std::uintptr_t, std::uintptr_t, std::uintptr_t);
using StatusAckFn = char(__fastcall*)(std::uintptr_t, std::uintptr_t, char, int);
using WriteHeaderFn = char(__fastcall*)(std::uintptr_t, std::uintptr_t, char);
using BunchProcessFn = std::uint64_t(__fastcall*)(std::uintptr_t, std::uintptr_t*, unsigned int,
                                                  std::uint8_t*, std::uint8_t*);
using ChannelRecvFn = std::uint64_t(__fastcall*)(std::uintptr_t, std::uintptr_t*);
using SendBunchFn = std::uintptr_t(__fastcall*)(std::uintptr_t, std::uintptr_t*, std::uintptr_t, unsigned char);
using FieldHeaderFn = std::uintptr_t(__fastcall*)(std::uintptr_t, std::uint32_t*, std::uint32_t*, std::uintptr_t, std::uintptr_t, std::uintptr_t, unsigned char);
using WriteIntFn = std::uint64_t(__fastcall*)(std::uintptr_t, int, unsigned int);
using WriteBitFn = std::uint64_t(__fastcall*)(std::uintptr_t, unsigned char);
using SerializeBitsFn = void(__fastcall*)(std::uintptr_t, void*, std::int64_t);
using SerializeIntFn = std::uint64_t(__fastcall*)(std::uintptr_t, std::uint32_t*, std::uint32_t);
using ProcessRPCFn = void(__fastcall*)(
    std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t,
    std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t,
    std::uintptr_t, std::uint64_t, std::uintptr_t);

struct EventRecord final {
    std::uint64_t sequence{};
    std::uint64_t qpc{};
    std::uint32_t hook{}; // 1=LowLevelSend 2=PacketHandler 3=RecvPump 4=ConnTick
    std::uint32_t thread_id{};
    std::array<std::uint64_t, 8> args{};
    std::uint32_t payload_size{};
    std::array<std::uint8_t, kPayloadCapacity> payload{};
    std::uint32_t extra_size{};
    std::array<std::uint8_t, kExtraCapacity> extra{};
};

struct Context final {
    std::atomic<std::uint64_t> next_sequence{0};
    std::atomic<std::uint32_t> ring_dropped{0};
    EventRecord ring[kRingCapacity]{};
    std::vector<EventRecord> history;
    std::mutex ring_mutex;
    std::mutex persistence_mutex;
    std::mutex flush_mutex;
    const AnomalyStorageServiceV1* storage{};
    const AnomalySchedulerServiceV1* scheduler{};
    const AnomalyHookServiceV1* hook{};
    AnomalyGenerationHandleV1 hook_handles[17]{};
    std::atomic<std::uint64_t> hook_ids[17]{};
    std::atomic<std::uint64_t> hook_generations[17]{};
    AnomalyGenerationHandleV1 flush_task{};
    AnomalyGenerationHandleV1 install_task{};
    std::uint64_t qpc_frequency{};
    std::uint64_t started_qpc{};
    std::uint64_t started_utc_unix_milliseconds{};
    std::uint64_t ended_qpc{};
    std::uint64_t ended_utc_unix_milliseconds{};
    std::uint64_t records_observed{};
    std::uint64_t records_recorded{};
    std::uint64_t records_persisted{};
    std::uint64_t persistence_attempts{};
    std::uint64_t persistence_successes{};
    std::uint64_t persistence_failures{};
    std::uint64_t last_persisted_sequence{}; // guarded by persistence_mutex
    std::atomic<std::uint32_t> scheduling_failures{0};
    std::atomic<bool> capture_open{true};
    std::atomic<bool> stop_started{false};
    bool finalization_requested{};
    bool finalized{};
    bool hook_quiesced{};
    std::array<std::uint8_t, 16> capture_id{};
};

std::atomic<const AnomalyHookServiceV1*> g_hook_service{};
std::atomic<Context*> g_context{};
std::atomic<void*> g_live_context{};
LowLevelSendFn g_original_low_level_send{};
PacketHandlerFn g_original_packet_handler{};
RecvPumpFn g_original_recv_pump{};
ConnTickFn g_original_conn_tick{};
RecvDispatchFn g_original_recv_dispatch{};
ReceivePacketFn g_original_receive_packet{};
HeaderReadFn g_original_header_read{};
StatusAckFn g_original_status_ack{};
WriteHeaderFn g_original_write_header{};
BunchProcessFn g_original_bunch_process{};
ChannelRecvFn g_original_channel_recv{};
SendBunchFn g_original_send_bunch{};
FieldHeaderFn g_original_field_header{};
WriteIntFn g_original_write_int{};
WriteBitFn g_original_write_bit{};
SerializeBitsFn g_original_serialize_bits{};
SerializeIntFn g_original_serialize_int{};
ProcessRPCFn g_original_process_rpc{};

std::uint64_t QueryPerformanceCounterValue() noexcept {
    LARGE_INTEGER value{};
    QueryPerformanceCounter(&value);
    return static_cast<std::uint64_t>(value.QuadPart);
}

std::uint64_t QueryPerformanceFrequencyValue() noexcept {
    LARGE_INTEGER value{};
    QueryPerformanceFrequency(&value);
    return static_cast<std::uint64_t>(value.QuadPart);
}

std::uint64_t QueryUnixTimeMilliseconds() noexcept {
    FILETIME file_time{};
    GetSystemTimeAsFileTime(&file_time);
    const std::uint64_t ticks =
        (static_cast<std::uint64_t>(file_time.dwHighDateTime) << 32U) | file_time.dwLowDateTime;
    return (ticks - kUnixEpochFileTimeTicks) / kFileTimeTicksPerMillisecond;
}

AnomalyStatusV1 Status(const std::int32_t code, const char* message) noexcept {
    return {static_cast<std::uint32_t>(code), 0, anomaly::sdk::StringView(message)};
}

void CaptureBytes(const void* buffer, const std::uint32_t length,
                  std::array<std::uint8_t, kPayloadCapacity>& destination,
                  std::uint32_t& size) noexcept {
    destination.fill(0);
    size = 0;
    if (buffer == nullptr || length == 0) return;
    const std::uint32_t bounded = (std::min)(length, static_cast<std::uint32_t>(destination.size()));
    __try {
        std::memcpy(destination.data(), buffer, bounded);
        size = bounded;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        size = 0;
    }
}

void CaptureExtra(std::array<std::uint8_t, kExtraCapacity>& destination,
                  std::uint32_t& size, const std::uint64_t* values, std::uint32_t count) noexcept {
    destination.fill(0);
    size = 0;
    if (values == nullptr) return;
    const std::uint32_t bounded = (std::min)(count * 8U, static_cast<std::uint32_t>(destination.size()));
    std::memcpy(destination.data(), values, bounded);
    size = bounded;
}

template <typename Service>
const Service* Query(const AnomalyHostApiV1* host, const char* id) noexcept {
    return anomaly::sdk::Host(host).Query<Service>(id, 1).get();
}

bool BeginCapture(AnomalyGenerationHandleV1& lease) noexcept {
    auto* const service = g_hook_service.load(std::memory_order_acquire);
    auto* const context = g_context.load(std::memory_order_acquire);
    if (service == nullptr || context == nullptr ||
        !context->capture_open.load(std::memory_order_relaxed)) return false;
    lease.id = context->hook_ids[0].load(std::memory_order_acquire);
    lease.generation = context->hook_generations[0].load(std::memory_order_acquire);
    if (lease.id == 0) return false;
    AnomalyGenerationHandleV1 callback_lease{};
    if (service->begin_callback == nullptr || service->end_callback == nullptr) return false;
    if (service->begin_callback(
            service->user, {lease.id, lease.generation}, &callback_lease).code !=
            ANOMALY_STATUS_V1_OK) return false;
    lease = callback_lease;
    return true;
}

void EndCapture(const AnomalyGenerationHandleV1 lease) noexcept {
    auto* const service = g_hook_service.load(std::memory_order_acquire);
    if (service == nullptr || service->end_callback == nullptr) return;
    if (lease.id == 0) return;
    static_cast<void>(service->end_callback(service->user, lease));
}

void FillRecord(EventRecord& record, const void* payload, std::uint32_t payload_size,
                const void* extra, std::uint32_t extra_size) noexcept {
    __try {
        CaptureBytes(payload, payload_size, record.payload, record.payload_size);
        if (extra != nullptr && extra_size != 0 && extra_size <= kExtraCapacity) {
            std::memcpy(record.extra.data(), extra, extra_size);
            record.extra_size = extra_size;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        record.payload_size = 0;
        record.extra_size = 0;
    }
}

void Emit(std::uint32_t hook, std::array<std::uint64_t, 8> args,
          const void* payload, std::uint32_t payload_size,
          const void* extra, std::uint32_t extra_size) noexcept {
    auto* const context = g_context.load(std::memory_order_acquire);
    if (context == nullptr || !context->capture_open.load(std::memory_order_relaxed)) return;
    EventRecord record{};
    record.sequence = context->next_sequence.fetch_add(1U, std::memory_order_relaxed);
    record.qpc = QueryPerformanceCounterValue();
    record.hook = hook;
    record.thread_id = static_cast<std::uint32_t>(GetCurrentThreadId());
    record.args = args;
    FillRecord(record, payload, payload_size, extra, extra_size);
    {
        std::scoped_lock lock(context->ring_mutex);
        const std::uint64_t sequence = record.sequence;
        const std::size_t slot = sequence % kRingCapacity;
        context->ring[slot] = record;
    }
}

void Drain(Context& context) {
    std::scoped_lock lock(context.ring_mutex);
    const std::uint64_t observed = context.next_sequence.load(std::memory_order_relaxed);
    if (context.history.empty()) {
        const std::uint64_t first = observed > kRingCapacity ? observed - kRingCapacity : 0;
        for (std::uint64_t seq = first; seq < observed; ++seq) {
            const EventRecord& record = context.ring[seq % kRingCapacity];
            if (record.sequence == seq && record.qpc != 0) context.history.push_back(record);
        }
    } else {
        const std::uint64_t last = context.history.back().sequence;
        std::uint64_t start = last + 1;
        if (observed > start + kRingCapacity) start = observed - kRingCapacity;
        for (std::uint64_t seq = start; seq < observed; ++seq) {
            const EventRecord& record = context.ring[seq % kRingCapacity];
            if (record.sequence == seq && record.qpc != 0) context.history.push_back(record);
        }
    }
    while (context.history.size() > kMaximumHistoryRecords) {
        context.history.erase(context.history.begin());
    }
    context.records_recorded = context.history.size();
    context.records_observed = observed;
}

void AppendHex(std::string& output, const std::uint8_t* data, std::size_t size) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    for (std::size_t i = 0; i < size; ++i) {
        output.push_back(kHexDigits[data[i] >> 4U]);
        output.push_back(kHexDigits[data[i] & 15U]);
    }
}

std::string Serialize(const Context& context, std::uint64_t persisted_records,
                      std::uint64_t persisted_max_sequence,
                      std::uint64_t persistence_successes, bool final_persist_succeeded) {
    std::string output;
    output.reserve(1024 + context.history.size() * 900);
    output += "{\"schemaVersion\":2,\"captureId\":\"";
    AppendHex(output, context.capture_id.data(), context.capture_id.size());
    output += "\",\"pluginId\":\"anomaly.diagnostics.netproto.pipeline\",\"hookCount\":4";
    output += ",\"clock\":{\"qpcFrequency\":" + std::to_string(context.qpc_frequency);
    output += ",\"startedQpc\":" + std::to_string(context.started_qpc);
    output += ",\"startedUtcUnixMilliseconds\":" + std::to_string(context.started_utc_unix_milliseconds);
    output += ",\"endedQpc\":" + std::to_string(context.ended_qpc);
    output += ",\"endedUtcUnixMilliseconds\":" + std::to_string(context.ended_utc_unix_milliseconds) + "}";
    output += ",\"state\":{\"finalizationRequested\":";
    output += context.finalization_requested ? "true" : "false";
    output += ",\"finalized\":";
    output += final_persist_succeeded ? "true" : "false";
    output += ",\"hookQuiesced\":";
    output += context.hook_quiesced ? "true" : "false";
    output += ",\"captureOpen\":";
    output += context.capture_open.load(std::memory_order_relaxed) ? "true" : "false";
    output += "}";
    output += ",\"integrity\":{\"recordsObserved\":";
    output += std::to_string(context.records_observed);
    output += ",\"recordsRecorded\":" + std::to_string(context.records_recorded);
    output += ",\"recordsPersisted\":" + std::to_string(persisted_records);
    output += ",\"persistedMaxSequence\":" + std::to_string(persisted_max_sequence);
    output += ",\"ringDropped\":" + std::to_string(context.ring_dropped.load(std::memory_order_relaxed));
    output += ",\"persistenceAttempts\":" + std::to_string(context.persistence_attempts);
    output += ",\"persistenceSuccesses\":" + std::to_string(persistence_successes);
    output += ",\"persistenceFailures\":" + std::to_string(context.persistence_failures);
    output += ",\"schedulingFailures\":" + std::to_string(context.scheduling_failures.load(std::memory_order_relaxed)) + "}";
    output += ",\"events\":[";
    bool first = true;
    for (const EventRecord& record : context.history) {
        if (!first) output.push_back(',');
        first = false;
        output += "{\"sequence\":" + std::to_string(record.sequence);
        output += ",\"qpc\":" + std::to_string(record.qpc);
        output += ",\"hook\":" + std::to_string(record.hook);
        output += ",\"threadId\":" + std::to_string(record.thread_id);
        output += ",\"args\":[";
        for (std::size_t i = 0; i < record.args.size(); ++i) {
            if (i != 0) output.push_back(',');
            output += "\"0x";
            char buffer[32]{};
            _ui64toa_s(record.args[i], buffer, sizeof(buffer), 16);
            output += buffer;
            output.push_back('"');
        }
        output += "],\"payload\":\"";
        AppendHex(output, record.payload.data(), record.payload_size);
        output += "\",\"extra\":\"";
        AppendHex(output, record.extra.data(), record.extra_size);
        output += "\"}";
    }
    output += "]}";
    return output;
}

bool Persist(Context& context, const bool final_snapshot, const bool hook_quiesced) {
    std::scoped_lock lock(context.persistence_mutex);
    Drain(context);
    const std::uint64_t current_max_sequence =
        context.history.empty() ? 0U : context.history.back().sequence;
    if (!final_snapshot && current_max_sequence == context.last_persisted_sequence) {
        return true;
    }
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
            context.storage->user, anomaly::sdk::StringView("netproto-trace.json"), bytes).code ==
            ANOMALY_STATUS_V1_OK;
    if (written) {
        context.persistence_successes = persistence_successes;
        context.last_persisted_sequence = persisted_max_sequence;
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
    static int beacon_tick = 0;
    if ((beacon_tick++ & 7) == 0) {
        char line[512]{};
        _snprintf_s(line, sizeof(line), _TRUNCATE,
                    "obs=%llu rec=%llu pers=%llu succ=%llu fail=%llu schedfail=%llu open=%d stop=%d",
                    (unsigned long long)context->records_observed,
                    (unsigned long long)context->records_recorded,
                    (unsigned long long)context->records_persisted,
                    (unsigned long long)context->persistence_successes,
                    (unsigned long long)context->persistence_failures,
                    (unsigned long long)context->scheduling_failures.load(),
                    context->capture_open.load() ? 1 : 0,
                    context->stop_started.load() ? 1 : 0);
        Beacon("flush", line);
    }
    static_cast<void>(Persist(*context, false, false));
    if (context->stop_started.load(std::memory_order_acquire) || context->finalization_requested) {
        context->finalized = true;
        return;
    }
    ScheduleFlush(context, kFlushIntervalMilliseconds);
}

void ScheduleFlush(Context* context, const std::uint32_t delay_milliseconds) {
    if (context == nullptr || context->stop_started.load(std::memory_order_acquire) ||
        context->scheduler == nullptr || context->scheduler->schedule == nullptr) return;
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

// ---- Detours ----

std::uint64_t __fastcall DetourLowLevelSend(std::uintptr_t a1, std::uintptr_t a2, int a3,
                                            std::uintptr_t a4) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, a2, static_cast<std::uint64_t>(static_cast<std::uint32_t>(a3)), a4, 0, 0, 0, 0};
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint32_t extra_size = 0;
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = a1;
            extra_values[1] = *reinterpret_cast<std::uint64_t*>(a1 + 320);
            const std::uint64_t pipeline = extra_values[1];
            if (IsUserMemory(pipeline)) {
                extra_values[2] = *reinterpret_cast<std::uint32_t*>(pipeline + 432);
                extra_values[3] = *reinterpret_cast<std::uint64_t*>(pipeline + 560);
                const std::uint64_t handlers = *reinterpret_cast<std::uint64_t*>(pipeline + 424);
                const bool handlers_ok = IsUserMemory(handlers);
                for (std::uint32_t i = 0; i < 4; ++i) {
                    const std::uint64_t handler = handlers_ok
                        ? *reinterpret_cast<std::uint64_t*>(handlers + 16ULL * i) : 0;
                    const bool handler_ok = IsUserMemory(handler);
                    extra_values[4 + i] = handler_ok ? handler : 0;
                    extra_values[8 + i] = handler_ok
                        ? *reinterpret_cast<std::uint64_t*>(handler) : 0;
                }
                if (IsUserMemory(extra_values[4])) {
                    const std::uint64_t handler0 = extra_values[4];
                    extra_values[12] = *reinterpret_cast<std::uint64_t*>(handler0 + 472);
                    extra_values[13] = *reinterpret_cast<std::uint64_t*>(handler0 + 480);
                    extra_values[14] = *reinterpret_cast<std::uint64_t*>(handler0 + 488);
                    extra_values[15] = *reinterpret_cast<std::uint64_t*>(handler0 + 496);
                    extra_values[16] = *reinterpret_cast<std::uint64_t*>(handler0 + 504);
                    extra_values[17] = *reinterpret_cast<std::uint64_t*>(handler0 + 512);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        extra_size = sizeof(extra_values);
        const std::uint32_t bytes = a3 > 0 ? (static_cast<std::uint32_t>(a3) + 7U) / 8U : 0U;
        Emit(1, args, reinterpret_cast<void*>(a2), bytes, extra.data(), extra_size);
    }
    const std::uint64_t result =
        g_original_low_level_send != nullptr ? g_original_low_level_send(a1, a2, a3, a4) : 0;
    if (capturing) EndCapture(lease);
    return result;
}

std::uintptr_t __fastcall DetourPacketHandler(std::uintptr_t a1, std::uintptr_t a2,
                                              std::uintptr_t a3, std::uint32_t a4,
                                              std::uintptr_t a5, char a6, std::uintptr_t a7) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, a2, a3, a4, a5, static_cast<std::uint64_t>(static_cast<unsigned char>(a6)), a7, 0};
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint32_t extra_size = 0;
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = a1;
            extra_values[1] = *reinterpret_cast<std::uint32_t*>(a1 + 432);
            extra_values[2] = *reinterpret_cast<std::uint64_t*>(a1 + 560);
            extra_values[3] = *reinterpret_cast<std::uint64_t*>(a1 + 208);
            extra_values[4] = *reinterpret_cast<std::uint32_t*>(a1 + 224);
            const std::uint64_t handlers = *reinterpret_cast<std::uint64_t*>(a1 + 424);
            const bool handlers_ok = IsUserMemory(handlers);
            for (std::uint32_t i = 0; i < 4; ++i) {
                const std::uint64_t handler = handlers_ok
                    ? *reinterpret_cast<std::uint64_t*>(handlers + 16ULL * i) : 0;
                const bool handler_ok = IsUserMemory(handler);
                extra_values[5 + i] = handler_ok ? handler : 0;
                extra_values[9 + i] = handler_ok
                    ? *reinterpret_cast<std::uint64_t*>(handler) : 0;
            }
            if (IsUserMemory(extra_values[5])) {
                const std::uint64_t handler0 = extra_values[5];
                extra_values[13] = *reinterpret_cast<std::uint64_t*>(handler0 + 472);
                extra_values[14] = *reinterpret_cast<std::uint64_t*>(handler0 + 480);
                extra_values[15] = *reinterpret_cast<std::uint64_t*>(handler0 + 488);
                extra_values[16] = *reinterpret_cast<std::uint64_t*>(handler0 + 496);
                extra_values[17] = *reinterpret_cast<std::uint64_t*>(handler0 + 504);
                extra_values[18] = *reinterpret_cast<std::uint64_t*>(handler0 + 512);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        extra_size = sizeof(extra_values);
        const std::uint32_t bytes = (a4 + 7U) / 8U;
        Emit(2, args, reinterpret_cast<void*>(a3), bytes, extra.data(), extra_size);
    }
    const std::uintptr_t result = g_original_packet_handler != nullptr
        ? g_original_packet_handler(a1, a2, a3, a4, a5, a6, a7) : 0;
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, a2, a3, a4, a5, static_cast<std::uint64_t>(static_cast<unsigned char>(a6)), a7, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::uint32_t payload_size = 0;
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint32_t extra_size = 0;
        __try {
            const __int64 out_ptr = *reinterpret_cast<const __int64*>(a2);
            const std::uint32_t out_bits = *reinterpret_cast<const std::uint32_t*>(a2 + 8);
            const std::uint32_t out_flag = *reinterpret_cast<const unsigned char*>(a2 + 12);
            std::uint64_t extra_values[24]{};
            extra_values[0] = static_cast<std::uint64_t>(out_ptr);
            extra_values[1] = out_bits;
            extra_values[2] = out_flag;
            const std::uint64_t handlers = *reinterpret_cast<std::uint64_t*>(a1 + 424);
            const bool handlers_ok = IsUserMemory(handlers);
            for (std::uint32_t i = 0; i < 4; ++i) {
                const std::uint64_t handler = handlers_ok
                    ? *reinterpret_cast<std::uint64_t*>(handlers + 16ULL * i) : 0;
                const bool handler_ok = IsUserMemory(handler);
                extra_values[3 + i] = handler_ok ? handler : 0;
                extra_values[7 + i] = handler_ok
                    ? *reinterpret_cast<std::uint64_t*>(handler) : 0;
            }
            if (IsUserMemory(extra_values[3])) {
                const std::uint64_t handler0 = extra_values[3];
                extra_values[11] = *reinterpret_cast<std::uint64_t*>(handler0 + 472);
                extra_values[12] = *reinterpret_cast<std::uint64_t*>(handler0 + 480);
                extra_values[13] = *reinterpret_cast<std::uint64_t*>(handler0 + 488);
                extra_values[14] = *reinterpret_cast<std::uint64_t*>(handler0 + 496);
                extra_values[15] = *reinterpret_cast<std::uint64_t*>(handler0 + 504);
                extra_values[16] = *reinterpret_cast<std::uint64_t*>(handler0 + 512);
            }
            const std::uint32_t out_bytes = (out_bits + 7U) / 8U;
            if (out_ptr != 0 && out_bytes > 0) {
                const std::uint32_t copy_bytes =
                    (std::min)(out_bytes, static_cast<std::uint32_t>(kPayloadCapacity));
                std::memcpy(payload.data(), reinterpret_cast<const void*>(out_ptr), copy_bytes);
                payload_size = copy_bytes;
            }
            extra_size = sizeof(extra_values);
            std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
            extra_size = 0;
        }
        Emit(5, args, payload.data(), payload_size, extra.data(), extra_size);
    }
    if (capturing) EndCapture(lease);
    return result;
}

unsigned char __fastcall DetourRecvPump(std::uintptr_t a1) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    std::uint64_t entry_data = 0;
    std::uint32_t entry_len = 0;
    std::uint32_t entry_status = 0;
    std::uint64_t entry_key = 0;
    std::uint64_t ring_base = 0;
    std::uint32_t ring_mask = 0;
    std::uint32_t ring_read = 0;
    std::uint32_t ring_write = 0;
    std::array<std::uint8_t, kPayloadCapacity> payload{};
    std::uint32_t payload_size = 0;
    if (capturing) {
        __try {
            const std::uint64_t ring = *reinterpret_cast<std::uint64_t*>(a1 + 40);
            if (IsUserMemory(ring)) {
                ring_base = *reinterpret_cast<std::uint64_t*>(ring + 16);
                ring_mask = *reinterpret_cast<std::uint32_t*>(ring + 8);
                ring_read = *reinterpret_cast<std::uint32_t*>(ring + 32);
                ring_write = *reinterpret_cast<std::uint32_t*>(ring + 36);
                if (IsUserMemory(ring_base) && ring_read != ring_write) {
                    const std::uint64_t entry = ring_base + 48ULL * (ring_mask & ring_read);
                    entry_data = *reinterpret_cast<std::uint64_t*>(entry);
                    entry_len = *reinterpret_cast<std::uint32_t*>(entry + 8);
                    entry_status = *reinterpret_cast<std::uint32_t*>(entry + 32);
                    entry_key = *reinterpret_cast<std::uint64_t*>(entry + 40);
                    if (IsUserMemory(entry_data) && entry_len <= kPayloadCapacity) {
                        std::memcpy(payload.data(), reinterpret_cast<const void*>(entry_data), entry_len);
                        payload_size = entry_len;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
        }
    }
    const unsigned char result = g_original_recv_pump != nullptr ? g_original_recv_pump(a1) : 0;
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, result, entry_data, entry_len, entry_status, entry_key, ring_read, ring_write};
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[16]{};
        std::uint32_t post_size = 0;
        __try {
            extra_values[0] = a1;
            extra_values[1] = *reinterpret_cast<std::uint64_t*>(a1 + 40);
            extra_values[2] = static_cast<std::uint64_t>(*reinterpret_cast<unsigned char*>(a1 + 48));
            extra_values[3] = static_cast<std::uint64_t>(static_cast<std::int64_t>(*reinterpret_cast<std::int32_t*>(a1 + 1076)));
            extra_values[4] = *reinterpret_cast<std::uint32_t*>(a1 + 1112);
            extra_values[5] = *reinterpret_cast<std::uint64_t*>(a1 + 1088);
            extra_values[6] = *reinterpret_cast<std::uint64_t*>(a1 + 1104);
            extra_values[7] = *reinterpret_cast<std::uint64_t*>(a1 + 24);
            post_size = 256;
            if (post_size > kPayloadCapacity) post_size = kPayloadCapacity;
            std::memcpy(payload.data(), reinterpret_cast<const void*>(a1 + 52), post_size);
            payload_size = post_size;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(3, args, payload.data(), payload_size, extra.data(), sizeof(extra_values));
    }
    if (capturing) EndCapture(lease);
    return result;
}

void __fastcall DetourConnTick(std::uintptr_t a1) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (g_original_conn_tick != nullptr) g_original_conn_tick(a1);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, 0, 0, 0, 0, 0, 0, 0};
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[16]{};
        __try {
            extra_values[0] = a1;
            extra_values[1] = static_cast<std::uint64_t>(*reinterpret_cast<unsigned char*>(a1));
            extra_values[2] = *reinterpret_cast<std::uint64_t*>(a1 + 8);
            extra_values[3] = *reinterpret_cast<std::uint64_t*>(a1 + 1120);
            extra_values[4] = static_cast<std::uint64_t>(*reinterpret_cast<unsigned char*>(a1 + 1128));
            extra_values[5] = *reinterpret_cast<std::uint32_t*>(a1 + 1132);
            extra_values[6] = *reinterpret_cast<std::uint32_t*>(a1 + 1136);
            extra_values[7] = static_cast<std::uint64_t>(*reinterpret_cast<unsigned char*>(a1 + 1152));
            extra_values[8] = *reinterpret_cast<std::uint32_t*>(a1 + 1156);
            extra_values[9] = *reinterpret_cast<std::uint32_t*>(a1 + 1160);
            extra_values[10] = *reinterpret_cast<std::uint64_t*>(a1 + 1168);
            extra_values[11] = *reinterpret_cast<std::uint64_t*>(a1 + 1184);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(4, args, nullptr, 0, extra.data(), sizeof(extra_values));
    }
    if (capturing) EndCapture(lease);
}

void __fastcall DetourRecvDispatch(std::uintptr_t a1, std::uintptr_t a2, std::uintptr_t a3,
                                   std::uint32_t a4, std::uintptr_t a5) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, a2, a3, a4, a5, 0, 0, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::uint32_t payload_size = 0;
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = a1;
            extra_values[1] = *reinterpret_cast<std::uint64_t*>(a1);
            const std::uint64_t vt = extra_values[1];
            if (IsUserMemory(vt) && IsUserMemory(vt + 0x4E8)) {
                const std::uint64_t getter = *reinterpret_cast<std::uint64_t*>(vt + 0x4E8);
                if (IsUserMemory(getter)) {
                    using GetterFn = std::uint64_t(__fastcall*)(std::uintptr_t);
                    const std::uint64_t v10 = reinterpret_cast<GetterFn>(getter)(a1);
                    extra_values[2] = v10;
                    if (IsUserMemory(v10)) {
                        const std::uint64_t inner_vt = *reinterpret_cast<std::uint64_t*>(v10);
                        extra_values[3] = inner_vt;
                        if (IsUserMemory(inner_vt) && IsUserMemory(inner_vt + 80)) {
                            extra_values[4] = *reinterpret_cast<std::uint64_t*>(inner_vt + 80);
                        }
                    }
                }
            }
            extra_values[5] = a3;
            extra_values[6] = a4;
            const std::uint32_t bytes = a4 > 0 ? (a4 + 7U) / 8U : 0U;
            if (bytes > 0 && IsUserMemory(a3)) {
                payload_size = (std::min)(bytes, static_cast<std::uint32_t>(kPayloadCapacity));
                std::memcpy(payload.data(), reinterpret_cast<const void*>(a3), payload_size);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(6, args, payload.data(), payload_size, extra.data(), sizeof(extra_values));
    }
    if (g_original_recv_dispatch != nullptr) {
        g_original_recv_dispatch(a1, a2, a3, a4, a5);
    }
    if (capturing) EndCapture(lease);
}

// ---- Plugin lifecycle ----

// ---- Packet-layer hooks (6-10) ----

std::uint64_t __fastcall DetourReceivePacket(std::uintptr_t a1, std::uintptr_t* a2, char a3, char a4) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, reinterpret_cast<std::uint64_t>(a2),
            static_cast<std::uint64_t>(static_cast<unsigned char>(a3)),
            static_cast<std::uint64_t>(static_cast<unsigned char>(a4)), 0, 0, 0, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::uint32_t payload_size = 0;
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            const std::uint64_t total_bits = a2[20];
            const std::uint64_t cursor = a2[21];
            const std::uint64_t buffer = a2[18];
            extra_values[0] = total_bits;
            extra_values[1] = cursor;
            extra_values[2] = buffer;
            extra_values[3] = *reinterpret_cast<std::uint64_t*>(a1 + 0x1A80 + 544);
            extra_values[4] = *reinterpret_cast<std::uint64_t*>(a1 + 0x1A80 + 556);
            extra_values[5] = *reinterpret_cast<std::uint64_t*>(a1 + 0x1A80 + 564);
            extra_values[6] = static_cast<std::uint64_t>(*reinterpret_cast<std::uint16_t*>(a1 + 0x1A80 + 590));
            extra_values[7] = static_cast<std::uint64_t>(*reinterpret_cast<std::uint16_t*>(a1 + 0x1A80 + 596));
            extra_values[8] = static_cast<std::uint64_t>(*reinterpret_cast<std::uint16_t*>(a1 + 7372));
            extra_values[9] = *reinterpret_cast<std::uint32_t*>(a1 + 5080);
            extra_values[10] = static_cast<std::uint64_t>(*reinterpret_cast<std::uint16_t*>(a1 + 7380));
            extra_values[11] = static_cast<std::uint64_t>(*reinterpret_cast<std::uint16_t*>(a1 + 7382));
            extra_values[12] = *reinterpret_cast<std::uint32_t*>(a1 + 5088);
            extra_values[13] = static_cast<std::uint64_t>(*reinterpret_cast<unsigned char*>(a1 + 7548));
            const std::uint32_t bytes = total_bits > 0
                ? static_cast<std::uint32_t>((total_bits + 7U) / 8U) : 0U;
            if (IsUserMemory(buffer) && bytes > 0) {
                const std::uint32_t copy_bytes =
                    (std::min)(bytes, static_cast<std::uint32_t>(kPayloadCapacity));
                std::memcpy(payload.data(), reinterpret_cast<const void*>(buffer), copy_bytes);
                payload_size = copy_bytes;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(6, args, payload.data(), payload_size, extra.data(), sizeof(extra_values));
    }
    const std::uint64_t result = g_original_receive_packet != nullptr
        ? g_original_receive_packet(a1, a2, a3, a4) : 0;
    if (capturing) EndCapture(lease);
    return result;
}

char __fastcall DetourHeaderRead(std::uintptr_t a1, std::uintptr_t a2, std::uintptr_t a3) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    const char result = g_original_header_read != nullptr ? g_original_header_read(a1, a2, a3) : 0;
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, a2, a3, static_cast<std::uint64_t>(static_cast<unsigned char>(result)), 0, 0, 0, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::uint32_t payload_size = 0;
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = *reinterpret_cast<std::uint64_t*>(a2 + 0);
            extra_values[1] = *reinterpret_cast<std::uint64_t*>(a2 + 8);
            extra_values[2] = *reinterpret_cast<std::uint64_t*>(a2 + 32);
            extra_values[3] = static_cast<std::uint64_t>(*reinterpret_cast<std::uint16_t*>(a2 + 40));
            extra_values[4] = static_cast<std::uint64_t>(*reinterpret_cast<std::uint16_t*>(a2 + 42));
            extra_values[5] = *reinterpret_cast<std::uint64_t*>(a3 + 160);
            extra_values[6] = *reinterpret_cast<std::uint64_t*>(a3 + 168);
            extra_values[7] = *reinterpret_cast<std::uint64_t*>(a3 + 144);
            const std::uint64_t buffer = extra_values[7];
            if (IsUserMemory(buffer)) {
                const std::uint32_t copy_bytes = (std::min)(32U, static_cast<std::uint32_t>(kPayloadCapacity));
                std::memcpy(payload.data(), reinterpret_cast<const void*>(buffer), copy_bytes);
                payload_size = copy_bytes;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(7, args, payload.data(), payload_size, extra.data(), sizeof(extra_values));
    }
    if (capturing) EndCapture(lease);
    return result;
}

char __fastcall DetourStatusAck(std::uintptr_t a1, std::uintptr_t a2, char a3, int a4) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, a2, static_cast<std::uint64_t>(static_cast<unsigned char>(a3)),
            static_cast<std::uint64_t>(static_cast<std::uint32_t>(a4)), 0, 0, 0, 0};
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = *reinterpret_cast<std::uint64_t*>(a2 + 160);
            extra_values[1] = *reinterpret_cast<std::uint64_t*>(a2 + 168);
            extra_values[2] = *reinterpret_cast<std::uint64_t*>(a2 + 144);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(8, args, nullptr, 0, extra.data(), sizeof(extra_values));
    }
    const char result = g_original_status_ack != nullptr
        ? g_original_status_ack(a1, a2, a3, a4) : 0;
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, a2, static_cast<std::uint64_t>(static_cast<unsigned char>(a3)),
            static_cast<std::uint64_t>(static_cast<std::uint32_t>(a4)),
            static_cast<std::uint64_t>(static_cast<unsigned char>(result)), 0, 0, 0};
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = *reinterpret_cast<std::uint64_t*>(a2 + 160);
            extra_values[1] = *reinterpret_cast<std::uint64_t*>(a2 + 168);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(9, args, nullptr, 0, extra.data(), sizeof(extra_values));
    }
    if (capturing) EndCapture(lease);
    return result;
}

char __fastcall DetourWriteHeader(std::uintptr_t a1, std::uintptr_t a2, char a3) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    const char result = g_original_write_header != nullptr
        ? g_original_write_header(a1, a2, a3) : 0;
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, a2, static_cast<std::uint64_t>(static_cast<unsigned char>(a3)),
            static_cast<std::uint64_t>(static_cast<unsigned char>(result)), 0, 0, 0, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::uint32_t payload_size = 0;
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = static_cast<std::uint64_t>(*reinterpret_cast<std::uint16_t*>(a1 + 590));
            extra_values[1] = static_cast<std::uint64_t>(*reinterpret_cast<std::uint16_t*>(a1 + 596));
            extra_values[2] = static_cast<std::uint64_t>(*reinterpret_cast<std::uint16_t*>(a1 + 552));
            extra_values[3] = *reinterpret_cast<std::uint64_t*>(a1 + 544);
            extra_values[4] = *reinterpret_cast<std::uint64_t*>(a1 + 556);
            extra_values[5] = *reinterpret_cast<std::uint64_t*>(a1 + 564);
            const std::uint64_t writer = a2;
            if (IsUserMemory(writer)) {
                const std::uint64_t arr = *reinterpret_cast<std::uint64_t*>(writer + 8);
                extra_values[6] = arr;
                if (IsUserMemory(arr)) {
                    const std::uint64_t data = *reinterpret_cast<std::uint64_t*>(arr);
                    extra_values[7] = data;
                    extra_values[8] = *reinterpret_cast<std::uint64_t*>(arr + 8);
                    if (IsUserMemory(data)) {
                        const std::uint32_t copy_bytes = (std::min)(16U, static_cast<std::uint32_t>(kPayloadCapacity));
                        std::memcpy(payload.data(), reinterpret_cast<const void*>(data), copy_bytes);
                        payload_size = copy_bytes;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(10, args, payload.data(), payload_size, extra.data(), sizeof(extra_values));
    }
    if (capturing) EndCapture(lease);
    return result;
}

std::uint64_t __fastcall DetourBunchProcess(std::uintptr_t a1, std::uintptr_t* a2, unsigned int a3,
                                            std::uint8_t* a4, std::uint8_t* a5) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, reinterpret_cast<std::uint64_t>(a2), a3,
            reinterpret_cast<std::uint64_t>(a4), reinterpret_cast<std::uint64_t>(a5), 0, 0, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::uint32_t payload_size = 0;
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = a2[20];
            extra_values[1] = a2[21];
            extra_values[2] = a2[18];
            extra_values[3] = *reinterpret_cast<std::uint32_t*>(a1 + 5080);
            extra_values[4] = *reinterpret_cast<std::uint32_t*>(a1 + 5088);
            const std::uint64_t buffer = a2[18];
            if (IsUserMemory(buffer)) {
                const std::uint32_t copy_bytes = (std::min)(64U, static_cast<std::uint32_t>(kPayloadCapacity));
                std::memcpy(payload.data(), reinterpret_cast<const void*>(buffer), copy_bytes);
                payload_size = copy_bytes;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(11, args, payload.data(), payload_size, extra.data(), sizeof(extra_values));
    }
    const std::uint64_t result = g_original_bunch_process != nullptr
        ? g_original_bunch_process(a1, a2, a3, a4, a5) : 0;
    if (capturing) EndCapture(lease);
    return result;
}
void CaptureStack(std::array<std::uint64_t, 12>& frames) noexcept {
    void* raw[12]{};
    const USHORT captured = RtlCaptureStackBackTrace(0, 12, raw, nullptr);
    for (std::uint32_t i = 0; i < 12; ++i) {
        frames[i] = i < captured ? reinterpret_cast<std::uint64_t>(raw[i]) : 0;
    }
}

// UActorChannel vtable slot 91: (channel, FInBunch*)
std::uint64_t __fastcall DetourChannelRecv(std::uintptr_t a1, std::uintptr_t* a2) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, reinterpret_cast<std::uint64_t>(a2), 0, 0, 0, 0, 0, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::uint32_t payload_size = 0;
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = *reinterpret_cast<std::uint32_t*>(a1 + 52);
            extra_values[1] = *reinterpret_cast<std::uint64_t*>(a1 + 88);
            extra_values[2] = *reinterpret_cast<std::uint64_t*>(a1 + 96);
            extra_values[3] = *reinterpret_cast<std::uint64_t*>(a1 + 104);
            extra_values[4] = *reinterpret_cast<std::uint64_t*>(a1 + 160);
            extra_values[5] = *reinterpret_cast<std::uint64_t*>(a1 + 168);
            extra_values[6] = *reinterpret_cast<std::uint64_t*>(a1 + 176);
            std::array<std::uint64_t, 12> frames{};
            CaptureStack(frames);
            for (std::uint32_t i = 0; i < 12; ++i) extra_values[12 + i] = frames[i];
            if (IsUserMemory(reinterpret_cast<std::uint64_t>(a2))) {
                const std::uint32_t copy_bytes = (std::min)(256U, static_cast<std::uint32_t>(kPayloadCapacity));
                std::memcpy(payload.data(), reinterpret_cast<const void*>(a2), copy_bytes);
                payload_size = copy_bytes;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(12, args, payload.data(), payload_size, extra.data(), sizeof(extra_values));
    }
    const std::uint64_t result = g_original_channel_recv != nullptr
        ? g_original_channel_recv(a1, a2) : 0;
    if (capturing) EndCapture(lease);
    return result;
}

// UChannel::SendBunch: (channel, outResult, FOutBunch*, merge)
std::uintptr_t __fastcall DetourSendBunch(std::uintptr_t a1, std::uintptr_t* a2, std::uintptr_t a3,
                                          unsigned char a4) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, reinterpret_cast<std::uint64_t>(a2), a3, a4, 0, 0, 0, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::uint32_t payload_size = 0;
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = *reinterpret_cast<std::uint32_t*>(a1 + 52);
            extra_values[1] = *reinterpret_cast<std::uint64_t*>(a1 + 104);
            extra_values[2] = *reinterpret_cast<std::uint32_t*>(a3 + 224);
            extra_values[3] = *reinterpret_cast<std::uint32_t*>(a3 + 228);
            extra_values[4] = *reinterpret_cast<std::uint32_t*>(a3 + 236);
            extra_values[5] = *reinterpret_cast<std::uint32_t*>(a3 + 240);
            extra_values[6] = *reinterpret_cast<std::uint64_t*>(a3 + 244);
            extra_values[7] = *reinterpret_cast<std::uint32_t*>(a3 + 160);
            extra_values[8] = *reinterpret_cast<std::uint64_t*>(a3 + 144);
            extra_values[9] = *reinterpret_cast<std::uint64_t*>(a3 + 216);
            std::array<std::uint64_t, 12> frames{};
            CaptureStack(frames);
            for (std::uint32_t i = 0; i < 12; ++i) extra_values[12 + i] = frames[i];
            const std::uint64_t buffer = extra_values[8];
            if (IsUserMemory(buffer)) {
                const std::uint32_t bits = static_cast<std::uint32_t>(extra_values[7]);
                std::uint32_t copy_bytes = (bits + 7U) / 8U;
                copy_bytes = (std::min)(copy_bytes, static_cast<std::uint32_t>(kPayloadCapacity));
                std::memcpy(payload.data(), reinterpret_cast<const void*>(buffer), copy_bytes);
                payload_size = copy_bytes;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(13, args, payload.data(), payload_size, extra.data(), sizeof(extra_values));
    }
    const std::uintptr_t result = g_original_send_bunch != nullptr
        ? g_original_send_bunch(a1, a2, a3, a4) : 0;
    if (capturing) EndCapture(lease);
    return result;
}

// FBitWriter::SerializeBits(void* Data, int64 NumBits) @ 0x14162E3A0.
// Records (retaddr, writer, bitpos, value) for every small scalar bit write.
// This exposes the exact write sequence of the move serializer (h/6bit, comps, five/5bit, f32 TS...).
std::uint64_t __fastcall DetourSerializeBits(std::uintptr_t a1, void* a2, std::int64_t a3) {
    const std::uint64_t numbits = a3 > 0 ? static_cast<std::uint64_t>(a3) : 0;
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        if (numbits <= 64) {
            std::array<std::uint64_t, 8> args{a1, reinterpret_cast<std::uint64_t>(a2),
                a3 > 0 ? static_cast<std::uint64_t>(a3) : 0,
                reinterpret_cast<std::uint64_t>(_ReturnAddress()), 0, 0, 0, 0};
            std::array<std::uint8_t, kPayloadCapacity> payload{};
            std::uint32_t payload_size = 0;
            std::array<std::uint8_t, kExtraCapacity> extra{};
            std::uint64_t extra_values[24]{};
            __try {
                extra_values[0] = reinterpret_cast<std::uint64_t>(_ReturnAddress());
                extra_values[1] = a1;
                extra_values[2] = *reinterpret_cast<std::uint64_t*>(a1 + 160);
                extra_values[3] = *reinterpret_cast<std::uint64_t*>(a1 + 168);
                extra_values[4] = *reinterpret_cast<std::uint64_t*>(a1 + 144);
                if (IsUserMemory(reinterpret_cast<std::uint64_t>(a2)) && numbits > 0) {
                    const std::uint32_t copy_bytes = (std::min)(
                        static_cast<std::uint32_t>((numbits + 7U) / 8U),
                        static_cast<std::uint32_t>(kPayloadCapacity));
                    std::memcpy(payload.data(), a2, copy_bytes);
                    payload_size = copy_bytes;
                }
                std::array<std::uint64_t, 12> frames{};
                CaptureStack(frames);
                for (std::uint32_t i = 0; i < 12; ++i) extra_values[12 + i] = frames[i];
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                payload_size = 0;
            }
            std::memcpy(extra.data(), extra_values, sizeof(extra_values));
            Emit(17, args, payload.data(), payload_size, extra.data(), sizeof(extra_values));
        }
    }
    if (g_original_serialize_bits != nullptr) g_original_serialize_bits(a1, a2, a3);
    if (capturing) EndCapture(lease);
    return numbits;
}

// FBitWriter::SerializeInt(uint32* Value, uint32 Max) @ 0x14162E740.
// Records (value, max, bitpos, buffer, retaddr, stack) for every integer bit write.
// Completes hook17 by exposing the caller chain for h(6bit)/five(5bit) scalar writes.
std::uint64_t __fastcall DetourSerializeInt(std::uintptr_t a1, std::uint32_t* a2, std::uint32_t a3) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::uint32_t value = 0;
        const std::uint64_t value_ptr = reinterpret_cast<std::uint64_t>(a2);
        __try {
            if (IsUserMemory(value_ptr)) value = *a2;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            value = 0;
        }
        std::array<std::uint64_t, 8> args{a1, value, a3,
            reinterpret_cast<std::uint64_t>(_ReturnAddress()), value_ptr, 0, 0, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = reinterpret_cast<std::uint64_t>(_ReturnAddress());
            extra_values[1] = a1;
            extra_values[2] = *reinterpret_cast<std::uint64_t*>(a1 + 160);
            extra_values[3] = *reinterpret_cast<std::uint64_t*>(a1 + 168);
            extra_values[4] = *reinterpret_cast<std::uint64_t*>(a1 + 144);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        std::array<std::uint64_t, 12> frames{};
        CaptureStack(frames);
        for (std::uint32_t i = 0; i < 12; ++i) extra_values[12 + i] = frames[i];
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(18, args, payload.data(), 0, extra.data(), sizeof(extra_values));
    }
    const std::uint64_t result = g_original_serialize_int != nullptr
        ? g_original_serialize_int(a1, a2, a3) : 0;
    if (capturing) EndCapture(lease);
    return result;
}

// UChannel::ProcessRemoteFunctionForChannelPrivate @ 0x14450F9B0 (RPC params entry, 13 args).
// Type id 21. Cheap 0.5ms throttle protects against pathological RPC bursts.
// The 9th argument (a9, [rsp+0x40]) is the params buffer; a7 is a UObject whose
// FName at +24 is compared against ServerUpdateCamera/ClientAckGoodMove/ServerMove.
std::atomic<std::uint64_t> g_last_process_rpc_qpc{0};

void __fastcall DetourProcessRPC(
    std::uintptr_t a1, std::uintptr_t a2, std::uintptr_t a3, std::uintptr_t a4,
    std::uintptr_t a5, std::uintptr_t a6, std::uintptr_t a7, std::uintptr_t a8,
    std::uintptr_t a9, std::uintptr_t a10, std::uintptr_t a11, std::uint64_t a12,
    std::uintptr_t a13) {
    const std::uint64_t now_qpc = QueryPerformanceCounterValue();
    const std::uint64_t last_qpc = g_last_process_rpc_qpc.load(std::memory_order_relaxed);
    bool emit = false;
    if (now_qpc - last_qpc >= 5000) {
        g_last_process_rpc_qpc.store(now_qpc, std::memory_order_relaxed);
        emit = true;
    }
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = emit && BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, a2, a3, a4, a5, a6, a7, a8};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        std::uint32_t payload_size = 0;
        __try {
            extra_values[0] = a9;
            extra_values[1] = a10;
            extra_values[2] = a11;
            extra_values[3] = a12;
            extra_values[4] = a13;
            extra_values[5] = IsUserMemory(a7 + 24) ? *reinterpret_cast<std::uint64_t*>(a7 + 24) : 0;
            extra_values[6] = IsUserMemory(a2 + 24) ? *reinterpret_cast<std::uint64_t*>(a2 + 24) : 0;
            extra_values[7] = IsUserMemory(a2 + 56) ? *reinterpret_cast<std::uint64_t*>(a2 + 56) : 0;
            extra_values[8] = IsUserMemory(a2 + 52) ? *reinterpret_cast<std::uint64_t*>(a2 + 52) : 0;
            extra_values[9] = IsUserMemory(a2 + 104) ? *reinterpret_cast<std::uint64_t*>(a2 + 104) : 0;
            // v3: dump both candidate parameter slots (a8 = Params buffer, a9 = stack
            // fallback slot) so raw MsgType/WrapperArray memory can be correlated with
            // the wire payload without changing the hook surface.
            if (IsUserMemory(a8)) {
                std::memcpy(payload.data(), reinterpret_cast<const void*>(a8), 256);
                payload_size = 256;
            }
            if (IsUserMemory(a9)) {
                std::memcpy(payload.data() + 256, reinterpret_cast<const void*>(a9), 256);
                payload_size = 512;
            }
            if (IsUserMemory(a4)) {
                for (std::uint32_t i = 0; i < 8; ++i) {
                    extra_values[12 + i] = *reinterpret_cast<const std::uint64_t*>(a4 + 8U * i);
                }
            }
            // v4 (delta): chase FParameterWrapperArray heap elements from the two params
            // candidates. Params layout for server RPCs: u32 MsgType@0; pad4;
            // FParameterWrapperArray@8 = { TArray<FParameterWrapper>{ptr@+0,num@+8,max@+12};
            // int32 ReadParameterIndex@+16 }. Copy num*0x20 bytes (capped at 256) so the
            // emit-time snapshot includes the wrapper element memory for 577/647 decoding.
            {
                const std::uintptr_t chase_a8 = a8;
                if (IsUserMemory(chase_a8)) {
                    const std::uint64_t data_ptr = *reinterpret_cast<const std::uint64_t*>(chase_a8 + 8);
                    const std::uint32_t num = *reinterpret_cast<const std::uint32_t*>(chase_a8 + 16);
                    extra_values[20] = data_ptr;
                    extra_values[21] = num;
                    extra_values[22] = static_cast<std::uint64_t>(*reinterpret_cast<const std::uint32_t*>(chase_a8));
                    if (IsUserMemory(data_ptr) && num > 0 && num <= 64) {
                        const std::uint32_t copy_bytes = (std::min)(num * 0x20U, 256U);
                        std::memcpy(payload.data() + 512, reinterpret_cast<const void*>(data_ptr), copy_bytes);
                        payload_size = (std::max)(payload_size, 512U + copy_bytes);
                    }
                }
                const std::uintptr_t chase_a9 = a9;
                if (IsUserMemory(chase_a9)) {
                    const std::uint64_t data_ptr = *reinterpret_cast<const std::uint64_t*>(chase_a9 + 8);
                    const std::uint32_t num = *reinterpret_cast<const std::uint32_t*>(chase_a9 + 16);
                    extra_values[23] = data_ptr;
                    if (IsUserMemory(data_ptr) && num > 0 && num <= 64) {
                        const std::uint32_t copy_bytes = (std::min)(num * 0x20U, 256U);
                        std::memcpy(payload.data() + 1024, reinterpret_cast<const void*>(data_ptr), copy_bytes);
                        payload_size = (std::max)(payload_size, 1024U + copy_bytes);
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(21, args, payload.data(), payload_size, extra.data(), sizeof(extra_values));
        EndCapture(lease);
    }
    if (g_original_process_rpc != nullptr) {
        g_original_process_rpc(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
    }
}

AnomalyStatusV1 ANOMALY_CALL Load(const AnomalyHostApiV1* host, void** plugin_context) {
    if (host == nullptr || plugin_context == nullptr) {
        return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "host is invalid");
    }
    auto* const context = new (std::nothrow) Context();
    if (context == nullptr) return Status(ANOMALY_STATUS_V1_FAILED, "context alloc failed");
    context->storage = Query<AnomalyStorageServiceV1>(host, ANOMALY_STORAGE_SERVICE_V1_ID);
    context->scheduler = Query<AnomalySchedulerServiceV1>(host, ANOMALY_SCHEDULER_SERVICE_V1_ID);
    context->hook = Query<AnomalyHookServiceV1>(host, ANOMALY_HOOK_SERVICE_V1_ID);
    g_live_context.store(context, std::memory_order_release);
    if (context->storage == nullptr || context->scheduler == nullptr || context->hook == nullptr) {
        *plugin_context = context;
        return Status(ANOMALY_STATUS_V1_UNAVAILABLE, "required service unavailable");
    }
    BeaconQ("load", "pid store sched hook", (std::uint64_t)GetCurrentProcessId());
    *plugin_context = context;
    return anomaly::sdk::Ok();
}


// UChannel::WriteFieldHeaderAndPayload: (channel, bunch, classcache, fieldcache, exportgroup, paramswriter, bInternalAck)
std::uintptr_t __fastcall DetourFieldHeader(std::uintptr_t a1, std::uint32_t* a2, std::uint32_t* a3,
                                            std::uintptr_t a4, std::uintptr_t a5, std::uintptr_t a6,
                                            unsigned char a7) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, reinterpret_cast<std::uint64_t>(a2), reinterpret_cast<std::uint64_t>(a3),
                                          a4, a5, a6, a7, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::uint32_t payload_size = 0;
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = *reinterpret_cast<std::uint32_t*>(a1 + 52);
            const std::uint64_t conn = *reinterpret_cast<std::uint64_t*>(a1 + 40);
            extra_values[1] = conn;
            if (IsUserMemory(conn)) {
                extra_values[2] = *reinterpret_cast<std::uint32_t*>(conn + 164);
            }
            if (IsUserMemory(a4)) {
                extra_values[3] = *reinterpret_cast<std::uint32_t*>(a4 + 8);
                extra_values[9] = *reinterpret_cast<std::uint64_t*>(a4);
                extra_values[8] = *reinterpret_cast<std::uint64_t*>(a4 + 12);
            }
            if (IsUserMemory(reinterpret_cast<std::uint64_t>(a3))) {
                extra_values[4] = *reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::uint64_t>(a3) + 40)
                    + *reinterpret_cast<std::uint32_t*>(a3) + 1;
            }
            extra_values[10] = 0;
            if (IsUserMemory(a5)) {
                extra_values[10] = *reinterpret_cast<std::uint32_t*>(a5 + 32);
            }
            if (IsUserMemory(a6)) {
                extra_values[5] = *reinterpret_cast<std::uint32_t*>(a6 + 160);
                extra_values[6] = *reinterpret_cast<std::uint64_t*>(a6 + 144);
            }
            if (IsUserMemory(reinterpret_cast<std::uint64_t>(a2))) {
                extra_values[7] = *reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::uint64_t>(a2) + 160);
                extra_values[11] = *reinterpret_cast<std::uint64_t*>(reinterpret_cast<std::uint64_t>(a2) + 144);
            }
            std::array<std::uint64_t, 12> frames{};
            CaptureStack(frames);
            for (std::uint32_t i = 0; i < 12; ++i) extra_values[12 + i] = frames[i];
            const std::uint64_t pbuf = extra_values[6];
            if (IsUserMemory(pbuf)) {
                const std::uint32_t bits = static_cast<std::uint32_t>(extra_values[5]);
                std::uint32_t copy_bytes = (bits + 7U) / 8U;
                copy_bytes = (std::min)(copy_bytes, static_cast<std::uint32_t>(kPayloadCapacity));
                std::memcpy(payload.data(), reinterpret_cast<const void*>(pbuf), copy_bytes);
                payload_size = copy_bytes;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            payload_size = 0;
        }
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(14, args, payload.data(), payload_size, extra.data(), sizeof(extra_values));
    }
    const std::uintptr_t result = g_original_field_header != nullptr
        ? g_original_field_header(a1, a2, a3, a4, a5, a6, a7) : 0;
    if (capturing) EndCapture(lease);
    return result;
}


// Filter: only record bit/int writes whose call chain passes through WriteFieldHeaderAndPayload(0x1441E9040) or its special-path helper(0x1441E8ED0)
bool InFieldHeaderStack(const std::array<std::uint64_t, 12>& frames) noexcept {
    for (std::uint32_t i = 1; i < 8 && frames[i] != 0; ++i) {
        const std::uint64_t f = frames[i];
        if ((f >= 0x1441E8ED0 && f < 0x1441E8ED0 + 0x16D) ||
            (f >= 0x1441E9040 && f < 0x1441E9040 + 0xFC)) {
            return true;
        }
    }
    return false;
}

std::uint64_t __fastcall DetourWriteInt(std::uintptr_t a1, int a2, unsigned int a3) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, static_cast<std::uint64_t>(static_cast<std::uint32_t>(a2)),
                                          a3, reinterpret_cast<std::uint64_t>(_ReturnAddress()), 0, 0, 0, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = reinterpret_cast<std::uint64_t>(_ReturnAddress());
            extra_values[1] = *reinterpret_cast<std::uint64_t*>(a1 + 160);
            extra_values[2] = *reinterpret_cast<std::uint64_t*>(a1 + 144);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        std::array<std::uint64_t, 12> frames{};
        CaptureStack(frames);
        for (std::uint32_t i = 0; i < 12; ++i) extra_values[12 + i] = frames[i];
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(19, args, payload.data(), 0, extra.data(), sizeof(extra_values));
    }
    const std::uint64_t result = g_original_write_int != nullptr
        ? g_original_write_int(a1, a2, a3) : 0;
    if (capturing) EndCapture(lease);
    return result;
}

std::uint64_t __fastcall DetourWriteBit(std::uintptr_t a1, unsigned char a2) {
    AnomalyGenerationHandleV1 lease{};
    const bool capturing = BeginCapture(lease);
    if (capturing) {
        std::array<std::uint64_t, 8> args{a1, a2, 0, reinterpret_cast<std::uint64_t>(_ReturnAddress()), 0, 0, 0, 0};
        std::array<std::uint8_t, kPayloadCapacity> payload{};
        std::array<std::uint8_t, kExtraCapacity> extra{};
        std::uint64_t extra_values[24]{};
        __try {
            extra_values[0] = reinterpret_cast<std::uint64_t>(_ReturnAddress());
            extra_values[1] = *reinterpret_cast<std::uint64_t*>(a1 + 160);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        std::array<std::uint64_t, 12> frames{};
        CaptureStack(frames);
        for (std::uint32_t i = 0; i < 12; ++i) extra_values[12 + i] = frames[i];
        std::memcpy(extra.data(), extra_values, sizeof(extra_values));
        Emit(20, args, payload.data(), 0, extra.data(), sizeof(extra_values));
    }
    const std::uint64_t result = g_original_write_bit != nullptr
        ? g_original_write_bit(a1, a2) : 0;
    if (capturing) EndCapture(lease);
    return result;
}
// Hook installation is deferred off the plugin activation thread. Installing
// MinHook detours synchronously from a UI-triggered enable path can deadlock
// (activation thread waits on the game dispatcher while the menu thread waits
// on activation). Running the same work from a scheduled callback returns the
// activation call immediately and leaves no circular wait behind.
constexpr std::uint32_t kHookInstallDelayMilliseconds = 2500;

void ANOMALY_CALL InstallHooksTask(void* user, const AnomalyGenerationHandleV1 task) {
    auto* const context = static_cast<Context*>(user);
    if (context == nullptr) return;
    // Hold flush_mutex across the whole install so Stop() can only interleave
    // before or after this task, never in the middle of hook creation.
    std::scoped_lock lock(context->flush_mutex);
    if (context->install_task.id == task.id) context->install_task = {};
    if (g_context.load(std::memory_order_acquire) != context) return;
    if (context->stop_started.load(std::memory_order_acquire)) return;
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    if (base == 0) {
        context->capture_open.store(false, std::memory_order_release);
        Beacon("install", "base module unavailable");
        return;
    }
    const std::uintptr_t targets[kHookCount] = {
        base + kRvaLowLevelSendInner,
        base + kRvaWriteHeader,
        base + kRvaBunchProcess,
        base + kRvaSendBunch,
        base + kRvaFieldHeader,
        base + kRvaWriteInt, base + kRvaWriteBit,
        base + kRvaSerializeBits, base + kRvaSerializeInt,
        base + kRvaProcessRPC};
    void* detours[kHookCount] = {
        reinterpret_cast<void*>(&DetourLowLevelSend),
        reinterpret_cast<void*>(&DetourWriteHeader),
        reinterpret_cast<void*>(&DetourBunchProcess),
        reinterpret_cast<void*>(&DetourSendBunch),
        reinterpret_cast<void*>(&DetourFieldHeader),
        reinterpret_cast<void*>(&DetourWriteInt),
        reinterpret_cast<void*>(&DetourWriteBit),
        reinterpret_cast<void*>(&DetourSerializeBits),
        reinterpret_cast<void*>(&DetourSerializeInt),
        reinterpret_cast<void*>(&DetourProcessRPC)};
    std::uintptr_t originals[kHookCount]{};
    std::size_t created = 0;
    bool install_failed = false;
    for (std::size_t i = 0; i < kHookCount; ++i) {
        {
            char line[512]{};
            _snprintf_s(line, sizeof(line), _TRUNCATE, "install hook %llu of %d target=%llx",
                        (unsigned long long)(i + 1), (int)kHookCount,
                        (unsigned long long)targets[i]);
            Beacon("install", line);
        }
        if (context->stop_started.load(std::memory_order_acquire)) break;
        AnomalyHookRequestV1 request{};
        request.struct_size = sizeof(request);
        request.kind = ANOMALY_HOOK_V1_FUNCTION;
        request.target = targets[i];
        request.detour = detours[i];
        request.label = anomaly::sdk::StringView("netproto-pipeline-trace");
        if (context->hook->create(
                context->hook->user, &request, &originals[i], &context->hook_handles[i]).code !=
                ANOMALY_STATUS_V1_OK ||
            originals[i] == 0 || context->hook_handles[i].id == 0) {
            char line[512]{};
            _snprintf_s(line, sizeof(line), _TRUNCATE, "hook %llu creation failed target=%llx",
                        (unsigned long long)i, (unsigned long long)targets[i]);
            Beacon("installfail", line);
            install_failed = true;
            break;
        }
        context->hook_ids[i].store(context->hook_handles[i].id, std::memory_order_release);
        context->hook_generations[i].store(context->hook_handles[i].generation, std::memory_order_release);
        ++created;
    }
    if (install_failed || context->stop_started.load(std::memory_order_acquire)) {
        for (std::size_t j = 0; j < created; ++j) {
            static_cast<void>(context->hook->release(context->hook->user, context->hook_handles[j]));
            context->hook_handles[j] = {};
        }
        context->capture_open.store(false, std::memory_order_release);
        Beacon("startfail", "netproto hooks did not fully install");
        return;
    }
    {
        char line[512]{};
        _snprintf_s(line, sizeof(line), _TRUNCATE,
                    "capture-open hooks=%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld cap0=%02x cap3=%02x",
                    (long long)context->hook_ids[0].load(), (long long)context->hook_ids[1].load(),
                    (long long)context->hook_ids[2].load(), (long long)context->hook_ids[3].load(),
                    (long long)context->hook_ids[4].load(), (long long)context->hook_ids[5].load(),
                    (long long)context->hook_ids[6].load(), (long long)context->hook_ids[7].load(),
                    (long long)context->hook_ids[8].load(), (long long)context->hook_ids[9].load(),
                    (unsigned)context->capture_id[0], (unsigned)context->capture_id[3]);
        Beacon("start", line);
    }
    g_original_low_level_send = reinterpret_cast<LowLevelSendFn>(originals[0]);
    g_original_write_header = reinterpret_cast<WriteHeaderFn>(originals[1]);
    g_original_bunch_process = reinterpret_cast<BunchProcessFn>(originals[2]);
    g_original_send_bunch = reinterpret_cast<SendBunchFn>(originals[3]);
    g_original_field_header = reinterpret_cast<FieldHeaderFn>(originals[4]);
    g_original_write_int = reinterpret_cast<WriteIntFn>(originals[5]);
    g_original_write_bit = reinterpret_cast<WriteBitFn>(originals[6]);
    g_original_serialize_bits = reinterpret_cast<SerializeBitsFn>(originals[7]);
    g_original_serialize_int = reinterpret_cast<SerializeIntFn>(originals[8]);
    g_original_process_rpc = reinterpret_cast<ProcessRPCFn>(originals[9]);
    context->qpc_frequency = QueryPerformanceFrequencyValue();
    const std::uint64_t qpc_before_clock = QueryPerformanceCounterValue();
    context->started_utc_unix_milliseconds = QueryUnixTimeMilliseconds();
    const std::uint64_t qpc_after_clock = QueryPerformanceCounterValue();
    context->started_qpc = qpc_before_clock + (qpc_after_clock - qpc_before_clock) / 2U;
}

AnomalyStatusV1 ANOMALY_CALL Start(void* plugin_context) {
    auto* const context = static_cast<Context*>(plugin_context);
    if (context == nullptr || context->hook == nullptr || context->hook->create == nullptr ||
        g_context.load(std::memory_order_acquire) != nullptr) {
        return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "netproto trace context is invalid");
    }
    if (BCryptGenRandom(nullptr, context->capture_id.data(),
                        static_cast<ULONG>(context->capture_id.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return Status(ANOMALY_STATUS_V1_FAILED, "capture id generation failed");
    }
    g_context.store(context, std::memory_order_release);
    g_hook_service.store(context->hook, std::memory_order_release);
    ScheduleFlush(context, kFlushIntervalMilliseconds);
    if (context->scheduler == nullptr || context->scheduler->schedule == nullptr) {
        context->capture_open.store(false, std::memory_order_release);
        Beacon("startfail", "scheduler unavailable; hooks not installed");
        return Status(ANOMALY_STATUS_V1_FAILED, "scheduler unavailable");
    }
    AnomalyGenerationHandleV1 task{};
    if (context->scheduler->schedule(
            context->scheduler->user, kHookInstallDelayMilliseconds, InstallHooksTask, context, &task).code !=
        ANOMALY_STATUS_V1_OK) {
        context->capture_open.store(false, std::memory_order_release);
        Beacon("startfail", "hook install scheduling failed");
        return Status(ANOMALY_STATUS_V1_FAILED, "hook install scheduling failed");
    }
    {
        std::scoped_lock lock(context->flush_mutex);
        context->install_task = task;
    }
    Beacon("start", "deferred hook install scheduled delay=2500");
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Stop(void* plugin_context, std::uint32_t) {
    if (plugin_context == nullptr) return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "context is null");
    if (g_live_context.load(std::memory_order_acquire) != plugin_context) {
        return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "context is stale or foreign");
    }
    auto* const context = static_cast<Context*>(plugin_context);
    if (context->stop_started.exchange(true, std::memory_order_acq_rel)) return anomaly::sdk::Ok();
    context->capture_open.store(false, std::memory_order_release);
    AnomalyGenerationHandleV1 pending_flush{};
    AnomalyGenerationHandleV1 pending_install{};
    bool hook_quiesced = true;
    {
        std::scoped_lock lock(context->flush_mutex);
        if (context->flush_task.id != 0) {
            pending_flush = context->flush_task;
            context->flush_task = {};
        }
        if (context->install_task.id != 0) {
            pending_install = context->install_task;
            context->install_task = {};
        }
        if (context->hook != nullptr) {
            for (std::size_t i = 0; i < kHookCount; ++i) {
                if (context->hook_handles[i].id == 0) continue;
                const AnomalyStatusV1 released =
                    context->hook->release(context->hook->user, context->hook_handles[i]);
                if (released.code != ANOMALY_STATUS_V1_OK &&
                    released.code != ANOMALY_STATUS_V1_NOT_FOUND) {
                    hook_quiesced = false;
                }
                context->hook_handles[i] = {};
            }
        }
    }
    if (pending_flush.id != 0 && context->scheduler != nullptr &&
        context->scheduler->cancel != nullptr) {
        static_cast<void>(context->scheduler->cancel(context->scheduler->user, pending_flush));
    }
    if (pending_install.id != 0 && context->scheduler != nullptr &&
        context->scheduler->cancel != nullptr) {
        static_cast<void>(context->scheduler->cancel(context->scheduler->user, pending_install));
    }
    g_context.store(nullptr, std::memory_order_release);
    g_hook_service.store(nullptr, std::memory_order_release);
    const bool persisted = Persist(*context, true, hook_quiesced);
    if (!hook_quiesced) {
        return Status(ANOMALY_STATUS_V1_FAILED, "netproto trace hooks did not quiesce");
    }
    return persisted ? anomaly::sdk::Ok()
                     : Status(ANOMALY_STATUS_V1_FAILED, "netproto trace final persistence failed");
}

void ANOMALY_CALL Unload(void* plugin_context) {
    if (plugin_context == nullptr) return;
    if (Stop(plugin_context, 0).code == ANOMALY_STATUS_V1_OK) {
        g_live_context.store(nullptr, std::memory_order_release);
        delete static_cast<Context*>(plugin_context);
    }
}

} // namespace

ANOMALY_SDK_EXPORT AnomalyStatusV1 ANOMALY_CALL AnomalyPluginEntryV1(
    AnomalyPluginDescriptorV1* descriptor) {
    if (descriptor == nullptr || descriptor->struct_size < sizeof(*descriptor)) {
        return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "descriptor is invalid");
    }
    *descriptor = {
        sizeof(*descriptor), ANOMALY_PLUGIN_API_V1_MAJOR, ANOMALY_PLUGIN_API_V1_MINOR,
        anomaly::sdk::StringView("anomaly.diagnostics.netproto.pipeline"),
        anomaly::sdk::StringView("NetProto pipeline trace"),
        anomaly::sdk::StringView("Anomaly"), anomaly::sdk::StringView("0.1.0"),
        Load, Start, Stop, Unload, nullptr, nullptr};
    return anomaly::sdk::Ok();
}
