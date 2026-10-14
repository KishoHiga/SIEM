#include "store/event_store.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>

#include "core/log.hpp"
#include "core/util.hpp"
#include "store/codec.hpp"
#include "store/lz.hpp"

namespace fs = std::filesystem;

namespace sentinel {

namespace {
constexpr char kFileMagic[8] = {'S', 'N', 'T', 'L', 'S', 'E', 'G', '1'};
constexpr size_t kFileHeader = 16;
constexpr uint32_t kBlockMagic = 0x4B4C4253;  // "SBLK"
constexpr size_t kBlockHeader = 128;
constexpr size_t kMinBloomBits = 512;
constexpr size_t kMaxBloomBits = size_t(1) << 20;
constexpr int kBloomHashes = 4;
constexpr size_t kMaxPending = 2'000'000;

uint64_t bloom_hash(std::string_view v) {
    std::string low = to_lower(v);
    return hash64(low, 0x5EEDB10Full);
}

void bloom_set(std::vector<uint8_t>& bloom, uint64_t h) {
    const uint64_t bits = bloom.size() * 8;
    uint64_t h1 = h, h2 = (h >> 32) | 1;
    for (int i = 0; i < kBloomHashes; ++i) {
        uint64_t bit = (h1 + uint64_t(i) * h2) & (bits - 1);
        bloom[bit >> 3] |= uint8_t(1u << (bit & 7));
    }
}

bool bloom_has(const std::vector<uint8_t>& bloom, uint64_t h) {
    if (bloom.empty()) return true;
    const uint64_t bits = bloom.size() * 8;
    uint64_t h1 = h, h2 = (h >> 32) | 1;
    for (int i = 0; i < kBloomHashes; ++i) {
        uint64_t bit = (h1 + uint64_t(i) * h2) & (bits - 1);
        if (!(bloom[bit >> 3] & (1u << (bit & 7)))) return false;
    }
    return true;
}

bool bloom_field(Field f) { return f == Field::SrcIp || f == Field::DstIp || f == Field::User || f == Field::Host; }
}  // namespace

struct EventStore::BlockMeta {
    uint64_t offset = 0;
    uint32_t count = 0;
    uint32_t raw_len = 0;
    uint32_t stored_len = 0;
    uint32_t payload_crc = 0;
    bool compressed = false;
    int64_t min_ts = 0, max_ts = 0;
    uint64_t min_id = 0, max_id = 0;
    uint32_t bloom_len = 0;   // байт фильтра (лежит сразу за заголовком)
    uint32_t bloom_crc = 0;
    std::vector<uint8_t> bloom;

    uint64_t payload_offset() const { return offset + kBlockHeader + bloom_len; }
    uint64_t total_size() const { return kBlockHeader + uint64_t(bloom_len) + stored_len; }

    std::string encode() const {
        std::string h;
        h.reserve(kBlockHeader);
        put_u32(h, kBlockMagic);
        put_u32(h, 0);  // CRC заголовка — заполним ниже
        put_u32(h, count);
        put_u32(h, raw_len);
        put_u32(h, stored_len);
        put_u32(h, payload_crc);
        put_u8(h, compressed ? 1 : 0);
        put_u8(h, 0);
        put_u8(h, 0);
        put_u8(h, 0);
        put_u64(h, uint64_t(min_ts));
        put_u64(h, uint64_t(max_ts));
        put_u64(h, min_id);
        put_u64(h, max_id);
        put_u32(h, bloom_len);
        put_u32(h, bloom_crc);
        h.resize(kBlockHeader, '\0');
        uint32_t crc = crc32(h.data() + 8, kBlockHeader - 8);
        for (int i = 0; i < 4; ++i) h[4 + size_t(i)] = char((crc >> (8 * i)) & 0xFF);
        return h;
    }

    bool decode(const char* p) {
        Reader r(p, kBlockHeader);
        if (r.u32() != kBlockMagic) return false;
        uint32_t crc = r.u32();
        if (crc != crc32(p + 8, kBlockHeader - 8)) return false;
        count = r.u32();
        raw_len = r.u32();
        stored_len = r.u32();
        payload_crc = r.u32();
        compressed = r.u8() != 0;
        r.u8();
        r.u8();
        r.u8();
        min_ts = int64_t(r.u64());
        max_ts = int64_t(r.u64());
        min_id = r.u64();
        max_id = r.u64();
        bloom_len = r.u32();
        bloom_crc = r.u32();
        return r.ok() && bloom_len <= kMaxBloomBits / 8;
    }
};

struct EventStore::Segment {
    std::string path;
    int64_t created = 0;
    uint64_t bytes = 0;
    std::vector<BlockMeta> blocks;
    uint64_t events = 0;
    uint64_t raw_bytes = 0;
};

EventStore::EventStore() = default;
EventStore::~EventStore() { close(); }

static bool parse_segment_name(const std::string& name, int64_t& created, uint64_t& counter) {
    // seg-<15 цифр>-<6 цифр>.sntl
    if (!starts_with(name, "seg-") || !ends_with(name, ".sntl")) return false;
    std::string_view mid = std::string_view(name).substr(4, name.size() - 9);
    size_t dash = mid.find('-');
    if (dash == std::string_view::npos) return false;
    auto c = parse_int(mid.substr(0, dash));
    auto n = parse_uint(mid.substr(dash + 1));
    if (!c || !n) return false;
    created = *c;
    counter = *n;
    return true;
}

bool EventStore::open(const StoreOptions& opt, std::string& error) {
    opt_ = opt;
    if (opt_.block_events == 0) opt_.block_events = 1;
    events_dir_ = opt_.dir + "/events";
    std::error_code ec;
    fs::create_directories(events_dir_, ec);
    if (ec) {
        error = "cannot create " + events_dir_ + ": " + ec.message();
        return false;
    }
    struct Found {
        std::string path;
        int64_t created;
        uint64_t counter;
    };
    std::vector<Found> files;
    for (auto& e : fs::directory_iterator(events_dir_, ec)) {
        if (!e.is_regular_file()) continue;
        int64_t created;
        uint64_t counter;
        std::string name = e.path().filename().string();
        if (parse_segment_name(name, created, counter)) files.push_back({e.path().string(), created, counter});
    }
    std::sort(files.begin(), files.end(), [](const Found& a, const Found& b) {
        return a.created != b.created ? a.created < b.created : a.counter < b.counter;
    });

    uint64_t total = 0;
    for (size_t fi = 0; fi < files.size(); ++fi) {
        auto seg = std::make_shared<Segment>();
        seg->path = files[fi].path;
        seg->created = files[fi].created;
        seg_counter_ = std::max(seg_counter_, files[fi].counter + 1);
        File f;
        if (!f.open(seg->path, "rb")) {
            log::warn("store: cannot open ", seg->path);
            continue;
        }
        uint64_t fsize = f.size();
        char fh[kFileHeader];
        if (fsize < kFileHeader || !f.read(fh, kFileHeader) || std::memcmp(fh, kFileMagic, 8) != 0) {
            log::warn("store: bad segment header, skipping ", seg->path);
            continue;
        }
        uint64_t off = kFileHeader;
        char hb[kBlockHeader];
        while (off + kBlockHeader <= fsize) {
            if (!f.seek(off) || !f.read(hb, kBlockHeader)) break;
            BlockMeta m;
            if (!m.decode(hb)) break;
            m.offset = off;
            if (off + m.total_size() > fsize) break;
            m.bloom.resize(m.bloom_len);
            if (m.bloom_len && (!f.read(m.bloom.data(), m.bloom_len) || crc32(m.bloom.data(), m.bloom_len) != m.bloom_crc))
                break;
            seg->blocks.push_back(m);
            seg->events += m.count;
            seg->raw_bytes += m.raw_len;
            max_id_ = std::max(max_id_, m.max_id);
            off += m.total_size();
        }
        f.close();
        if (off != fsize) {
            // недописанный хвост (сбой питания/процесса) — отрезаем
            log::warn("store: truncating damaged tail of ", seg->path, " at ", off, " (file size ", fsize, ")");
            fs::resize_file(seg->path, off, ec);
        }
        seg->bytes = off;
        total += seg->events;
        segments_.push_back(seg);
    }
    open_ = true;
    // потоки сжатия: на 1–2 ядрах сжимаем прямо в потоке записи
    int threads = opt_.compress_threads;
    if (threads < 0 && std::getenv("SENTINEL_STORE_THREADS"))  // для проверок: задать вручную
        threads = std::clamp(std::atoi(std::getenv("SENTINEL_STORE_THREADS")), 0, 16);
    if (threads < 0) {
        unsigned hw = std::thread::hardware_concurrency();
        threads = hw <= 2 ? 0 : int(std::min<unsigned>(hw / 2, 4));
    }
    pool_stop_ = false;
    for (int i = 0; i < threads; ++i) pool_.emplace_back([this] { worker(); });
    last_flush_ = last_sync_ = last_retention_ = now_ms();
    log::info("store: opened ", segments_.size(), " segments, ", total, " events, max id ", max_id_);
    return true;
}

void EventStore::close() {
    if (!open_) return;
    flush();
    {
        std::lock_guard<std::mutex> lock(mu_);
        pool_stop_ = true;
    }
    work_cv_.notify_all();
    for (auto& t : pool_) t.join();
    pool_.clear();
    if (writer_) {
        writer_->sync();
        writer_->close();
    }
    writer_.reset();
    current_.reset();
    open_ = false;
}

bool EventStore::open_new_segment(int64_t now) {
    if (writer_) {
        writer_->sync();
        writer_->close();
    }
    char name[64];
    std::snprintf(name, sizeof(name), "seg-%015lld-%06llu.sntl", (long long)now, (unsigned long long)seg_counter_++);
    auto seg = std::make_shared<Segment>();
    seg->path = events_dir_ + "/" + name;
    seg->created = now;
    writer_ = std::make_unique<File>();
    if (!writer_->open(seg->path, "wb")) {
        log::error("store: cannot create segment ", seg->path);
        writer_.reset();
        return false;
    }
    char fh[kFileHeader] = {};
    std::memcpy(fh, kFileMagic, 8);
    fh[8] = 1;  // версия
    if (!writer_->write(fh, kFileHeader) || !writer_->flush()) {
        log::error("store: cannot write segment header ", seg->path);
        writer_.reset();
        return false;
    }
    seg->bytes = kFileHeader;
    {
        std::lock_guard<std::mutex> lock(mu_);
        segments_.push_back(seg);
    }
    current_ = seg;
    return true;
}

struct EventStore::Prepared {
    std::vector<Event> events;  // неизменны, пока блок в работе (их читают поиск и поток сжатия)
    BlockMeta meta;
    std::string stored;
    bool ready = false;  // под mu_
};

// Кодирование, bloom-фильтр и сжатие блока. Не трогает общее состояние — можно в любом потоке.
void EventStore::prepare_block(Prepared& p) {
    auto& events = p.events;
    BlockMeta& m = p.meta;
    m.count = uint32_t(events.size());
    m.min_ts = events[0].ts;
    m.max_ts = events[0].ts;
    m.min_id = events[0].id;
    m.max_id = events[0].id;
    std::string raw;
    raw.reserve(events.size() * 300);
    std::vector<uint64_t> keys;
    keys.reserve(events.size() * 2);
    for (auto& e : events) {
        encode_event(e, raw);
        m.min_ts = std::min(m.min_ts, e.ts);
        m.max_ts = std::max(m.max_ts, e.ts);
        m.min_id = std::min(m.min_id, e.id);
        m.max_id = std::max(m.max_id, e.id);
        for (Field f : {Field::SrcIp, Field::DstIp, Field::User, Field::Host})
            if (!e[f].empty()) keys.push_back(bloom_hash(e[f]));
    }
    // Размер фильтра по числу разных значений: ~10 бит на значение -> ~1% ложных срабатываний
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    size_t bits = kMinBloomBits;
    while (bits < keys.size() * 10 && bits < kMaxBloomBits) bits <<= 1;
    m.bloom.assign(bits / 8, 0);
    for (uint64_t h : keys) bloom_set(m.bloom, h);
    m.bloom_len = uint32_t(m.bloom.size());
    m.bloom_crc = crc32(m.bloom.data(), m.bloom.size());
    lz::compress(raw, p.stored);
    m.raw_len = uint32_t(raw.size());
    if (p.stored.size() < raw.size()) {
        m.compressed = true;
    } else {
        p.stored.swap(raw);
        m.compressed = false;
    }
    m.stored_len = uint32_t(p.stored.size());
    m.payload_crc = crc32(p.stored.data(), p.stored.size());
}

void EventStore::worker() {
    while (true) {
        std::shared_ptr<Prepared> p;
        {
            std::unique_lock<std::mutex> lock(mu_);
            work_cv_.wait(lock, [&] { return pool_stop_ || !work_.empty(); });
            if (work_.empty()) return;
            p = std::move(work_.front());
            work_.pop_front();
        }
        prepare_block(*p);
        {
            std::lock_guard<std::mutex> lock(mu_);
            p->ready = true;
        }
        ready_cv_.notify_all();
    }
}

// Отрезать n первых событий из pending_ в новый блок (mu_ захвачен).
void EventStore::cut_block_locked(size_t n) {
    auto p = std::make_shared<Prepared>();
    p->events.assign(std::make_move_iterator(pending_.begin()), std::make_move_iterator(pending_.begin() + long(n)));
    pending_.erase(pending_.begin(), pending_.begin() + long(n));
    inflight_.push_back(p);
    if (!pool_.empty()) {
        work_.push_back(std::move(p));
        work_cv_.notify_one();
    }
}

// Записать готовые блоки по порядку. all — дождаться и записать все.
void EventStore::write_ready(bool all) {
    const size_t max_inflight = pool_.size() * 2 + 2;
    while (true) {
        std::shared_ptr<Prepared> head;
        {
            std::unique_lock<std::mutex> lock(mu_);
            if (inflight_.empty()) return;
            head = inflight_.front();
            if (!head->ready) {
                if (pool_.empty()) {
                    lock.unlock();
                    prepare_block(*head);
                    lock.lock();
                    head->ready = true;
                } else if (all || inflight_.size() > max_inflight) {
                    ready_cv_.wait(lock, [&] { return head->ready; });
                } else {
                    return;
                }
            }
        }
        if (!write_prepared(*head)) {
            write_failed();
            return;
        }
    }
}

bool EventStore::write_prepared(Prepared& p) {
    const int64_t now = now_ms();
    if (!current_ || current_->bytes >= opt_.segment_max_bytes || now - current_->created >= opt_.segment_max_age_ms) {
        open_new_segment(now);
    }
    BlockMeta& m = p.meta;
    bool ok = false;
    if (writer_ && current_) {
        m.offset = current_->bytes;
        std::string header = m.encode();
        ok = writer_->write(header.data(), header.size()) && writer_->write(m.bloom.data(), m.bloom.size()) &&
             writer_->write(p.stored.data(), p.stored.size()) && writer_->flush();
        if (ok && opt_.fsync && now - last_sync_ >= opt_.flush_interval_ms) {
            writer_->sync();
            last_sync_ = now;
        }
    }
    if (!ok) return false;
    std::lock_guard<std::mutex> lock(mu_);
    current_->bytes += m.total_size();
    current_->events += m.count;
    current_->raw_bytes += m.raw_len;
    p.stored.clear();
    p.stored.shrink_to_fit();
    current_->blocks.push_back(std::move(m));
    inflight_.pop_front();
    last_flush_ = now;
    return true;
}

// Ошибка записи (диск полон?): события всех блоков в работе возвращаются в очередь, сегмент закрывается.
void EventStore::write_failed() {
    std::unique_lock<std::mutex> lock(mu_);
    ready_cv_.wait(lock, [&] {  // потоки сжатия ещё читают события — дождаться
        for (auto& p : inflight_)
            if (!p->ready) return false;
        return true;
    });
    std::vector<Event> back;
    size_t n = 0;
    for (auto& p : inflight_) n += p->events.size();
    back.reserve(n + pending_.size());
    for (auto& p : inflight_)
        for (auto& e : p->events) back.push_back(std::move(e));
    inflight_.clear();
    log::error("store: block write failed, will retry (", back.size(), " events kept in memory)");
    for (auto& e : pending_) back.push_back(std::move(e));
    pending_.swap(back);
    if (writer_) writer_->close();
    writer_.reset();
    current_.reset();
    if (pending_.size() > kMaxPending) {
        size_t drop = pending_.size() - kMaxPending;
        log::error("store: dropping ", drop, " oldest events, storage unavailable");
        pending_.erase(pending_.begin(), pending_.begin() + long(drop));
    }
    last_flush_ = now_ms();
}

void EventStore::append(std::vector<Event>& batch) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& e : batch) {
            if (e.id > max_id_) max_id_ = e.id;
            pending_.push_back(std::move(e));
        }
        while (pending_.size() >= opt_.block_events) cut_block_locked(opt_.block_events);
    }
    batch.clear();
    write_ready(false);
}

void EventStore::flush() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!pending_.empty()) cut_block_locked(pending_.size());
    }
    write_ready(true);
    if (writer_ && opt_.fsync) {
        writer_->sync();
        last_sync_ = now_ms();
    }
}

void EventStore::tick(int64_t now) {
    write_ready(false);  // готовые блоки — на диск, не дожидаясь интервала
    bool need = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        need = (!pending_.empty() || !inflight_.empty()) && now - last_flush_ >= opt_.flush_interval_ms;
    }
    if (need) flush();
    if (writer_ && opt_.fsync && now - last_sync_ >= opt_.flush_interval_ms) {
        writer_->sync();
        last_sync_ = now;
    }
    if (current_ && now - current_->created >= opt_.segment_max_age_ms) {
        // закрываем старый сегмент заранее, следующая запись откроет новый
        if (writer_) {
            writer_->sync();
            writer_->close();
        }
        writer_.reset();
        current_.reset();
    }
    if (now - last_retention_ >= 60000) {
        apply_retention(now);
        last_retention_ = now;
    }
}

void EventStore::apply_retention(int64_t now) {
    std::vector<std::string> to_delete;
    {
        std::lock_guard<std::mutex> lock(mu_);
        const int64_t cutoff = now - opt_.retention_ms;
        std::vector<std::shared_ptr<Segment>> keep;
        for (auto& s : segments_) {
            bool old = s->created + opt_.segment_max_age_ms < cutoff;
            if (old && s != current_) to_delete.push_back(s->path);
            else keep.push_back(s);
        }
        segments_.swap(keep);
    }
    for (auto& p : to_delete) {
        std::error_code ec;
        fs::remove(p, ec);
        if (ec) log::warn("store: cannot delete old segment ", p, ": ", ec.message());
        else log::info("store: retention removed ", p);
    }
}

bool EventStore::read_block(const Segment& seg, const BlockMeta& b, std::vector<Event>& out) const {
    File f;
    if (!f.open(seg.path, "rb") || !f.seek(b.payload_offset())) return false;
    std::string stored(b.stored_len, '\0');
    if (!f.read(stored.data(), stored.size())) return false;
    if (crc32(stored.data(), stored.size()) != b.payload_crc) {
        log::error("store: CRC mismatch in ", seg.path, " at ", b.offset);
        std::lock_guard<std::mutex> lock(mu_);
        ++corrupt_blocks_;
        return false;
    }
    std::string raw;
    if (b.compressed) {
        if (!lz::decompress(stored, b.raw_len, raw)) {
            log::error("store: decompression failed in ", seg.path, " at ", b.offset);
            return false;
        }
    } else {
        raw.swap(stored);
    }
    Reader r(raw);
    out.clear();
    out.reserve(b.count);
    for (uint32_t i = 0; i < b.count; ++i) {
        Event e;
        if (!decode_event(r, e)) {
            log::error("store: bad event record in ", seg.path, " at ", b.offset);
            return false;
        }
        out.push_back(std::move(e));
    }
    return true;
}

namespace {
struct Filter {
    std::optional<Field> field;
    std::string name;
    std::string value;
    uint64_t hash = 0;
};
}  // namespace

size_t EventStore::visit(const EventQuery& q, const std::function<bool(Event&&)>& fn) const {
    std::vector<Filter> filters;
    for (auto& kv : q.equals) {
        Filter f;
        f.field = field_from_name(kv.first);
        f.name = kv.first;
        f.value = kv.second;
        f.hash = bloom_hash(kv.second);
        filters.push_back(std::move(f));
    }
    auto matches = [&](const Event& e) {
        if (e.ts < q.from || e.ts > q.to) return false;
        if (q.before_id && e.id >= q.before_id) return false;
        for (auto& f : filters) {
            std::string_view v = f.field ? std::string_view(e[*f.field]) : e.get(f.name);
            if (!iequals(v, f.value)) return false;
        }
        if (!q.text.empty() && ifind(e[Field::Message], q.text) == std::string_view::npos &&
            ifind(e[Field::Raw], q.text) == std::string_view::npos)
            return false;
        return true;
    };

    const size_t limit = q.limit ? q.limit : SIZE_MAX;
    size_t passed = 0;
    std::vector<Event> fresh;  // ещё не на диске — копируем под блокировкой
    std::vector<std::pair<std::shared_ptr<Segment>, BlockMeta>> candidates;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto it = pending_.rbegin(); it != pending_.rend() && fresh.size() < limit; ++it)
            if (matches(*it)) fresh.push_back(*it);
        for (auto bit = inflight_.rbegin(); bit != inflight_.rend() && fresh.size() < limit; ++bit)
            for (auto it = (*bit)->events.rbegin(); it != (*bit)->events.rend() && fresh.size() < limit; ++it)
                if (matches(*it)) fresh.push_back(*it);
        if (fresh.size() < limit) {
            for (auto sit = segments_.rbegin(); sit != segments_.rend(); ++sit) {
                const auto& seg = *sit;
                for (auto bit = seg->blocks.rbegin(); bit != seg->blocks.rend(); ++bit) {
                    const BlockMeta& b = *bit;
                    if (b.max_ts < q.from || b.min_ts > q.to) continue;
                    if (q.before_id && b.min_id >= q.before_id) continue;
                    bool skip = false;
                    for (auto& f : filters)
                        if (f.field && bloom_field(*f.field) && !bloom_has(b.bloom, f.hash)) {
                            skip = true;
                            break;
                        }
                    if (!skip) {
                        BlockMeta lite = b;
                        lite.bloom.clear();  // фильтр для чтения не нужен
                        candidates.emplace_back(seg, std::move(lite));
                    }
                }
            }
        }
    }
    for (auto& e : fresh) {
        ++passed;
        if (!fn(std::move(e)) || passed >= limit) return passed;
    }
    std::vector<Event> block;
    for (auto& c : candidates) {
        if (!read_block(*c.first, c.second, block)) continue;
        for (auto it = block.rbegin(); it != block.rend(); ++it)
            if (matches(*it)) {
                ++passed;
                if (!fn(std::move(*it)) || passed >= limit) return passed;
            }
    }
    return passed;
}

std::vector<Event> EventStore::query(const EventQuery& q) const {
    std::vector<Event> res;
    EventQuery lq = q;
    if (!lq.limit) lq.limit = 100;
    visit(lq, [&](Event&& e) {
        res.push_back(std::move(e));
        return true;
    });
    std::sort(res.begin(), res.end(), [](const Event& a, const Event& b) { return a.id > b.id; });
    return res;
}

size_t EventStore::scan(int64_t from, int64_t to, size_t max, const std::function<bool(const Event&)>& fn) const {
    std::vector<std::pair<std::shared_ptr<Segment>, BlockMeta>> blocks;
    std::vector<Event> tail;  // ещё не записанные на диск
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& seg : segments_)
            for (auto& b : seg->blocks) {
                if (b.max_ts < from || b.min_ts > to) continue;
                BlockMeta lite = b;
                lite.bloom.clear();
                blocks.emplace_back(seg, std::move(lite));
            }
        for (auto& b : inflight_)
            for (auto& e : b->events)
                if (e.ts >= from && e.ts <= to) tail.push_back(e);
        for (auto& e : pending_)
            if (e.ts >= from && e.ts <= to) tail.push_back(e);
    }
    // самые свежие max событий: отбрасываем старые блоки, пока остальных хватает
    size_t total = tail.size();
    for (auto& b : blocks) total += b.second.count;
    size_t skip_blocks = 0;
    while (skip_blocks < blocks.size() && total - blocks[skip_blocks].second.count >= max) {
        total -= blocks[skip_blocks].second.count;
        ++skip_blocks;
    }
    size_t skip_events = total > max ? total - max : 0;  // лишнее в первом оставшемся блоке
    size_t passed = 0;
    std::vector<Event> block;
    auto feed = [&](const Event& e) {
        if (e.ts < from || e.ts > to) return true;
        if (skip_events) {
            --skip_events;
            return true;
        }
        ++passed;
        return fn(e) && passed < max;
    };
    for (size_t i = skip_blocks; i < blocks.size(); ++i) {
        if (!read_block(*blocks[i].first, blocks[i].second, block)) continue;
        for (auto& e : block)
            if (!feed(e)) return passed;
    }
    std::sort(tail.begin(), tail.end(), [](const Event& a, const Event& b) { return a.id < b.id; });
    for (auto& e : tail)
        if (!feed(e)) return passed;
    return passed;
}

std::optional<Event> EventStore::get(uint64_t id) const {
    std::vector<std::pair<std::shared_ptr<Segment>, BlockMeta>> candidates;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& e : pending_)
            if (e.id == id) return e;
        for (auto& b : inflight_)
            for (auto& e : b->events)
                if (e.id == id) return e;
        for (auto& seg : segments_)
            for (auto& b : seg->blocks)
                if (id >= b.min_id && id <= b.max_id) {
                    BlockMeta lite = b;
                    lite.bloom.clear();
                    candidates.emplace_back(seg, std::move(lite));
                }
    }
    std::vector<Event> block;
    for (auto& c : candidates) {
        if (!read_block(*c.first, c.second, block)) continue;
        for (auto& e : block)
            if (e.id == id) return std::move(e);
    }
    return std::nullopt;
}

uint64_t EventStore::max_id() const {
    std::lock_guard<std::mutex> lock(mu_);
    return max_id_;
}

StoreStats EventStore::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    StoreStats s;
    s.segments = segments_.size();
    for (auto& seg : segments_) {
        s.events += seg->events;
        s.blocks += seg->blocks.size();
        s.bytes_on_disk += seg->bytes;
        s.raw_bytes += seg->raw_bytes;
    }
    s.pending = pending_.size();
    for (auto& b : inflight_) s.pending += b->events.size();
    s.events += s.pending;
    s.corrupt_blocks = corrupt_blocks_;
    return s;
}

}  // namespace sentinel
