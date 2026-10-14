// SentinelCore — управление правилами из панели: чтение, проверка, сохранение, включение,
// удаление, история версий и пробный запуск (на строках логов и на сохранённых событиях).
//
// Правило попадает на диск только после полной проверки: YAML, регулярки, уникальность id,
// ссылки цепочек, сборка движка и встроенные примеры tests (match / no_match).
// После сохранения новые правила сразу применяются (без перезапуска сервера).
// Правка файлов вручную тоже подхватывается (reload_if_changed из главного цикла).
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "detect/engine.hpp"
#include "detect/rule_tests.hpp"
#include "detect/rules.hpp"
#include "store/event_store.hpp"

namespace sentinel {

struct RuleCheck {
    bool ok = false;
    std::string error;                        // главное: что не так
    std::vector<std::string> errors;          // все ошибки проверки
    std::vector<RuleTestFailure> test_failures;
    size_t test_cases = 0;
    std::vector<std::string> rule_ids;        // правила в проверенном тексте
    std::string file;                         // файл, который был/будет изменён
};

struct RuleVersion {
    int64_t ts = 0;
    std::string action;  // original | create | update | enable | disable | delete
    std::string by;
    std::string name;    // имя файла версии (для чтения)
};

struct DryRunLine {
    size_t index = 0;       // номер строки во входных данных (с 0)
    bool parsed = false;
    Event event;
    std::vector<size_t> alerts;  // номера алертов в DryRun::alerts
};

struct DryRun {
    bool ok = false;
    std::string error;
    std::vector<std::string> errors;
    std::vector<std::string> tested_ids;  // правила из текста
    std::vector<std::string> helper_ids;  // правила, на которые ссылаются цепочки (взяты из рабочих)
    std::vector<Alert> alerts;            // для истории — только первые kMaxSample
    std::map<std::string, uint64_t> alerts_by_rule;
    std::vector<DryRunLine> lines;        // только для проверки на строках
    uint64_t events = 0;
    uint64_t distinct_ips = 0;            // разных src_ip в алертах
    int64_t first_ts = 0, last_ts = 0;
    int64_t took_ms = 0;
    bool truncated = false;               // достигнут предел событий
    RuleTestReport tests;
    static constexpr size_t kMaxSample = 50;
};

class RuleManager {
public:
    explicit RuleManager(std::string rules_dir, std::string history_dir);

    // Вызывается после каждой успешной загрузки правил: новый движок для конвейера и полный список.
    using Apply = std::function<void(std::unique_ptr<DetectionEngine>, const std::vector<Rule>&)>;
    void set_apply(Apply fn) { apply_ = std::move(fn); }

    bool reload(std::string& error);  // загрузить каталог и применить (при ошибке — остаются старые правила)
    bool reload_if_changed();         // если файлы изменили вручную

    std::vector<Rule> rules() const;             // все загруженные, включая отключённые
    std::vector<std::string> load_errors() const;  // файлы, которые не загрузились
    std::string rules_dir() const { return dir_; }

    bool source(const std::string& id, std::string& file, std::string& text, std::string& error) const;

    // id пусто — новый файл. Проверка без записи.
    RuleCheck check(const std::string& id, const std::string& text) const;
    RuleCheck save(const std::string& id, const std::string& text, const std::string& by);
    RuleCheck remove(const std::string& id, const std::string& by);
    RuleCheck set_enabled(const std::string& id, bool enabled, const std::string& by);

    std::vector<RuleVersion> history(const std::string& id) const;
    bool version_text(const std::string& id, const std::string& version, std::string& text) const;

    // Пробный запуск правил из text: на строках логов или на событиях из хранилища.
    DryRun try_lines(const std::string& text, const std::vector<std::string>& lines, const std::string& format,
                     int tz_minutes) const;
    DryRun try_history(const std::string& text, const EventStore& store, int64_t from, int64_t to,
                       size_t max_events) const;

    // Имя файла для нового правила по его id.
    static std::string file_name_for(const std::string& id);
    // Включить/выключить правило правкой текста (комментарии и оформление сохраняются).
    static bool edit_enabled(const std::string& text, const std::string& id, bool enabled, std::string& out);

private:
    struct Candidate {
        std::vector<Rule> all;
        std::vector<std::string> errors;
    };
    std::string file_of(const std::string& id) const;  // пусто — нет такого правила
    std::map<std::string, std::string> read_files() const;
    Candidate build(const std::map<std::string, std::string>& files) const;
    RuleCheck check_files(const std::string& file, const std::string* text) const;
    bool write_file(const std::string& file, const std::string& text, std::string& error) const;
    void record(const std::string& file, const std::string& action, const std::string& by, const std::string& text);
    bool prepare_dry(const std::string& text, DryRun& out, DetectionEngine& eng) const;
    int64_t dir_stamp() const;
    bool reload_locked(std::string& error);

    std::string dir_, history_dir_;
    Apply apply_;
    mutable std::mutex mu_;  // одно изменение за раз
    std::vector<Rule> rules_;
    std::vector<std::string> errors_;
    int64_t stamp_ = 0;
};

}  // namespace sentinel
