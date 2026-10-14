// SentinelCore Agent — чтение журнала событий Windows (Security) через системный API wevtapi.
// На Linux/macOS — заглушка.
#pragma once

#include <string>
#include <vector>

namespace sentinel::agent {

class WinEventReader {
public:
    // bookmark — сохранённая позиция (XML от прошлого запуска) или пусто = начать с новых событий.
    WinEventReader(std::string channel, std::string bookmark);
    ~WinEventReader();

    // Прочитать новые события как JSON-объекты (по одному в строке). false — ошибка API.
    bool read(std::vector<std::string>& json_lines, size_t max_events, std::string& error);
    // Позиция, до которой всё прочитано (подтверждается после успешной отправки).
    std::string pending_bookmark() const { return pending_; }
    std::string committed_bookmark() const { return committed_; }
    void commit() { committed_ = pending_; }
    void rewind() { pending_ = committed_; }

    // Разбор XML события в JSON (вынесено отдельно — проверяется тестами на любой ОС).
    static bool xml_to_json(const std::string& xml, std::string& json);

private:
    std::string channel_;
    std::string committed_;
    std::string pending_;
};

}  // namespace sentinel::agent
