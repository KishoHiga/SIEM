// SentinelCore Agent — работа с файлами логов: маски, идентичность файла, чтение хвоста.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace sentinel::agent {

// Раскрыть маску: '*' и '?' допускаются в любой части пути (/var/lib/docker/containers/*/*-json.log).
std::vector<std::string> expand_glob(const std::string& pattern);
bool glob_match(const char* pattern, const char* name);

// Идентичность файла (устройство + inode). Нужна, чтобы заметить ротацию: путь тот же, файл новый.
struct FileId {
    uint64_t dev = 0;
    uint64_t ino = 0;
    bool valid = false;
    bool operator==(const FileId& o) const { return valid && o.valid && dev == o.dev && ino == o.ino; }
    bool operator!=(const FileId& o) const { return !(*this == o); }
};
FileId file_id_of_path(const std::string& path);
bool readable(const std::string& path);

// Читатель хвоста одного файла. Держит файл открытым: после ротации (переименования)
// старый файл дочитывается до конца, ничего не теряется.
class FileTailer {
public:
    FileTailer(std::string path, uint64_t offset);
    ~FileTailer();
    FileTailer(const FileTailer&) = delete;
    FileTailer& operator=(const FileTailer&) = delete;

    bool open();
    bool is_open() const { return f_ != nullptr; }
    const std::string& path() const { return path_; }
    FileId id() const { return id_; }

    // Прочитать целые строки (не больше max_bytes). Возвращает число байт прочитанного.
    // Позиция после этих строк — pending_offset(); подтвердить — commit().
    size_t read_lines(std::vector<std::string>& out, size_t max_bytes);
    uint64_t committed() const { return committed_; }
    uint64_t pending_offset() const { return pos_; }
    void commit(uint64_t pos) { committed_ = pos; }
    void rewind() { pos_ = committed_; }

    // Файл обрезали (copytruncate) — начать сначала.
    bool truncated();
    uint64_t current_size();

private:
    std::string path_;
    std::FILE* f_ = nullptr;
    FileId id_;
    uint64_t committed_ = 0;
    uint64_t pos_ = 0;
};

}  // namespace sentinel::agent
