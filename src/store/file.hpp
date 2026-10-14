// SentinelCore — переносимая работа с файлами (Linux / macOS / Windows).
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace sentinel {

class File {
public:
    File() = default;
    ~File() { close(); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;

    // mode: "rb" чтение, "ab" дозапись, "wb" перезапись, "r+b" чтение+запись
    bool open(const std::string& path, const char* mode);
    bool is_open() const { return f_ != nullptr; }
    void close();

    bool seek(uint64_t offset);
    uint64_t tell();
    uint64_t size();
    bool read(void* buf, size_t n);
    bool write(const void* buf, size_t n);
    bool flush();
    bool sync();  // сбросить на диск (fsync)

private:
    std::FILE* f_ = nullptr;
};

}  // namespace sentinel
