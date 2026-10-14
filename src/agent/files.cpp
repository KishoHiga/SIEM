#include "agent/files.hpp"

#include <algorithm>
#include <filesystem>

#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace sentinel::agent {

namespace {
constexpr size_t kMaxLine = 256 * 1024;  // длиннее — обрезаем

bool has_wildcard(const std::string& s) { return s.find_first_of("*?") != std::string::npos; }

void expand_rec(const fs::path& base, const std::vector<std::string>& parts, size_t i, std::vector<std::string>& out) {
    if (i == parts.size()) {
        std::error_code ec;
        if (fs::is_regular_file(base, ec)) out.push_back(base.string());
        return;
    }
    const std::string& part = parts[i];
    if (!has_wildcard(part)) {
        expand_rec(base / part, parts, i + 1, out);
        return;
    }
    std::error_code ec;
    for (auto& e : fs::directory_iterator(base, fs::directory_options::skip_permission_denied, ec)) {
        std::string name = e.path().filename().string();
        if (glob_match(part.c_str(), name.c_str())) expand_rec(e.path(), parts, i + 1, out);
    }
}
}  // namespace

bool glob_match(const char* p, const char* s) {
    // классический поиск с откатом только для '*' — линейно на практике для коротких имён
    const char* star = nullptr;
    const char* ss = nullptr;
    while (*s) {
        if (*p == '?' || *p == *s) {
            ++p;
            ++s;
        } else if (*p == '*') {
            star = p++;
            ss = s;
        } else if (star) {
            p = star + 1;
            s = ++ss;
        } else {
            return false;
        }
    }
    while (*p == '*') ++p;
    return *p == 0;
}

std::vector<std::string> expand_glob(const std::string& pattern) {
    std::vector<std::string> out;
    if (!has_wildcard(pattern)) {
        std::error_code ec;
        if (fs::is_regular_file(pattern, ec)) out.push_back(pattern);
        return out;
    }
    fs::path p(pattern);
    fs::path root = p.root_path();
    std::vector<std::string> parts;
    for (const auto& part : p.relative_path()) parts.push_back(part.string());
    expand_rec(root.empty() ? fs::path(".") : root, parts, 0, out);
    std::sort(out.begin(), out.end());
    return out;
}

FileId file_id_of_path(const std::string& path) {
    FileId id;
#ifdef _WIN32
    HANDLE h = CreateFileA(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return id;
    BY_HANDLE_FILE_INFORMATION info;
    if (GetFileInformationByHandle(h, &info)) {
        id.dev = info.dwVolumeSerialNumber;
        id.ino = (uint64_t(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
        id.valid = true;
    }
    CloseHandle(h);
#else
    struct stat st;
    if (::stat(path.c_str(), &st) == 0) {
        id.dev = uint64_t(st.st_dev);
        id.ino = uint64_t(st.st_ino);
        id.valid = true;
    }
#endif
    return id;
}

bool readable(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::fclose(f);
    return true;
}

FileTailer::FileTailer(std::string path, uint64_t offset) : path_(std::move(path)), committed_(offset), pos_(offset) {}

FileTailer::~FileTailer() {
    if (f_) std::fclose(f_);
}

bool FileTailer::open() {
    if (f_) return true;
#ifdef _WIN32
    // Открываем с разрешением на удаление/переименование, чтобы не мешать ротации логов.
    HANDLE h = CreateFileA(path_.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    int fd = _open_osfhandle(intptr_t(h), _O_RDONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(h);
        return false;
    }
    f_ = _fdopen(fd, "rb");
    if (!f_) {
        _close(fd);
        return false;
    }
    BY_HANDLE_FILE_INFORMATION info;
    if (GetFileInformationByHandle(h, &info)) {
        id_.dev = info.dwVolumeSerialNumber;
        id_.ino = (uint64_t(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
        id_.valid = true;
    }
#else
    f_ = std::fopen(path_.c_str(), "rb");
    if (!f_) return false;
    struct stat st;
    if (fstat(fileno(f_), &st) == 0) {
        id_.dev = uint64_t(st.st_dev);
        id_.ino = uint64_t(st.st_ino);
        id_.valid = true;
    }
#endif
    return true;
}

uint64_t FileTailer::current_size() {
    if (!f_) return 0;
#ifdef _WIN32
    struct _stat64 st;
    if (_fstat64(_fileno(f_), &st) != 0) return 0;
#else
    struct stat st;
    if (fstat(fileno(f_), &st) != 0) return 0;
#endif
    return uint64_t(st.st_size);
}

bool FileTailer::truncated() { return f_ && current_size() < committed_; }

size_t FileTailer::read_lines(std::vector<std::string>& out, size_t max_bytes) {
    if (!f_ && !open()) return 0;
    if (current_size() < pos_) {  // файл обрезан (copytruncate) — начинаем сначала
        pos_ = committed_ = 0;
    }
#ifdef _WIN32
    if (_fseeki64(f_, int64_t(pos_), SEEK_SET) != 0) return 0;
#else
    if (fseeko(f_, off_t(pos_), SEEK_SET) != 0) return 0;
#endif
    std::clearerr(f_);
    // Отдаём только целые строки. Незаконченная последняя строка будет прочитана в следующий раз.
    uint64_t file_pos = pos_;     // позиция следующего читаемого байта
    std::string cur;              // текущая строка (обрезанная до kMaxLine)
    size_t taken = 0;
    char buf[64 * 1024];
    while (true) {
        size_t n = std::fread(buf, 1, sizeof(buf), f_);
        if (n == 0) break;
        size_t start = 0;
        for (size_t i = 0; i < n; ++i) {
            if (buf[i] != '\n') continue;
            if (cur.size() < kMaxLine) cur.append(buf + start, std::min(i - start, kMaxLine - cur.size()));
            if (!cur.empty() && cur.back() == '\r') cur.pop_back();
            taken += size_t(file_pos + i + 1 - pos_);
            pos_ = file_pos + i + 1;
            out.push_back(std::move(cur));
            cur.clear();
            start = i + 1;
            if (taken >= max_bytes) return taken;
        }
        if (start < n && cur.size() < kMaxLine) cur.append(buf + start, std::min(n - start, kMaxLine - cur.size()));
        file_pos += n;
    }
    return taken;
}

}  // namespace sentinel::agent
