#include "store/file.hpp"

#ifdef _WIN32
#include <io.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif

namespace sentinel {

bool File::open(const std::string& path, const char* mode) {
    close();
    f_ = std::fopen(path.c_str(), mode);
    return f_ != nullptr;
}

void File::close() {
    if (f_) {
        std::fclose(f_);
        f_ = nullptr;
    }
}

bool File::seek(uint64_t offset) {
    if (!f_) return false;
#ifdef _WIN32
    return _fseeki64(f_, int64_t(offset), SEEK_SET) == 0;
#else
    return fseeko(f_, off_t(offset), SEEK_SET) == 0;
#endif
}

uint64_t File::tell() {
    if (!f_) return 0;
#ifdef _WIN32
    return uint64_t(_ftelli64(f_));
#else
    return uint64_t(ftello(f_));
#endif
}

uint64_t File::size() {
    if (!f_) return 0;
    uint64_t cur = tell();
#ifdef _WIN32
    _fseeki64(f_, 0, SEEK_END);
    uint64_t s = uint64_t(_ftelli64(f_));
    _fseeki64(f_, int64_t(cur), SEEK_SET);
#else
    fseeko(f_, 0, SEEK_END);
    uint64_t s = uint64_t(ftello(f_));
    fseeko(f_, off_t(cur), SEEK_SET);
#endif
    return s;
}

bool File::read(void* buf, size_t n) { return f_ && std::fread(buf, 1, n, f_) == n; }
bool File::write(const void* buf, size_t n) { return f_ && std::fwrite(buf, 1, n, f_) == n; }
bool File::flush() { return f_ && std::fflush(f_) == 0; }

bool File::sync() {
    if (!f_ || std::fflush(f_) != 0) return false;
#ifdef _WIN32
    return _commit(_fileno(f_)) == 0;
#else
    return fsync(fileno(f_)) == 0;
#endif
}

}  // namespace sentinel
