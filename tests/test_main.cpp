#include <cstring>

#include "core/log.hpp"
#include "testing.hpp"

int main(int argc, char** argv) {
    sentinel::log::set_level(sentinel::log::Level::Warn);
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int run = 0, failed_tests = 0;
    for (auto& t : testing::registry()) {
        if (filter && !std::strstr(t.name, filter)) continue;
        int before = testing::failures();
        t.fn();
        ++run;
        bool ok = testing::failures() == before;
        if (!ok) ++failed_tests;
        std::cout << (ok ? "[ OK ] " : "[FAIL] ") << t.name << "\n";
    }
    std::cout << "\n" << run << " tests, " << failed_tests << " failed, " << testing::failures()
              << " failed checks\n";
    return failed_tests == 0 ? 0 : 1;
}
