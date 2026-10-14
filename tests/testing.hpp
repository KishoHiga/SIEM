// Минимальный собственный фреймворк тестов (без сторонних библиотек).
#pragma once

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace testing {

struct TestCase {
    const char* name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

inline int& failures() {
    static int f = 0;
    return f;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

inline void report(const char* file, int line, const std::string& what) {
    ++failures();
    std::cerr << "  FAIL " << file << ":" << line << ": " << what << "\n";
}

}  // namespace testing

#define TEST_CAT2(a, b) a##b
#define TEST_CAT(a, b) TEST_CAT2(a, b)
#define TEST(name)                                                                 \
    static void TEST_CAT(test_fn_, __LINE__)();                                    \
    static ::testing::Registrar TEST_CAT(test_reg_, __LINE__)(name, TEST_CAT(test_fn_, __LINE__)); \
    static void TEST_CAT(test_fn_, __LINE__)()

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) ::testing::report(__FILE__, __LINE__, "CHECK(" #cond ")"); \
    } while (0)

#define CHECK_EQ(a, b)                                                                  \
    do {                                                                                \
        const auto va_ = (a);                                                               \
        const auto vb_ = (b);                                                               \
        if (!(va_ == vb_)) {                                                            \
            std::ostringstream os_;                                                     \
            os_ << "CHECK_EQ(" #a ", " #b ") -> [" << va_ << "] != [" << vb_ << "]";    \
            ::testing::report(__FILE__, __LINE__, os_.str());                           \
        }                                                                               \
    } while (0)

#define REQUIRE(cond)                                                       \
    do {                                                                    \
        if (!(cond)) {                                                      \
            ::testing::report(__FILE__, __LINE__, "REQUIRE(" #cond ")");    \
            return;                                                         \
        }                                                                   \
    } while (0)
