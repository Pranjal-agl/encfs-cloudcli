#pragma once
// Minimal test helpers. Unlike assert(), CHECK is never compiled out, so the
// tests still test something in Release (-DNDEBUG) builds.

#include <cstdlib>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <stdlib.h>

namespace encfs_test {

inline int& Failures() {
    static int failures = 0;
    return failures;
}

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::cerr << "    CHECK failed: " #cond " (" __FILE__ ":"            \
                      << __LINE__ << ")\n";                                     \
            ++::encfs_test::Failures();                                          \
        }                                                                        \
    } while (0)

#define CHECK_THROWS(expr)                                                       \
    do {                                                                         \
        bool threw_ = false;                                                     \
        try {                                                                    \
            (void)(expr);                                                        \
        } catch (const std::exception&) {                                        \
            threw_ = true;                                                       \
        }                                                                        \
        if (!threw_) {                                                           \
            std::cerr << "    expected exception: " #expr " (" __FILE__ ":"      \
                      << __LINE__ << ")\n";                                     \
            ++::encfs_test::Failures();                                          \
        }                                                                        \
    } while (0)

// Run named test functions; returns the process exit code.
inline int RunTests(const char* suite,
                    const std::vector<std::pair<const char*, std::function<void()>>>& tests) {
    std::cout << "Running " << suite << " tests...\n";
    int failed_tests = 0;
    for (const auto& [name, fn] : tests) {
        int before = Failures();
        try {
            fn();
        } catch (const std::exception& e) {
            std::cerr << "    unexpected exception: " << e.what() << "\n";
            ++Failures();
        }
        bool ok = Failures() == before;
        if (!ok) ++failed_tests;
        std::cout << "  " << (ok ? "✓ " : "✗ ") << name << "\n";
    }
    if (failed_tests) {
        std::cout << "\n✗ " << failed_tests << " of " << tests.size() << " " << suite
                  << " tests failed\n";
        return 1;
    }
    std::cout << "\n✓ All " << tests.size() << " " << suite << " tests passed\n";
    return 0;
}

// A fresh temporary directory, removed when it goes out of scope.
class TempDir {
public:
    TempDir() {
        std::string tmpl = "/tmp/encfs_test_XXXXXX";
        std::vector<char> buf(tmpl.begin(), tmpl.end());
        buf.push_back('\0');
        if (!mkdtemp(buf.data())) throw std::runtime_error("mkdtemp failed");
        path_ = buf.data();
    }
    ~TempDir() {
        std::string cmd = "rm -rf '" + path_ + "'";
        if (std::system(cmd.c_str()) != 0) {
            std::cerr << "warning: could not remove " << path_ << "\n";
        }
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    const std::string& path() const { return path_; }
    std::string operator/(const std::string& name) const { return path_ + "/" + name; }

private:
    std::string path_;
};

inline std::vector<uint8_t> Bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace encfs_test
