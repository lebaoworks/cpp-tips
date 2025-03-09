#pragma once

// Defer
#include <memory>

namespace nstd
{
    struct defer_dummy {};
    template<class F>
    struct deferer
    {
        F _f;
        deferer(F&& f) noexcept : _f(f) {}
        ~deferer() { _f(); }
    };
    template<class F>
    inline deferer<F> operator*(defer_dummy, F&& f) noexcept { return deferer<F>(std::move(f)); }
}
#define DEFER_(LINE) zz_defer##LINE
#define DEFER(LINE) DEFER_(LINE)
#define defer auto DEFER(__LINE__) = nstd::defer_dummy{} *[&]()

// Format
#include <cstdio>
#include <stdexcept>
#include <string>

namespace nstd
{
    template<typename... Args>
    std::string format(const std::string& format, const Args&... args)
    {
        int size_s = std::snprintf(nullptr, 0, format.c_str(), args...);
        if (size_s < 0) throw std::runtime_error("Error during formatting");
        std::string ret(size_s, '\x00');
        std::snprintf(&ret[0], size_s + 1, format.c_str(), args...);
        return ret;
    }
}

// Format exception
#include <stdexcept>

namespace nstd
{
    struct runtime_error : public std::runtime_error
    {
        template<typename... Args>
        runtime_error(const std::string& format, const Args&... args) :
            std::runtime_error(nstd::format(format, args...)) {}
    };

    struct invalid_argument : public std::invalid_argument
    {
        template<typename... Args>
        invalid_argument(const std::string& format, const Args&... args) :
            std::invalid_argument(nstd::format(format, args...)) {}
    };
}

// Time counter
#include <chrono>
namespace nstd
{
    struct time_counter
    {
        std::chrono::time_point<std::chrono::high_resolution_clock> start;

        time_counter() :
            start(std::chrono::high_resolution_clock::now()) {}

        inline void reset() { start = std::chrono::high_resolution_clock::now(); }

        template <typename T>
        size_t elapsed() const { return std::chrono::duration_cast<T>(std::chrono::high_resolution_clock::now() - start).count(); }
    };
}