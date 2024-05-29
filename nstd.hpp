#pragma once

// Defer
#include <memory>

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
#define DEFER_(LINE) zz_defer##LINE
#define DEFER(LINE) DEFER_(LINE)
#define defer auto DEFER(__LINE__) = defer_dummy{} *[&]()

// Format
#include <cstdio>
#include <memory>
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
#include <string>

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

// Encoding
#include <locale>
#include <codecvt>
namespace nstd
{
    namespace encoding
    {
        inline std::wstring utf8_to_wide(const std::string& str)
        {
            return std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>().from_bytes(str);
        }

        inline std::string wide_to_utf8(const std::wstring& wstr)
        {
            return std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>().to_bytes(wstr);
        }
    }
}