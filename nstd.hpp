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
#include <string>
#include <stdexcept>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
namespace nstd
{
    namespace encoding
    {
        inline std::wstring utf8_to_wide(const std::string& utf8_str)
        {
            if (utf8_str.length() > INT_MAX)
                throw std::invalid_argument("string too long");
            int cb = static_cast<int>(utf8_str.length());

            auto cch = MultiByteToWideChar(
                CP_UTF8,                                    // Code page -> UTF-8
                MB_ERR_INVALID_CHARS | MB_PRECOMPOSED,      // Flags -> Fail if an invalid input character is encountered + Using single character for base and nonspacing
                utf8_str.c_str(),                           // MultiByteStr
                cb,                                         // MultiByteStr size in bytes
                NULL,                                       // WideStr
                0);                                         // WideStr size in characters -> 0 to get final size
            if (cch == 0)
                throw nstd::runtime_error("convert failed, error: %d", GetLastError());
            
            std::wstring ret(cch, L'\x00');
            auto cch2 = MultiByteToWideChar(
                CP_UTF8,                                    // Code page -> UTF-8
                MB_PRECOMPOSED | MB_ERR_INVALID_CHARS,      // Flags -> Fail if an invalid input character is encountered + Using single character for base and nonspacing
                utf8_str.c_str(),                           // MultiByteStr
                cb,                                         // MultiByteStr size in bytes
                &ret[0],                                    // WideStr
                cch + 1);                                   // WideStr size in characters
            if (cch2 != cch)
                throw nstd::runtime_error("convert failed, error: %d", GetLastError());
            return ret;
        }

        inline std::string wide_to_utf8(const std::wstring& wide_str)
        {
            if (wide_str.length() > INT_MAX)
                throw std::invalid_argument("string too long");
            int cch = static_cast<int>(wide_str.length());

            auto cb = WideCharToMultiByte(
                CP_UTF8,                                    // Code page -> UTF-8
                WC_ERR_INVALID_CHARS | WC_DISCARDNS,        // Flags -> Fail if an invalid input character is encountered + Discard nonspacing
                wide_str.c_str(),                           // WideStr
                cch,                                        // WideStr size in characters
                NULL,                                       // MultiByteStr
                0,                                          // MultiByteStr size in bytes -> 0 to get final size
                NULL,                                       // DefaultChar -> Don't care, discard anyway
                NULL);                                      // UsedDefaultChar
            if (cb == 0)
                throw nstd::runtime_error("convert failed, error: %d", GetLastError());

            std::string ret(cb, '\x00');
            auto cb2 = WideCharToMultiByte(
                CP_UTF8,                                    // Code page -> UTF-8
                WC_ERR_INVALID_CHARS | WC_DISCARDNS,        // Flags -> Fail if an invalid input character is encountered + Discard nonspacing
                wide_str.c_str(),                           // WideStr
                cch,                                        // WideStr size in characters
                &ret[0],                                    // MultiByteStr
                cb + 1,                                     // MultiByteStr size in bytes
                NULL,                                       // DefaultChar -> Don't care, discard anyway
                NULL);                                      // UsedDefaultChar -> Don't care
            if (cb2 != cb)
                throw nstd::runtime_error("convert failed, error: %d", GetLastError());
            return ret;
        }
    }
}
#else
#include <string>
#include <stdexcept>
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
#endif