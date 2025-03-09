#pragma once

// Encoding
#include <string>
#include <locale>
#include <codecvt>
#include <cstdint>

namespace nstd
{
    inline std::string hex(const void* data, size_t size)
    {
        static const char characters[] = "0123456789ABCDEF";
        std::string ret(size * 2, 0);
        auto buf = const_cast<char*>(ret.data());
        auto d = reinterpret_cast<const uint8_t*>(data);
        for (size_t i = 0; i < size; ++i, ++d)
        {
            *buf++ = characters[*d >> 4];
            *buf++ = characters[*d & 0x0F];
        }
        return ret;
    }

    template<typename V, typename U>
    inline V encode(const U& str) = delete;

    template<>
    inline std::u16string encode<std::u16string, std::string>(const std::string& str)
    {
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
        return converter.from_bytes(str);
    }

    template<>
    inline std::string encode<std::string, std::u16string>(const std::u16string& str)
    {
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
        return converter.to_bytes(str);
    }
}