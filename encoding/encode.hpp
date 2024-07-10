#pragma once

#include <string>
#include <locale>
#include <codecvt>

namespace encoding
{
    inline std::string hex(void* data, size_t size)
    {
        static const char characters[] = "0123456789ABCDEF";
        std::string ret(size * 2, 0);
        auto buf = const_cast<char*>(ret.data());
        auto d = reinterpret_cast<uint8_t*>(data);
        for (size_t i = 0; i < size; ++i, ++d)
        {
            *buf++ = characters[*d >> 4];
            *buf++ = characters[*d & 0x0F];
        }
        return ret;
    }
}

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

