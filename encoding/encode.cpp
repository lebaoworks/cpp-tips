#include "encode.hpp"

#include "../utest.h"

UTEST(encoding, utf8_to_wide)
{
    {
        const void* utf8 = "\x42\xE1\xBA\xA3\x6F";
        auto utf8_str = std::string(reinterpret_cast<const char*>(utf8), 5);

        const void* wide = "\x42\x00\xA3\x1E\x6F\x00";
        auto expected = std::wstring(reinterpret_cast<const wchar_t*>(wide), 3);

        auto wide_str = encoding::utf8_to_wide(utf8_str);
        ASSERT_EQ(wide_str, expected);
    }

    {
        const void* utf8 = "\x54\xE1\xBA\xA5\x74\x20\x63\xE1\xBA\xA3\x20\xC4\x91\xE1\xBB\x81\x75\x20\x63\xC3\xB3\x20\x6C\xC3\xBD\x20\x64\x6F\x20\x63\xE1\xBB\xA7\x61\x20\x6E\xC3\xB3";
        auto utf8_str = std::string(reinterpret_cast<const char*>(utf8), 38);

        const void* wide = "\x54\x00\xA5\x1E\x74\x00\x20\x00\x63\x00\xA3\x1E\x20\x00\x11\x01\xC1\x1E\x75\x00\x20\x00\x63\x00\xF3\x00\x20\x00\x6C\x00\xFD\x00\x20\x00\x64\x00\x6F\x00\x20\x00\x63\x00\xE7\x1E\x61\x00\x20\x00\x6E\x00\xF3\x00";
        auto expected = std::wstring(reinterpret_cast<const wchar_t*>(wide), 26);

        auto wide_str = encoding::utf8_to_wide(utf8_str);
        ASSERT_EQ(wide_str, expected);
    }

}

UTEST(encoding, wide_to_utf8)
{
    {
        const void* wide = "\x42\x00\xA3\x1E\x6F\x00";
        auto wide_str = std::wstring(reinterpret_cast<const wchar_t*>(wide), 3);

        const void* utf8 = "\x42\xE1\xBA\xA3\x6F";
        auto expected = std::string(reinterpret_cast<const char*>(utf8), 5);

        auto utf8_str = encoding::wide_to_utf8(wide_str);
        ASSERT_EQ(utf8_str, expected);
    }

    {
        const void* wide = "\x54\x00\xA5\x1E\x74\x00\x20\x00\x63\x00\xA3\x1E\x20\x00\x11\x01\xC1\x1E\x75\x00\x20\x00\x63\x00\xF3\x00\x20\x00\x6C\x00\xFD\x00\x20\x00\x64\x00\x6F\x00\x20\x00\x63\x00\xE7\x1E\x61\x00\x20\x00\x6E\x00\xF3\x00";
        auto wide_str = std::wstring(reinterpret_cast<const wchar_t*>(wide), 26);

        const void* utf8 = "\x54\xE1\xBA\xA5\x74\x20\x63\xE1\xBA\xA3\x20\xC4\x91\xE1\xBB\x81\x75\x20\x63\xC3\xB3\x20\x6C\xC3\xBD\x20\x64\x6F\x20\x63\xE1\xBB\xA7\x61\x20\x6E\xC3\xB3";
        auto expected = std::string(reinterpret_cast<const char*>(utf8), 38);

        auto utf8_str = encoding::wide_to_utf8(wide_str);
        ASSERT_EQ(utf8_str, expected);
    }
}
