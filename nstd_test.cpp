#include "nstd.hpp"

#include "utest.h"

UTEST(nstd_encoding, utf8_to_wide)
{
    const void* utf8 = "\x42\xE1\xBA\xA3\x6F";
    const void* wide = "\x42\x00\xA3\x1E\x6F\x00";

    auto utf8_str = std::string(reinterpret_cast<const char*>(utf8), 5);
    
    auto wide_str = nstd::encoding::utf8_to_wide(utf8_str);
    ASSERT_EQ(wide_str.length(), 3);

    auto expected = std::wstring(reinterpret_cast<const wchar_t*>(wide), 3);
    ASSERT_EQ(wide_str, expected);
}

UTEST(nstd_encoding, wide_to_utf8)
{
    const void* utf8 = "\x42\xE1\xBA\xA3\x6F";
    const void* wide = "\x42\x00\xA3\x1E\x6F\x00";

    auto wide_str = std::wstring(reinterpret_cast<const wchar_t*>(wide), 3);

    auto utf8_str = nstd::encoding::wide_to_utf8(wide_str);
    ASSERT_EQ(utf8_str.length(), 5);

    auto expected = std::string(reinterpret_cast<const char*>(utf8), 5);
    ASSERT_EQ(utf8_str, expected);
}