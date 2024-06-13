#include "nstd.hpp"

#include "utest.h"

UTEST(nstd_defer, defer_)
{
    std::string check = "1";
    defer{ ASSERT_EQ(check, "2"); };

    defer{ check = "2"; };
    ASSERT_EQ(check, "1");

    {
        defer{ check = "3"; };
        check = "4";
    }
    ASSERT_EQ(check, "3");
}

UTEST(nstd_format, format)
{
    auto str = nstd::format("%s is %dk", "format", 0);
    ASSERT_EQ(str, "format is 0k");

    const void* invalid_encode = "\xFF\xFF";
    ASSERT_EXCEPTION(nstd::format("%ls", reinterpret_cast<const wchar_t*>(invalid_encode)), std::runtime_error);
}

UTEST(nstd_exception, exception)
{
    ASSERT_EXCEPTION_WITH_MESSAGE(throw nstd::runtime_error("%s x", "exception"), std::runtime_error, "exception x");
    ASSERT_EXCEPTION_WITH_MESSAGE(throw nstd::invalid_argument("%s y", "exception"), std::invalid_argument, "exception y");
}

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

UTEST(nstd_hash, MD5)
{
    {
        nstd::hash::MD5 hash;
        hash.feed("lebaoworks@gmail", 16);

        // 1 hex digest
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "0B737437545077EC6FF2393187441A8D");

        // 2 multiple times
        EXPECT_EQ(hex, hash.hex_digest());

        // 3 feed
        hash.feed(".com", 4);
        EXPECT_EQ(hash.hex_digest(), "05AC2DFB7480D1547E99D1FF60033C01");
    }

    {
        // 4 padding
        nstd::hash::MD5 hash;
        hash.feed("6eabd16e239f03cf3187237747f78c8f0ea07e456eabd16e23aaaaaaa", 57);
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "15424B726B74DFF743E8C7128E137C9F");
    }
}

UTEST(nstd_hash, SHA1)
{
    {
        nstd::hash::SHA1 hash;
        hash.feed("lebaoworks@gmail", 16);

        // 1 hex digest
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "DC20F4CA1A7E2DB511418644EDF69E0B831CE98C");

        // 2 multiple times
        EXPECT_EQ(hex, hash.hex_digest());

        // 3 feed
        hash.feed(".com", 4);
        EXPECT_EQ(hash.hex_digest(), "6EABD16E239F03CF3187237747F78C8F0EA07E45");
    }

    {
        // 4 padding
        nstd::hash::SHA1 hash;
        hash.feed("6eabd16e239f03cf3187237747f78c8f0ea07e456eabd16e23aaaaaaa", 57);
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "D50DB2A34B7513AABC3E63E0EC913C2953096D2E");
    }
}

UTEST(nstd_hash, SHA256)
{
    {
        nstd::hash::SHA256 hash;
        hash.feed("lebaoworks@gmail", 16);

        // 1 hex digest
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "D736285BCBE504A601B7A01ECBC0DAD88E95DB846110CC3A0F50A176B1439720");

        // 2 multiple times
        EXPECT_EQ(hex, hash.hex_digest());

        // 3 feed
        hash.feed(".com", 4);
        EXPECT_EQ(hash.hex_digest(), "7A0E47BC9465926BE31799E54885F33B42550AB40BB222617AAFC71715579AC6");
    }

    {
        // 4 padding
        nstd::hash::SHA256 hash;
        hash.feed("6eabd16e239f03cf3187237747f78c8f0ea07e456eabd16e23aaaaaaa", 57);
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "C48EF574E6D59BD0DEFA5D1002EE0B8A2B42C16982A798FDD73F2A2D5E19FE70");
    }
}