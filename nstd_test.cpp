#include "nstd.hpp"

#include "utest.h"

UTEST(nstd_defer, defer_)
{
    std::string check = "1";
    defer { ASSERT_EQ(check, "2"); };
    
    defer { check = "2"; };
    ASSERT_EQ(check, "1");

    {
        defer { check = "3"; };
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

UTEST(nstd_hash, SHA256)
{
    nstd::hash::SHA256 sha256;
    sha256.feed("lebaoworks@gmail", 16);

    // 1
    auto hex = sha256.hex_digest();
    EXPECT_EQ(hex, "D736285BCBE504A601B7A01ECBC0DAD88E95DB846110CC3A0F50A176B1439720");

    // 2
    EXPECT_EQ(hex, sha256.hex_digest());

    // 3
    sha256.feed(".com", 4);
    EXPECT_EQ(sha256.hex_digest(), "7A0E47BC9465926BE31799E54885F33B42550AB40BB222617AAFC71715579AC6");
}