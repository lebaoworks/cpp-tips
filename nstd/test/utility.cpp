#include <gtest/gtest.h>
#include <nstd/nstd.hpp>

TEST(nstd_utility, defer_order)
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

TEST(nstd_utility, format)
{
    auto str = nstd::format("%s is %dk", "format", 0);
    ASSERT_EQ(str, "format is 0k");

    const void* invalid_encode = "\xFF\xFF";
    EXPECT_THROW(nstd::format("%ls", reinterpret_cast<const wchar_t*>(invalid_encode)), std::runtime_error);
}

TEST(nstd_utility, exception)
{
    EXPECT_THROW(throw nstd::runtime_error("%s x", "exception"), std::runtime_error);
    EXPECT_THROW(throw nstd::invalid_argument("%s y", "exception"), std::invalid_argument);
}
