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

