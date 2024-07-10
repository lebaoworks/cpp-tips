#include "event_log.hpp"

#include "../utest.h"
#include "user.hpp"


UTEST(windows, event_log_log)
{
    if (windows::user::is_admin() == false)
        UTEST_SKIP("test session is not running by admin user");

    windows::event_log::setup(L"test_src", L"test_1");
    windows::event_log::setup(L"test_src", L"test_2");

    windows::event_log::log logger1(L"test_1");
    logger1.info("abc");

    windows::event_log::log logger2(L"test_2");
    logger2.info("qwe");
}