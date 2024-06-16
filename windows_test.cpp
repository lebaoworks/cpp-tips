#include "windows.hpp"

#include "utest.h"


UTEST(windows_process, list)
{
    ASSERT_GT(windows::process::list().size(), 0);
}

UTEST(windows_process, process)
{
    auto this_process = windows::process::process();
    this_process.search_memory("a", 1);
}

UTEST(windows_process, process_image_path)
{
    auto this_process = windows::process::process();
    ASSERT_GT(this_process.image_path().length(), 0);
}

UTEST(windows_process, process_command_line)
{
    auto this_process = windows::process::process();
    ASSERT_GT(this_process.command_line().length(), 0);
}

UTEST(windows_process, process_search_memory)
{
    auto this_process = windows::process::process();
    this_process.search_memory("a", 1);
}

UTEST(windows_regisry, create_delete)
{
    auto key = windows::registry::key(L"HKEY_CURRENT_USER", KEY_ALL_ACCESS);
    EXPECT_EXCEPTION(key.create_key(L"\\asd\\qwe"), std::invalid_argument);

    auto sub = key.create_key(L"bao");
    defer{ key.delete_key(L"bao"); };
}

UTEST(windows_regisry, dword)
{
    auto key = windows::registry::key(L"HKEY_CURRENT_USER", KEY_ALL_ACCESS);
    key.set_dword(L"bao", 123);
    defer{ key.delete_value(L"bao"); };

    auto value = key.get_dword(L"bao");
    EXPECT_EQ(value, 123);
}

UTEST(windows_regisry, string)
{
    auto key = windows::registry::key(L"HKEY_CURRENT_USER", KEY_ALL_ACCESS);
    key.set_string(L"bao", L"zxc");
    defer{ key.delete_value(L"bao"); };

    auto value = key.get_string(L"bao");
    EXPECT_EQ(value, L"zxc");
}

UTEST(windows_regisry, expand_string)
{
    auto key = windows::registry::key(L"HKEY_CURRENT_USER", KEY_ALL_ACCESS);
    key.set_expand_string(L"bao", L"%systemroot%\\system32");
    defer{ key.delete_value(L"bao"); };

    auto non_expand = key.get_expand_string(L"bao");
    EXPECT_EQ(non_expand, L"%systemroot%\\system32");
    
    auto expand = key.get_expand_string(L"bao", true);
    EXPECT_NE(expand, L"%systemroot%\\system32");
    EXPECT_NE(expand.find(L"system32"), std::wstring::npos);
}

UTEST(windows_regisry, multi_string)
{
    auto key = windows::registry::key(L"HKEY_CURRENT_USER", KEY_ALL_ACCESS);
    key.set_multi_string(L"bao", {L"1", L"2"});
    defer{ key.delete_value(L"bao"); };

    auto values = key.get_multi_string(L"bao");
    ASSERT_EQ(values.size(), 2);
    EXPECT_EQ(values.front(), L"1");
    EXPECT_EQ(values.back(), L"2");
}

UTEST(windows_event_log, log)
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