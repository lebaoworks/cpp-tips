#include "registry.hpp"

#include "../nstd.hpp"
#include "../utest.h"

UTEST(windows, regisry_create_delete)
{
    auto key = windows::registry::key(L"HKEY_CURRENT_USER", KEY_ALL_ACCESS);
    EXPECT_EXCEPTION(key.create_key(L"\\asd\\qwe"), std::invalid_argument);

    auto sub = key.create_key(L"bao");
    defer{ key.delete_key(L"bao"); };
}

UTEST(windows, regisry_dword)
{
    auto key = windows::registry::key(L"HKEY_CURRENT_USER", KEY_ALL_ACCESS);
    key.set_dword(L"bao", 123);
    defer{ key.delete_value(L"bao"); };

    auto value = key.get_dword(L"bao");
    EXPECT_EQ(value, 123);
}

UTEST(windows, regisry_string)
{
    auto key = windows::registry::key(L"HKEY_CURRENT_USER", KEY_ALL_ACCESS);
    key.set_string(L"bao", L"zxc");
    defer{ key.delete_value(L"bao"); };

    auto value = key.get_string(L"bao");
    EXPECT_EQ(value, L"zxc");
}

UTEST(windows, regisry_list_subkeys)
{
    auto key = windows::registry::key(L"HKEY_CURRENT_USER", KEY_ALL_ACCESS);
    auto subkeys = key.list_subkeys();
    ASSERT_GT(subkeys.size(), 0);
}

UTEST(windows, regisry_list_values)
{
    auto key = windows::registry::key(L"HKEY_CURRENT_USER\\Environment", KEY_ALL_ACCESS);
    auto values = key.list_values();
    ASSERT_GT(values.size(), 0);
}

UTEST(windows, regisry_expand_string)
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

UTEST(windows, regisry_multi_string)
{
    auto key = windows::registry::key(L"HKEY_CURRENT_USER", KEY_ALL_ACCESS);
    key.set_multi_string(L"bao", {L"1", L"2"});
    defer{ key.delete_value(L"bao"); };

    auto values = key.get_multi_string(L"bao");
    ASSERT_EQ(values.size(), 2);
    EXPECT_EQ(values.front(), L"1");
    EXPECT_EQ(values.back(), L"2");
}