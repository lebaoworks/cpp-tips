#include <iostream>

#include "nstd.hpp"
#include "windows.hpp"

void search_memory(const void* data, size_t size)
{
    for (auto& process_info : windows::process::list_processes())
    {
        try
        {
            windows::process::process process = windows::process::process(process_info.process_id, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
            if (process.search_memory(data, size) == true)
                printf("[+] Process %d\n", process_info.process_id);
        }
        catch (std::exception& e)
        {
            printf("[!] Open process %d error: %s\n", process_info.process_id, e.what());
        }
    }
}

std::list<std::string> search_registry_value_recursive(const windows::registry::key& key)
{
    //printf("key -> %s\n", key.get_path().c_str());

    for (auto& subkey_name : key.list_subkeys())
    {
        try
        {
            search_registry_value_recursive(key.subkey(subkey_name, KEY_READ));
        }
        catch (std::exception& e)
        {
        }
    }
    return {};
}

void search_registry_value()
{
    auto key = windows::registry::key("HKEY_CURRENT_USER\\Bao", KEY_READ);
    //search_registry_value_recursive(key);
    for (auto& subkey_name : key.list_subkeys())
        printf("%s\n", subkey_name.c_str());
    for (auto& value_name : key.list_values())
        printf("%s\n", value_name.c_str());
}

#include "utest.h"

UTEST_MAIN()
