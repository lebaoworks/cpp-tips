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

int main()
{
    try
    {
        search_memory("bao", 3);

        return 0;
    }
    catch (std::exception& e)
    {
        printf("Exception: %s\n", e.what());
        return 1;
    }

}
