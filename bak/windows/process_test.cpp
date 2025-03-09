#include "process.hpp"

#include "../utest.h"

UTEST(windows, process_list)
{
    ASSERT_GT(windows::process::list().size(), 0);
}

UTEST(windows, process_process)
{
    auto this_process = windows::process::process();
    this_process.search_memory("a", 1);
}

UTEST(windows, process_image_path)
{
    auto this_process = windows::process::process();
    ASSERT_GT(this_process.image_path().length(), 0);
}

UTEST(windows, process_command_line)
{
    auto this_process = windows::process::process();
    ASSERT_GT(this_process.command_line().length(), 0);
}

UTEST(windows, process_search_memory)
{
    auto this_process = windows::process::process();
    this_process.search_memory("a", 1);
}