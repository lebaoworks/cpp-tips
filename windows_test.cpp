#include "windows.hpp"

#include "utest.h"


UTEST(windows, process)
{
    ASSERT_GT(windows::process::list_processes().size(), 0);
}