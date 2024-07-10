#pragma once

// Standard C/C++ Headers:
#include <string>
#include <list>

namespace windows
{
    namespace disk
    {
        /// @brief List all disks.
        /// @return list of disks.
        /// @note currently only list fixed and removable drives.
        std::list<std::string> list_logical();
    }
}