#pragma once

namespace windows
{
    namespace user
    {
        /// @brief Check if current process as administrator.
        /// @return true if it is, false otherwise.
        bool is_admin();
    }
}