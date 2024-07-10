#pragma once

// Standard C/C++ Headers:
#include <string>
#include <list>

// Standard Windows Headers:
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace windows
{
    namespace process
    {
        struct process_info
        {
            DWORD id = 0;
            std::wstring name = L"";
            DWORD parent_id = 0;
        };

        /// @brief List all running processes.
        /// @return list of processes.
        std::list<process_info> list();

        class process
        {
        private:
            HANDLE _handle = NULL;
        public:

            /// @brief Default constructor. Object is reference to current process.
            process();

            /// @brief Open process by process id.
            /// @param process_id process id.
            /// @param desired_access access to the process.
            process(DWORD process_id, DWORD desired_access = PROCESS_ALL_ACCESS);

            /// @brief Destructor.
            ~process();

            /// @brief Get process image full path.
            /// @return Full path to the process image.
            /// @note require `PROCESS_QUERY_INFORMATION` access.
            std::wstring image_path() const;

            /// @brief Get process command line.
            /// @return Command line of the process.
            /// @note require `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` access.
            std::wstring command_line() const;

            /// @brief Search memory space of the process.
            /// @param data data to search.
            /// @param size size of the data.
            /// @return true if data found, false otherwise.
            /// @note require `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` access.
            bool search_memory(const void* data, size_t size) const;
        };
    }
}
