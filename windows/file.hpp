#pragma once

// Standard C/C++ Headers:
#include <string>

// Standard Windows Headers:
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// Standard C/C++ Libraries:
#include <list>

namespace windows
{
    namespace file
    {
        struct file_info
        {
            std::wstring name;
            DWORD attributes;
            size_t size;
            FILETIME creation_time;
            FILETIME last_access_time;
            FILETIME last_write_time;

            /// @brief Check if the file is a directory.
            /// @return true if it is, false otherwise.
            bool is_directory() const noexcept;
        };

        /// @brief List all files in the directory.
        /// @param path path to the directory.
        /// @return list of files.
        std::list<file_info> list(const std::wstring& path);

        /// @brief Check if the file exists.
        /// @param path path to the file.
        /// @return true if it is, false otherwise.
        bool is_file_exists(const std::wstring& path) noexcept;

        /// @brief Check if the directory exists.
        /// @param path path to the directory.
        /// @return true if it is, false otherwise.
        bool is_directory_exists(const std::wstring& path) noexcept;

        /// @brief Delete the file.
        /// @param path path to the file.
        void delete_file(const std::wstring& path);

        // @brief Delete the directory.
        /// @param path path to the directory.
        void delete_directory(const std::wstring& path);

    }
}