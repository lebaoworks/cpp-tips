#include "file.hpp"

// Standard C/C++ Headers:
#include <string>

// Standard C/C++ Libraries:
#include <list>

// Precompiled Headers:
#include "../nstd.hpp"

namespace windows
{
    namespace file
    {
        bool file_info::is_directory() const noexcept
        {
            return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        }

        std::list<file_info> list(const std::wstring& path)
        {
            WIN32_FIND_DATAW data;
            auto handle = FindFirstFileW((path + L"\\*").c_str(), &data);
            if (handle == INVALID_HANDLE_VALUE)
                throw nstd::runtime_error("find first file error: %d", GetLastError());
            defer{ FindClose(handle); };

            std::list<file_info> ret;
            do
            {
                if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
                    continue;

                file_info fi;
                fi.name = data.cFileName;
                fi.size = (static_cast<uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
                fi.creation_time = data.ftCreationTime;
                fi.last_access_time = data.ftLastAccessTime;
                fi.last_write_time = data.ftLastWriteTime;
                fi.attributes = data.dwFileAttributes;
                ret.emplace_back(std::move(fi));
            } while (FindNextFileW(handle, &data) == TRUE);

            return ret;
        }

        bool is_file_exists(const std::wstring& path) noexcept
        {
            DWORD attributes = GetFileAttributesW(path.c_str());
            return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
        }

        bool is_directory_exists(const std::wstring& path) noexcept
        {
            DWORD attributes = GetFileAttributesW(path.c_str());
            return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        }

        void delete_file(const std::wstring& path)
        {
            if (path.empty())
                throw std::invalid_argument("empty path");
            if (DeleteFileW(path.c_str()) == FALSE)
                throw nstd::runtime_error("delete file error: %d", GetLastError());
        }

        void delete_directory(const std::wstring& path)
        {
            if (path.empty())
                throw std::invalid_argument("empty path");
            for (auto& entry : list(path))
            {
                auto entry_path = path + (path.back() == L'\\' ? L"" : L"\\") + entry.name;
                if (entry.is_directory())
                    delete_directory(entry_path);
                else
                    delete_file(entry_path);
            }
            if (RemoveDirectoryW(path.c_str()) == FALSE)
                throw nstd::runtime_error("delete directory error: %d", GetLastError());
        }
    }
}