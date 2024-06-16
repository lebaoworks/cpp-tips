#include "nstd.hpp"

#include "utest.h"

UTEST_MAIN()


#include <chrono>
#include <list>
#include <queue>

#include <thread>
#include <iostream>
#include "windows.hpp"

static bool scan_file(const std::wstring file_path, uint32_t diskio_limit = 1048576) noexcept
{
    try
    {
        // open file without putting any restrictions on access to the file
        HANDLE handle = CreateFileW(
            file_path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL
        );
        if (handle == INVALID_HANDLE_VALUE)
            throw nstd::runtime_error("open file error: %d", GetLastError());
        defer { CloseHandle(handle); };

        // read file in chunks
        auto buffer = std::make_unique<uint8_t[]>(diskio_limit);
        DWORD read = 0;
        nstd::hash::MD5 md5;
        nstd::hash::SHA1 sha1;
        nstd::hash::SHA256 sha256;
        while (true)
        {
            auto start = std::chrono::steady_clock::now();

            // read chunk
            if (ReadFile(handle, buffer.get(), diskio_limit, &read, NULL) == FALSE)
                throw nstd::runtime_error("read file error: %d", GetLastError());
            // end of file
            if (read == 0)
                break;

            // hash chunk
            md5.feed(buffer.get(), read);
            sha1.feed(buffer.get(), read);
            sha256.feed(buffer.get(), read);

            // sleep to limit disk io
            auto end = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            if (elapsed < 1000)
                std::this_thread::sleep_for(std::chrono::milliseconds(1000 - elapsed));
        }
        
        // print hashes
        std::cout << "MD5: " << md5.hex_digest() << std::endl;
        std::cout << "SHA1: " << sha1.hex_digest() << std::endl;
        std::cout << "SHA256: " << sha256.hex_digest() << std::endl;

        return true;
    }
    catch (std::exception& e)
    {
        return false;
    }
}

UTEST(main, scan_files)
{
    UTEST_SKIP("skip scan_files test");
    
    std::queue<std::wstring> pending;
    for (auto& drive : windows::disk::list_logical())
        pending.push(nstd::encoding::utf8_to_wide(drive));

    while (!pending.empty())
    {
        auto dir_path = std::move(pending.front());
        pending.pop();
        
        // skip directories that we don't have access to
        try
        {
            for (const auto& file : windows::file::list(dir_path))
            {
                auto file_path = dir_path + (dir_path.back() != L'\\' ? L"\\" : L"") + file.name;
                
                // if the file is a directory, add it to the pending list
                if (file.is_directory())
                {
                    pending.push(file_path);
                    continue;
                }
                // if the file is a regular file, scan it
                else
                {
                    std::wcout << file_path << std::endl;
                    scan_file(file_path);
                }
            }
        }
        catch (std::exception& e)
        {
            std::wcerr << dir_path << " -> " << e.what() << std::endl;
        }
    }
}


#include <fstream>
UTEST(main, mark_files)
{
    UTEST_SKIP("skip mark_files test");

    std::ofstream marker("file_marker.txt");
    ASSERT_EQ(marker.is_open(), true);

    std::queue<std::wstring> pending;
    for (auto& drive : windows::disk::list_logical())
        pending.push(nstd::encoding::utf8_to_wide(drive));

    while (!pending.empty())
    {
        auto dir_path = std::move(pending.front());
        pending.pop();

        // skip directories that we don't have access to
        try
        {
            for (const auto& file : windows::file::list(dir_path))
            {
                auto file_path = dir_path + (dir_path.back() != L'\\' ? L"\\" : L"") + file.name;

                // if the file is a directory, add it to the pending list
                if (file.is_directory())
                {
                    pending.push(file_path);
                    continue;
                }
                // if the file is a regular file, scan it
                else
                {
                    marker << nstd::encoding::wide_to_utf8(file_path) << std::endl;
                }
            }
        }
        catch (std::exception& e)
        {
            std::wcerr << dir_path << " -> " << e.what() << std::endl;
        }
    }
}


#include <unordered_map>
UTEST(main, mark_files_md5)
{
    UTEST_SKIP("skip mark_files_md5 test");

    std::ifstream marker2("file_marker2.txt");
    ASSERT_EQ(marker2.is_open(), true);

    std::ofstream marker("file_marker.txt");
    ASSERT_EQ(marker.is_open(), true);

    std::unordered_map<std::string, std::wstring> files;
    for (std::string line; std::getline(marker2, line);)
    {
        auto file_path = nstd::encoding::utf8_to_wide(line);
        nstd::hash::MD5 md5;
        md5.feed(file_path.c_str(), file_path.size() * sizeof(wchar_t));

        auto hex = md5.hex_digest();
        auto found = files.find(hex);
        if (found == files.end())
        {
            files[hex] = file_path;
            marker << hex << std::endl;
        }
        else
        {
            std::wcout << L"DUPLICATE: " << file_path << L" -> " << files[hex] << std::endl;
        }
    }
}


UTEST(main, mark_registry)
{
    std::ofstream marker("registry_marker.txt");
    ASSERT_EQ(marker.is_open(), true);

    std::queue<std::wstring> pending;
    pending.push(L"HKEY_CLASSES_ROOT");
    pending.push(L"HKEY_LOCAL_MACHINE");
    pending.push(L"HKEY_CURRENT_USER");
    pending.push(L"HKEY_USERS");

    while (!pending.empty())
    {
        auto key_path = std::move(pending.front());
        pending.pop();

        // skip keys that we don't have access to
        try
        {
            windows::registry::key key(key_path, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS);
            for (const auto& subkey_name : key.list_subkeys())
            {
                auto subkey_path = key_path + L"\\" + subkey_name; 
                pending.push(subkey_path);
                marker << nstd::encoding::wide_to_utf8(subkey_path) << std::endl;
            }
        }
        catch (std::exception& e)
        {
            std::wcerr << key_path << " -> " << e.what() << std::endl;
        }
    }
}