#include "windows.hpp"

// Standard C/C++ Libraries:
#include <algorithm>
#include <map>
#include <memory>

// Standard Windows Headers:
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")
#include <Winternl.h>
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0
#endif

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
    }
}

namespace windows
{
    namespace disk
    {
        std::list<std::string> list_logical()
        {
            std::list<std::string> drives;
            char buffer[256];
            DWORD needed = GetLogicalDriveStringsA(sizeof(buffer), buffer);

            if (needed == 0)
                throw nstd::runtime_error("GetLogicalDriveStringsA error: %d", GetLastError());
            if (needed > sizeof(buffer))
                throw nstd::runtime_error("GetLogicalDriveStringsA buffer too small: %d", needed);

            for (char* p = buffer; p < buffer + 256;)
            {
                std::string drive = p;
                UINT driveType = GetDriveTypeA(drive.c_str());
                if (driveType == DRIVE_FIXED ||
                    driveType == DRIVE_REMOVABLE)
                    drives.push_back(drive);

                p += drive.length() + 1;
            }

            return drives;
        }
    }
}

namespace windows
{
    namespace process
    {
        std::list<process_info> list()
        {
            auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                throw nstd::runtime_error("snapshot process error %d", GetLastError());
            defer { CloseHandle(snapshot); };

            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(snapshot, &pe) == FALSE)
                throw nstd::runtime_error("find snapshot first process error: %d", GetLastError());
            
            std::list<process_info> ret;
            do
            {
                process_info pi;
                pi.id = pe.th32ProcessID;
                pi.name = pe.szExeFile;
                pi.parent_id = pe.th32ParentProcessID;
                ret.emplace_back(std::move(pi));
            } while (Process32NextW(snapshot, &pe));

            return ret;
        }

        process::process() : _handle(GetCurrentProcess()) {}

        process::process(DWORD process_id, DWORD desired_access)
        {
            _handle = OpenProcess(
                desired_access,     // Desired access
                FALSE,              // Inherit -> Child processes do not need this handle
                process_id);        // Process id
            if (_handle == NULL)
                throw nstd::runtime_error("open process error %d", GetLastError());
        }
        
        process::~process()
        {
            CloseHandle(_handle);
        }

        std::wstring process::image_path() const
        {
            std::vector<WCHAR> buffer(MAX_PATH);
            while (true)
            {
                DWORD cch_written = static_cast<DWORD>(buffer.size());
                BOOL success = QueryFullProcessImageNameW(
                    _handle,                // Process handle
                    0,                      // Flags -> 0 for Win32 Path
                    &buffer[0],             // ImagePath
                    &cch_written);          // Number of written characters.
                if (success == TRUE)
                    return std::wstring(&buffer[0], cch_written);

                DWORD err = GetLastError();
                if (err == ERROR_INSUFFICIENT_BUFFER)
                {
                    // Win32 path length is limited within half of USHORT (UNICODE_STRING.MaxLength / sizeof(WCHAR))
                    if (buffer.size() > MAXSHORT)
                        throw std::runtime_error("invalid size");
                    buffer.resize(buffer.size() * 2);
                }
                else
                    throw nstd::runtime_error("query error: %d", err);
            }
        }

        std::wstring process::command_line() const
        {
            // Get the address of the PEB
            PROCESS_BASIC_INFORMATION pbi = {};
            NTSTATUS status = NtQueryInformationProcess(
                _handle,                    // Process handle
                ProcessBasicInformation,    // Information class
                &pbi,                       // Information
                sizeof(pbi),                // Information size in bytes.
                NULL);                      // Returned size in bytes -> Don't care
            if (status != STATUS_SUCCESS)
                throw nstd::runtime_error("query pbi status: %X", status);
            if (pbi.PebBaseAddress == NULL)
                throw nstd::runtime_error("peb address null");

            // Get the address of the process parameters in the PEB
            PEB peb = {};
            if (ReadProcessMemory(_handle, pbi.PebBaseAddress, &peb, sizeof(peb), NULL) == FALSE)
                throw nstd::runtime_error("read peb error: %X", GetLastError());

            // Get the command line arguments from the process parameters
            RTL_USER_PROCESS_PARAMETERS params = {};
            if (ReadProcessMemory(_handle, peb.ProcessParameters, &params, sizeof(params), NULL) == FALSE)
                throw nstd::runtime_error("read process parameters error: %d", GetLastError());

            void* command_line_addr = params.CommandLine.Buffer;
            size_t command_line_cch = params.CommandLine.Length / sizeof(WCHAR);
            std::vector<WCHAR> buffer(command_line_cch);
            if (ReadProcessMemory(_handle, command_line_addr, buffer.data(), command_line_cch * sizeof(WCHAR), NULL) == FALSE)
                throw nstd::runtime_error("read process command line error: %d", GetLastError());
            return std::wstring(buffer.data(), buffer.size());
        }

        bool process::search_memory(const void* data, size_t size) const
        {
            if (data == nullptr)
                throw std::invalid_argument("null data");

            SYSTEM_INFO si;
            GetSystemInfo(&si);

            MEMORY_BASIC_INFORMATION info;
            std::vector<uint8_t> chunk(0x10000);
            void* p = nullptr;
            while (p < si.lpMaximumApplicationAddress)
            {
                if (VirtualQueryEx(_handle, p, &info, sizeof(info)) != sizeof(info))
                    break;
                p = info.BaseAddress;
                if (info.AllocationProtect != 0 &&
                    info.Protect != 0 &&
                    info.State != MEM_RESERVE)
                {
                    chunk.resize(info.RegionSize);
                    SIZE_T read;
                    if (ReadProcessMemory(_handle, p, &chunk[0], info.RegionSize, &read))
                        for (size_t i = 0; i < (read - size); ++i)
                            if (memcmp(data, &chunk[i], size) == 0)
                                return true;
                }
                p = reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(p) + info.RegionSize);
            }
            return false;
        }
    }
}

namespace windows
{
    namespace registry
    {
        static std::map<std::wstring, HKEY> root_keys = {
            {L"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT },
            {L"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE },
            {L"HKEY_CURRENT_USER", HKEY_CURRENT_USER },
            {L"HKEY_USERS", HKEY_USERS },
        };

        key::key(const std::wstring& path, DWORD desired_access)
        {
            // Trim \ character from the end of the path
            _path = std::wstring(path.begin(), std::find_if(path.begin(), path.end(), [](wchar_t ch) { return ch == L'\\'; }));

            auto root_end = path.find(L"\\");
            std::wstring root = root_end == std::wstring::npos ? path : path.substr(0, root_end);
            std::wstring sub = root_end == std::wstring::npos ? L"" : path.substr(root_end + 1);

            auto ite = root_keys.find(root);
            if (ite == root_keys.end())
                throw nstd::invalid_argument("invalid root key");
            auto status = RegOpenKeyExW(ite->second, sub.c_str(), 0, desired_access, &_handle);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("open key error: %d", status);
        };
        
        key::key(HKEY&& key, std::wstring&& path) noexcept : _handle(key), _path(std::move(path)) { key = NULL; }

        key::key(key&& key) noexcept : _handle(key._handle), _path(std::move(key._path))
        {
            key._handle = NULL;
            key._path.clear();
        }

        key::~key() { if (_handle != NULL) RegCloseKey(_handle); }

        const std::wstring& key::get_path() const noexcept { return _path; }

        key key::open_key(const std::wstring& key_name, DWORD desired_access) const
        {
            if (key_name.find(L"\\") != std::wstring::npos)
                throw std::invalid_argument("invalid name");

            HKEY handle;
            auto status = RegOpenKeyExW(_handle, key_name.c_str(), 0, desired_access, &handle);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("open sub key error: %d", status);
            // Clean-up
            defer { if (handle != NULL) CloseHandle(handle); };

            return key(std::move(handle), _path + L"\\" + key_name);
        }

        key key::create_key(const std::wstring& key_name, DWORD desired_access)
        {
            if (key_name.find(L"\\") != std::wstring::npos)
                throw std::invalid_argument("invalid name");

            HKEY handle;
            auto status = RegCreateKeyExW(_handle, key_name.c_str(), NULL, NULL, 0, desired_access, NULL, &handle, NULL);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("create sub key error: %d", status);
            return key(std::move(handle), _path + L"\\" + key_name);
        }

        void key::delete_key(const std::wstring& key_name)
        {                
            auto status = RegDeleteTreeW(_handle, key_name.c_str());
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("delete key error: %d", status);
        }

        void key::delete_value(const std::wstring& value_name)
        {
            auto status = RegDeleteKeyValueW(_handle, NULL, value_name.c_str());
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("delete value error: %d", status);
        }
        
        void key::set_dword(const std::wstring& value_name, DWORD value)
        {
            auto status = RegSetKeyValueW(_handle, NULL, value_name.c_str(), REG_DWORD, &value, sizeof(value));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value dword error: %d", status);
        }

        void key::set_string(const std::wstring& value_name, const std::wstring& value)
        {
            // Size in bytes includes null terminating character.
            size_t cb_size = (value.length() + 1) * sizeof(wchar_t);
            if (cb_size > MAXDWORD)
                throw std::invalid_argument("string too long");
            auto status = RegSetKeyValueW(_handle, NULL, value_name.c_str(), REG_SZ, value.c_str(), static_cast<DWORD>(cb_size));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value string error: %d", status);
        }

        void key::set_expand_string(const std::wstring& value_name, const std::wstring& value)
        {
            size_t cb_size = (value.length() + 1) * sizeof(wchar_t);
            if (cb_size > MAXDWORD)
                throw std::invalid_argument("string too long");
            auto status = RegSetKeyValueW(_handle, NULL, value_name.c_str(), REG_EXPAND_SZ, value.c_str(), static_cast<DWORD>(cb_size));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value expand string error: %d", status);
        }

        void key::set_multi_string(const std::wstring& value_name, const std::list<std::wstring>& values)
        {
            size_t cb_size = 2;
            for (auto& value : values)
                cb_size += (value.length() + 1) * sizeof(wchar_t);
            if (cb_size > MAXDWORD)
                throw std::invalid_argument("string too long");

            auto buffer = std::make_unique<uint8_t[]>(cb_size);
            uint8_t* ptr = buffer.get();
            for (auto& value : values)
            {
                size_t size_to_write = (value.length() + 1) * sizeof(wchar_t);
                std::memcpy(ptr, value.c_str(), size_to_write);                
                ptr += size_to_write;
            }
            // Write last terminating character
            *reinterpret_cast<wchar_t*>(ptr) = NULL;

            auto status = RegSetKeyValueW(_handle, NULL, value_name.c_str(), REG_MULTI_SZ, buffer.get(), static_cast<DWORD>(cb_size));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value multi string error: %d", status);
        }

        DWORD key::get_dword(const std::wstring& value_name) const
        {
            DWORD ret;
            DWORD cb_size = sizeof(DWORD);
            auto status = RegGetValueW(_handle, NULL, value_name.c_str(), RRF_RT_REG_DWORD, NULL, reinterpret_cast<LPBYTE>(&ret), &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value dword error: %d", status);
            return ret;
        }

        std::wstring key::get_string(const std::wstring& value_name) const
        {
            DWORD type;
            DWORD cb_size = 0;
            auto status = RegQueryValueExW(_handle, value_name.c_str(), NULL, NULL, NULL, &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value error: %d", status);

            std::wstring ret((cb_size+1) / 2, 0);
            status = RegQueryValueExW(_handle, value_name.c_str(), NULL, &type, reinterpret_cast<LPBYTE>(&ret[0]), &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value error: %d", status);
            if (type != REG_SZ)
                throw nstd::runtime_error("type mismatch");
            
            ret.resize(wcsnlen(ret.c_str(), cb_size / 2));
            return ret;
        }

        std::wstring key::get_expand_string(const std::wstring& value_name, bool expand) const
        {
            DWORD cb_size = 0;
            auto status = RegQueryValueExW(_handle, value_name.c_str(), NULL, NULL, NULL, &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value error: %d", status);

            DWORD type;
            std::wstring ret((cb_size + 1) / 2, 0);
            status = RegQueryValueExW(_handle, value_name.c_str(), NULL, &type, reinterpret_cast<LPBYTE>(&ret[0]), &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read expand string error: %d", status);
            if (type != REG_EXPAND_SZ)
                throw nstd::runtime_error("type mismatch");
            ret.resize(wcsnlen(ret.c_str(), cb_size / 2));

            if (expand)
            {
                DWORD size = 4096;
                std::wstring temp(size, 0);
                do
                {
                    DWORD needed = ExpandEnvironmentStringsW(ret.c_str(), &temp[0], size);
                    if (needed == 0)
                        throw windows::registry::expand_error(std::to_string(GetLastError()));
                    if (needed <= size)
                    {
                        temp.resize(needed-1);
                        break;
                    }
                    size = (size > MAXDWORD / 2) ? MAXDWORD : size * 2;
                    temp.resize(size);
                } while (true);
                ret = std::move(temp);
            }

            return ret;
        }

        std::list<std::wstring> key::get_multi_string(const std::wstring& value_name) const
        {
            DWORD cb_size = 0;
            auto status = RegQueryValueExW(_handle, value_name.c_str(), NULL, NULL, NULL, &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value error: %d", status);

            auto buffer = std::make_unique<uint8_t[]>(cb_size);
            status = RegQueryValueExW(_handle, value_name.c_str(), NULL, NULL, buffer.get(), &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value error: %d", status);

            uint8_t* ptr = buffer.get();
            std::list<std::wstring> ret;
            while (*reinterpret_cast<wchar_t*>(ptr) != NULL)
            {
                ret.emplace_back(reinterpret_cast<wchar_t*>(ptr));
                ptr += (ret.back().length()+1) * sizeof(wchar_t);
            }
            return ret;
        }
        
        std::list<std::wstring> key::list_subkeys() const
        {
            DWORD count = 0;
            DWORD max_len = 0;
            auto error = RegQueryInfoKeyW(
                _handle,
                NULL,
                NULL,
                NULL,
                &count,
                &max_len,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL);
            if (error != ERROR_SUCCESS)
                throw nstd::runtime_error("query key info error: %d", error);

            std::list<std::wstring> ret;
            std::vector<wchar_t> name(max_len + 1);
            for (DWORD i = 0; i < count; i++)
            {
                DWORD len = max_len + 1;
                error = RegEnumKeyExW(
                    _handle,
                    i,
                    &name[0],
                    &len,
                    NULL,
                    NULL,
                    NULL,
                    NULL);
                if (error != ERROR_SUCCESS)
                    continue;

                ret.emplace_back(&name[0], len);
            }
            return ret;
        }

        std::list<key::value_info> key::list_values() const
        {
            DWORD count = 0;
            DWORD max_len = 0;
            auto error = RegQueryInfoKeyW(
                _handle,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                &count,
                &max_len,
                NULL,
                NULL,
                NULL);
            if (error != ERROR_SUCCESS)
                throw nstd::runtime_error("list values error: %d", error);

            std::list<value_info> ret;
            std::vector<wchar_t> name(max_len + 1);
            for (DWORD i = 0; i < count; i++)
            {
                DWORD len = max_len + 1;
                DWORD type;
                error = RegEnumValueW(
                    _handle,
                    i,
                    &name[0],
                    &len,
                    NULL,
                    &type,
                    NULL,
                    NULL);
                if (error != ERROR_SUCCESS)
                    continue;

                value_info info;
                info.name = std::wstring(&name[0], len);
                info.type = type;
                ret.emplace_back(std::move(info));
            }
            return ret;
        }
    }
}

namespace windows
{
    namespace user
    {
        bool is_admin()
        {
            BOOL isAdmin = FALSE;
            PSID adminGroup = NULL;

            // Create a SID for the Administrators group.
            SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
            if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup) == FALSE)
                throw nstd::runtime_error("init std error: %d", GetLastError());
            defer{ FreeSid(adminGroup); };

            // Check whether the token of the calling thread is a member of the Administrators group.
            if (CheckTokenMembership(NULL, adminGroup, &isAdmin) == FALSE)
                throw nstd::runtime_error("check membership error: %d", GetLastError());

            return isAdmin == TRUE;
        }
    }
}

namespace windows
{
    namespace event_log
    {
        void setup(const std::wstring& group, const std::wstring& source, DWORD bytes)
        {
            auto key = windows::registry::key(LR"(HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog)", REG_CREATED_NEW_KEY).create_key(group);
            key.set_dword(L"Retention", 0);
            key.set_dword(L"MaxSize", bytes);

            std::list<std::wstring> sources = {source};
            try
            {
                for (auto& src : key.get_multi_string(L"Sources"))
                    if (src != source)
                        sources.emplace_back(std::move(src));
            } catch (...) {}
            key.set_multi_string(L"Sources", sources);

            auto sub = key.create_key(source);
            sub.set_dword(L"CustomSource", 1);
            sub.set_expand_string(L"EventMessageFile", LR"(%SystemRoot%\System32\EventCreate.exe)");
            sub.set_dword(L"TypesSupported", EVENTLOG_SUCCESS | EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE | EVENTLOG_AUDIT_SUCCESS | EVENTLOG_AUDIT_FAILURE);
        }

        void log::report(WORD type, const std::string& log)
        {
            const char* s[] = { log.c_str() };
            WORD len = log.length() >= 65535 ? 65535 : static_cast<WORD>(log.length());
            if (ReportEventA(_event_source, type, 0, 1, NULL, 1, len, s, (PVOID) log.c_str()) != TRUE)
                throw nstd::runtime_error("ReportEventA error: %d", GetLastError());
        }

        log::log(const std::wstring& source)
        {
            _event_source = RegisterEventSourceW(NULL, source.c_str());
            if (_event_source == NULL)
                throw nstd::runtime_error("RegisterEventSource(%ws) error: %d", source.c_str(), GetLastError());
        }

        log::~log()
        {
            DeregisterEventSource(_event_source);
        }


    }
}