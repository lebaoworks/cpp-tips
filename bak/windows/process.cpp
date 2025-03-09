#include "process.hpp"

// Standard Windows Headers:
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")
#include <Winternl.h>
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0
#endif

// Precompiled Headers:
#include "../nstd.hpp"

namespace windows
{
    namespace process
    {
        std::list<process_info> list()
        {
            auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                throw nstd::runtime_error("snapshot process error %d", GetLastError());
            defer{ CloseHandle(snapshot); };

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
            auto buffer = std::make_unique<wchar_t[]>(MAX_PATH);
            DWORD buffer_size = MAX_PATH;
            while (true)
            {
                DWORD size = buffer_size;
                BOOL success = QueryFullProcessImageNameW(
                    _handle,                // Process handle
                    0,                      // Flags -> 0 for Win32 Path
                    buffer.get(),           // ImagePath
                    &size);                 // Number of written characters.
                if (success == TRUE)
                    return std::wstring(buffer.get(), size);

                DWORD err = GetLastError();
                if (err == ERROR_INSUFFICIENT_BUFFER)
                {
                    // Win32 path length is limited within half of USHORT (UNICODE_STRING.MaxLength / sizeof(WCHAR))
                    if (buffer_size > MAXSHORT)
                        throw std::runtime_error("invalid size");
                    buffer_size *= 2;
                    buffer = std::make_unique<wchar_t[]>(buffer_size);
                }
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
            auto buffer = std::make_unique<WCHAR[]>(command_line_cch);
            if (ReadProcessMemory(_handle, command_line_addr, buffer.get(), command_line_cch * sizeof(WCHAR), NULL) == FALSE)
                throw nstd::runtime_error("read process command line error: %d", GetLastError());
            return std::wstring(buffer.get(), command_line_cch);
        }

        bool process::search_memory(const void* data, size_t size) const
        {
            if (data == nullptr)
                throw std::invalid_argument("null data");

            SYSTEM_INFO si;
            GetSystemInfo(&si);

            MEMORY_BASIC_INFORMATION info;
            auto buffer = std::make_unique<uint8_t[]>(0x10000);
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
                    buffer = std::make_unique<uint8_t[]>(info.RegionSize);
                    SIZE_T read;
                    if (ReadProcessMemory(_handle, p, buffer.get(), info.RegionSize, &read))
                        for (size_t i = 0; i < (read - size); ++i)
                            if (memcmp(data, &buffer[i], size) == 0)
                                return true;
                }
                p = reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(p) + info.RegionSize);
            }
            return false;
        }
    }
}