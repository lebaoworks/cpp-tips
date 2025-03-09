#include "disk.hpp"

// Standard Windows Headers:
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// Precompiled Headers:
#include "../nstd.hpp"

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