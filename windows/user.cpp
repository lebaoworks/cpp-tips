#include "user.hpp"

// Standard Windows Headers:
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// Precompiled Headers:
#include "../nstd.hpp"

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