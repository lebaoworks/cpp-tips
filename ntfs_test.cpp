#include "ntfs.hpp"

#include "utest.h"

#include "windows.hpp"

UTEST(ntfs, mft)
{
    if (windows::user::is_admin() == false)
        UTEST_SKIP("test session is not running by admin user");

    NTFS::volume::volume('C');
}
