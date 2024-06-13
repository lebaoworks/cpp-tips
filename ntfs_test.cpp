#include "ntfs.hpp"

#include "utest.h"

UTEST(ntfs, read_c)
{
    NTFS::volume::volume('C');
}
