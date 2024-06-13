#pragma once
#include "nstd.hpp"

#pragma pack(push, 1)

// Reference:
//      https://www.codeproject.com/Articles/81456/An-NTFS-Parser-Lib
//      http://www.kcall.co.uk/ntfs/index.html
namespace NTFS
{
    struct VolumeBootRecord
    {
        static constexpr const char* NTFSSignature = "NTFS    ";

        // Jump instruction
        uint8_t     Jmp[3];

        // Signature
        uint8_t     Signature[8];

        // Bios Partition Block
        uint16_t    BytesPerSector;
        uint8_t     SectorsPerCluster;
        uint16_t    ReservedSectors;
        uint8_t     Zeros1[3];
        uint16_t    NotUsed1;
        uint8_t     MediaDescriptor;
        uint16_t    Zeros2;
        uint16_t    SectorsPerTrack;
        uint16_t    NumberOfHeads;
        uint32_t    HiddenSectors;
        uint32_t    NotUsed2;

        // Extended Bios Partition Block
        uint32_t    NotUsed3;
        uint64_t    TotalSectors;
        uint64_t    LCN_MFT;
        uint64_t    LCN_MFTMirr;
        uint32_t    ClustersPerFileRecord;
        uint32_t    ClustersPerIndexBlock;
        uint8_t     VolumeSerialNumber[8];
        uint32_t    NotUsed4;

        // Boot code
        uint8_t        Code[426];

        // End of Sector Marker -> 0xAA55
        uint8_t        _AA;
        uint8_t        _55;
    };

    static_assert (sizeof(VolumeBootRecord) == 512, "Size of VolumeBootRecord is not 512");

    // MFT Indexes
#define    MFT_IDX_MFT                0
#define    MFT_IDX_MFT_MIRR        1
#define    MFT_IDX_LOG_FILE        2
#define    MFT_IDX_VOLUME            3
#define    MFT_IDX_ATTR_DEF        4
#define    MFT_IDX_ROOT            5
#define    MFT_IDX_BITMAP            6
#define    MFT_IDX_BOOT            7
#define    MFT_IDX_BAD_CLUSTER        8
#define    MFT_IDX_SECURE            9
#define    MFT_IDX_UPCASE            10
#define    MFT_IDX_EXTEND            11
#define    MFT_IDX_RESERVED12        12
#define    MFT_IDX_RESERVED13        13
#define    MFT_IDX_RESERVED14        14
#define    MFT_IDX_RESERVED15        15
#define    MFT_IDX_USER            16

    /******************************
            File Record
        ---------------------
        | File Record Header|
        ---------------------
        |    Attribute 1    |
        ---------------------
        |    Attribute 2    |
        ---------------------
        |      ......       |
        ---------------------
        |     0xFFFFFFFF    |
        ---------------------
    *******************************/

#define    FILE_RECORD_MAGIC        'ELIF'
#define    FILE_RECORD_FLAG_INUSE   0x01    // File record is in use
#define    FILE_RECORD_FLAG_DIR     0x02    // File record is a directory

    struct FileRecordHeader
    {
        uint32_t    Magic;          // "FILE"
        uint16_t    OffsetOfUS;     // Offset of Update Sequence
        uint16_t    SizeOfUS;       // Size in words of Update Sequence Number & Array
        uint64_t    LSN;            // $LogFile Sequence Number
        uint16_t    SeqNo;          // Sequence number
        uint16_t    Hardlinks;      // Hard link count
        uint16_t    OffsetOfAttr;   // Offset of the first Attribute
        uint16_t    Flags;          // Flags
        uint32_t    RealSize;       // Real size of the FILE record
        uint32_t    AllocSize;      // Allocated size of the FILE record
        uint64_t    RefToBase;      // File reference to the base FILE record
        uint16_t    NextAttrId;     // Next Attribute Id
        uint16_t    Align;          // Align to 4 uint8_t boundary
        uint32_t    RecordNo;       // Number of this MFT Record
    };

    /******************************
        Attribute
    --------------------
    | Attribute Header |
    --------------------
    |  Attribute Data  |
    --------------------
*******************************/

// Attribute Header

#define    ATTR_TYPE_STANDARD_INFORMATION    0x10
#define    ATTR_TYPE_ATTRIBUTE_LIST        0x20
#define    ATTR_TYPE_FILE_NAME                0x30
#define    ATTR_TYPE_OBJECT_ID                0x40
#define    ATTR_TYPE_SECURITY_DESCRIPTOR    0x50
#define    ATTR_TYPE_VOLUME_NAME            0x60
#define    ATTR_TYPE_VOLUME_INFORMATION    0x70
#define    ATTR_TYPE_DATA                    0x80
#define    ATTR_TYPE_INDEX_ROOT            0x90
#define    ATTR_TYPE_INDEX_ALLOCATION        0xA0
#define    ATTR_TYPE_BITMAP                0xB0
#define    ATTR_TYPE_REPARSE_POINT            0xC0
#define    ATTR_TYPE_EA_INFORMATION        0xD0
#define    ATTR_TYPE_EA                    0xE0
#define    ATTR_TYPE_LOGGED_UTILITY_STREAM    0x100

#define    ATTR_FLAG_COMPRESSED            0x0001
#define    ATTR_FLAG_ENCRYPTED                0x4000
#define    ATTR_FLAG_SPARSE                0x8000

    struct AttributeHeader
    {
        uint32_t        Type;           // Attribute Type
        uint32_t        TotalSize;      // Length (including this header)
        uint8_t         NonResident;    // 0 - resident, 1 - non resident
        uint8_t         NameLength;     // name length in words
        uint16_t        NameOffset;     // offset to the name
        uint16_t        Flags;          // Flags
        uint16_t        Id;             // Attribute Id
    };

    struct AttributeHeaderResident
    {
        AttributeHeader     Header;         // Common data structure
        uint32_t            AttrSize;       // Length of the attribute body
        uint16_t            AttrOffset;     // Offset to the Attribute
        uint8_t             IndexedFlag;    // Indexed flag
        uint8_t             Padding;        // Padding
    };

    struct AttributeHeaderNonResident
    {
        AttributeHeader     Header;         // Common data structure
        uint64_t            StartVCN;       // Starting VCN
        uint64_t            LastVCN;        // Last VCN
        uint16_t            DataRunOffset;  // Offset to the Data Runs
        uint16_t            CompUnitSize;   // Compression unit size
        uint32_t            Padding;        // Padding
        uint64_t            AllocSize;      // Allocated size of the attribute
        uint64_t            RealSize;       // Real size of the attribute
        uint64_t            IniSize;        // Initialized data size of the stream 
    };


    // Attribute: STANDARD_INFORMATION

#define    ATTR_STDINFO_PERMISSION_READONLY    0x00000001
#define    ATTR_STDINFO_PERMISSION_HIDDEN        0x00000002
#define    ATTR_STDINFO_PERMISSION_SYSTEM        0x00000004
#define    ATTR_STDINFO_PERMISSION_ARCHIVE        0x00000020
#define    ATTR_STDINFO_PERMISSION_DEVICE        0x00000040
#define    ATTR_STDINFO_PERMISSION_NORMAL        0x00000080
#define    ATTR_STDINFO_PERMISSION_TEMP        0x00000100
#define    ATTR_STDINFO_PERMISSION_SPARSE        0x00000200
#define    ATTR_STDINFO_PERMISSION_REPARSE        0x00000400
#define    ATTR_STDINFO_PERMISSION_COMPRESSED    0x00000800
#define    ATTR_STDINFO_PERMISSION_OFFLINE        0x00001000
#define    ATTR_STDINFO_PERMISSION_NCI            0x00002000
#define    ATTR_STDINFO_PERMISSION_ENCRYPTED    0x00004000

    struct AttributeStandardInformation
    {
        uint64_t    CreateTime;     // File creation time
        uint64_t    AlterTime;      // File altered time
        uint64_t    MFTTime;        // MFT changed time
        uint64_t    ReadTime;       // File read time
        uint32_t    Permission;     // Dos file permission
        uint32_t    MaxVersionNo;   // Maxim number of file versions
        uint32_t    VersionNo;      // File version number
        uint32_t    ClassId;        // Class Id
        uint32_t    OwnerId;        // Owner Id
        uint32_t    SecurityId;     // Security Id
        uint64_t    QuotaCharged;   // Quota charged
        uint64_t    USN;            // USN Journel
    };


    // Attribute: ATTRIBUTE_LIST

    struct AttributeList
    {
        uint32_t    AttrType;        // Attribute type
        uint16_t    RecordSize;        // Record length
        uint8_t     NameLength;        // Name length in characters
        uint8_t     NameOffset;        // Name offset
        uint64_t    StartVCN;        // Start VCN
        uint64_t    BaseRef;        // Base file reference to the attribute
        uint16_t    AttrId;            // Attribute Id
    };

    // Attribute: FILE_NAME

#define    ATTR_FILENAME_FLAG_READONLY        0x00000001
#define    ATTR_FILENAME_FLAG_HIDDEN        0x00000002
#define    ATTR_FILENAME_FLAG_SYSTEM        0x00000004
#define    ATTR_FILENAME_FLAG_ARCHIVE        0x00000020
#define    ATTR_FILENAME_FLAG_DEVICE        0x00000040
#define    ATTR_FILENAME_FLAG_NORMAL        0x00000080
#define    ATTR_FILENAME_FLAG_TEMP            0x00000100
#define    ATTR_FILENAME_FLAG_SPARSE        0x00000200
#define    ATTR_FILENAME_FLAG_REPARSE        0x00000400
#define    ATTR_FILENAME_FLAG_COMPRESSED    0x00000800
#define    ATTR_FILENAME_FLAG_OFFLINE        0x00001000
#define    ATTR_FILENAME_FLAG_NCI            0x00002000
#define    ATTR_FILENAME_FLAG_ENCRYPTED    0x00004000
#define    ATTR_FILENAME_FLAG_DIRECTORY    0x10000000
#define    ATTR_FILENAME_FLAG_INDEXVIEW    0x20000000

#define    ATTR_FILENAME_NAMESPACE_POSIX    0x00
#define    ATTR_FILENAME_NAMESPACE_WIN32    0x01
#define    ATTR_FILENAME_NAMESPACE_DOS        0x02

    struct AttributeFileName
    {
        uint64_t    ParentRef;        // File reference to the parent directory
        uint64_t    CreateTime;        // File creation time
        uint64_t    AlterTime;        // File altered time
        uint64_t    MFTTime;        // MFT changed time
        uint64_t    ReadTime;        // File read time
        uint64_t    AllocSize;        // Allocated size of the file
        uint64_t    RealSize;        // Real size of the file
        uint32_t    Flags;            // Flags
        uint32_t    ER;                // Used by EAs and Reparse
        uint8_t     NameLength;        // Filename length in characters
        uint8_t     NameSpace;        // Filename space
        uint16_t    Name[1];        // Filename
    };


    // Attribute: VOLUME_INFORMATION

#define    ATTR_VOLINFO_FLAG_DIRTY        0x0001    // Dirty
#define    ATTR_VOLINFO_FLAG_RLF        0x0002    // Resize logfile
#define    ATTR_VOLINFO_FLAG_UOM        0x0004    // Upgrade on mount
#define    ATTR_VOLINFO_FLAG_MONT        0x0008    // Mounted on NT4
#define    ATTR_VOLINFO_FLAG_DUSN        0x0010    // Delete USN underway
#define    ATTR_VOLINFO_FLAG_ROI        0x0020    // Repair object Ids
#define    ATTR_VOLINFO_FLAG_MBC        0x8000    // Modified by chkdsk

    struct AttributeVolumeInformation
    {
        uint8_t     Reserved1[8];    // Always 0 ?
        uint8_t     MajorVersion;    // Major version
        uint8_t     MinorVersion;    // Minor version
        uint16_t    Flags;            // Flags
        uint8_t     Reserved2[4];    // Always 0 ?
    };


    // Attribute: INDEX_ROOT
    /******************************
            INDEX_ROOT
        ---------------------
        | Index Root Header |
        ---------------------
        |    Index Header   |
        ---------------------
        |    Index Entry    |
        ---------------------
        |    Index Entry    |
        ---------------------
        |      ......       |
        ---------------------
    *******************************/

#define    ATTR_INDEXROOT_FLAG_SMALL    0x00    // Fits in Index Root File Record
#define    ATTR_INDEXROOT_FLAG_LARGE    0x01    // Index Allocation and Bitmap needed

    struct AttributeIndexRoot
    {
        // Index Root Header
        uint32_t        AttrType;            // Attribute type (ATTR_TYPE_FILE_NAME: Directory, 0: Index View)
        uint32_t        CollRule;            // Collation rule
        uint32_t        IBSize;                // Size of index block
        uint8_t        ClustersPerIB;        // Clusters per index block (same as BPB?)
        uint8_t        Padding1[3];        // Padding
        // Index Header
        uint32_t        EntryOffset;        // Offset to the first index entry, relative to this address(0x10)
        uint32_t        TotalEntrySize;        // Total size of the index entries
        uint32_t        AllocEntrySize;        // Allocated size of the index entries
        uint8_t        Flags;                // Flags
        uint8_t        Padding2[3];        // Padding
    };


    // INDEX ENTRY

#define    INDEX_ENTRY_FLAG_SUBNODE    0x01    // Index entry points to a sub-node
#define    INDEX_ENTRY_FLAG_LAST        0x02    // Last index entry in the node, no Stream

    struct IndexEntry
    {
        uint64_t    FileReference;    // Low 6B: MFT record index, High 2B: MFT record sequence number
        uint16_t        Size;            // Length of the index entry
        uint16_t        StreamSize;        // Length of the stream
        uint8_t        Flags;            // Flags
        uint8_t        Padding[3];        // Padding
        uint8_t        Stream[1];        // Stream
        // VCN of the sub node in Index Allocation, Offset = Size - 8
    };


    // INDEX BLOCK
    /******************************
             INDEX_BLOCK
        -----------------------
        |  Index Block Header |
        -----------------------
        |     Index Header    |
        -----------------------
        |     Index Entry     |
        -----------------------
        |     Index Entry     |
        -----------------------
        |       ......        |
        -----------------------
    *******************************/

#define    INDEX_BLOCK_MAGIC        'XDNI'

    struct IndexBlock
    {
        // Index Block Header
        uint32_t        Magic;            // "INDX"
        uint16_t        OffsetOfUS;        // Offset of Update Sequence
        uint16_t        SizeOfUS;        // Size in words of Update Sequence Number & Array
        uint64_t    LSN;            // $LogFile Sequence Number
        uint64_t    VCN;            // VCN of this index block in the index allocation
        // Index Header
        uint32_t        EntryOffset;    // Offset of the index entries, relative to this address(0x18)
        uint32_t        TotalEntrySize;    // Total size of the index entries
        uint32_t        AllocEntrySize;    // Allocated size of index entries
        uint8_t        NotLeaf;        // 1 if not leaf node (has children)
        uint8_t        Padding[3];        // Padding
    };

}

#pragma pack(pop)

#include <iostream>

#include <cctype>
#include <stdexcept>
#include <string>
#include <memory>

#ifdef _WIN32
namespace NTFS
{
    class volume;
    class file_record;


    struct file_record_data
    {
    private:
        uint8_t* _raw;
    public:
        file_record_data(size_t size) : _raw(new uint8_t[size]) {}
        file_record_data(const file_record_data& other) = delete;
        file_record_data(file_record_data&& old) : _raw(old._raw) { old._raw = nullptr; }
        ~file_record_data() { if (_raw != nullptr) delete[] _raw; }

        FileRecordHeader* header() { return reinterpret_cast<FileRecordHeader*>(_raw); }
    };


    class volume
    {
        friend class file_record;
    private:
        HANDLE _handle;
        uint16_t _sector_size;
        uint32_t _cluster_size;
        uint32_t _file_record_size;
        uint32_t _index_block_size;
        uint64_t _mft_offset;

    public:
        volume(char volume_letter)
        {
            bool success = false;

            if (isalpha(volume_letter) == 0)
                throw std::invalid_argument("invalid volume letter");

            // Open raw volume
            auto raw_path = nstd::format("\\\\.\\%c:", volume_letter);
            _handle = CreateFileA(
                raw_path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_READONLY,
                NULL);
            if (_handle == INVALID_HANDLE_VALUE)
                throw nstd::runtime_error("open raw volume error: %d", GetLastError());
            defer{ if (success == false) CloseHandle(_handle); };

            // Read the first sector (boot sector)
            VolumeBootRecord vbr;
            DWORD num;

            if (ReadFile(_handle, &vbr, 512, &num, NULL) == FALSE)
                throw nstd::runtime_error("read boot record error: %d", GetLastError());
            if (num != 512)
                throw nstd::runtime_error("read boot record not complete");
            if (memcmp(vbr.Signature, vbr.NTFSSignature, 8) != 0)
                throw nstd::runtime_error("signature mismatch");

            _sector_size = vbr.BytesPerSector;
            _cluster_size = _sector_size * vbr.SectorsPerCluster;

            int sz = (char)vbr.ClustersPerFileRecord;
            _file_record_size = (sz > 0) ? _cluster_size * sz : 1 << (-sz);

            sz = (char)vbr.ClustersPerIndexBlock;
            _index_block_size = (sz > 0) ? _cluster_size * sz : 1 << (-sz);

            _mft_offset = vbr.LCN_MFT * _cluster_size;

            // Read volume information
            auto file_record = read_file_record(MFT_IDX_VOLUME);
            if (file_record.header()->Magic == FILE_RECORD_MAGIC)
            {
                // Patch US
                WORD* usnaddr = (WORD*)((BYTE*)file_record.header() + file_record.header()->OffsetOfUS);
                WORD usn = *usnaddr;
                WORD* usarray = usnaddr + 1;
                patch_us((WORD*)file_record.header(), _file_record_size/ _sector_size, usn, usarray);
            }

            // List attributes
            DWORD dataPtr = 0;	// guard if data exceeds FileRecordSize bounds
            AttributeHeader* ahc = (AttributeHeader*)((BYTE*)file_record.header() + file_record.header()->OffsetOfAttr);
            dataPtr += file_record.header()->OffsetOfAttr;

            while (ahc->Type != (DWORD)-1 && (dataPtr + ahc->TotalSize) <= _file_record_size)
            {
                printf("Attr: %d\n", ahc->Type);
                //if (!ParseAttr(ahc))	// Parse error
                //    return FALSE;

                //if (IsEncrypted() || IsCompressed())
                //{
                //    NTFS_TRACE("Compressed and Encrypted file not supported yet !\n");
                //    return FALSE;
                //}

                dataPtr += ahc->TotalSize;
                ahc = (AttributeHeader*)((BYTE*)ahc + ahc->TotalSize);	// next attribute
            }

            success = true;
        }
        ~volume()
        {
            CloseHandle(_handle);
        }

        file_record_data read_file_record(uint64_t file_ref)
        {
            if (file_ref < MFT_IDX_USER)
            {
                LARGE_INTEGER file_record_offset;
                file_record_offset.QuadPart = _mft_offset + (_file_record_size) * file_ref;
                file_record_offset.LowPart = SetFilePointer(_handle, file_record_offset.LowPart, &file_record_offset.HighPart, FILE_BEGIN);

                if (file_record_offset.LowPart == INVALID_SET_FILE_POINTER)
                    throw nstd::runtime_error("seek raw volume error: %d", GetLastError());

                file_record_data ret(_file_record_size);
                DWORD len;
                if (ReadFile(_handle, ret.header(), _file_record_size, &len, NULL) == FALSE)
                    throw nstd::runtime_error("read file ref %llu error: %d", file_ref, GetLastError());
                if (len != _file_record_size)
                    throw std::runtime_error("read file ref not complete");
                if (ret.header()->Magic != FILE_RECORD_MAGIC)
                    throw std::runtime_error("invalid file record");
                
                return ret;
            }
            else
                throw std::runtime_error("not supported");
        }
        
        // Verify US and update sectors
        void patch_us(WORD* sector, int sectors, WORD usn, WORD* usarray)
        {
            for (int i = 0; i < sectors; i++)
            {
                sector += ((_sector_size >> 1) - 1);
                if (*sector != usn)
                    throw std::runtime_error("invalid usn");
                *sector = usarray[i];	// Write back correct data
                sector++;
            }
        }


        //// Parse a single Attribute
        //// Return False on error
        //BOOL ParseAttr(AttributeHeader* ahc)
        //{
        //    DWORD attrIndex = ATTR_INDEX(ahc->Type);
        //    if (attrIndex < ATTR_NUMS)
        //    {
        //	    BOOL bDiscard = FALSE;
        //	    UserCallBack(attrIndex, ahc, &bDiscard);

        //	    if (!bDiscard)
        //	    {
        //		    BOOL bUnhandled = FALSE;
        //		    CAttrBase* attr = AllocAttr(ahc, &bUnhandled);
        //		    if (attr)
        //		    {
        //			    if (bUnhandled)
        //			    {
        //				    NTFS_TRACE1("Unhandled attribute: 0x%04X\n", ahc->Type);
        //			    }
        //			    AttrList[attrIndex].InsertEntry(attr);
        //			    return TRUE;
        //		    }
        //		    else
        //		    {
        //			    NTFS_TRACE1("Attribute Parse error: 0x%04X\n", ahc->Type);
        //			    return FALSE;
        //		    }
        //	    }
        //	    else
        //	    {
        //		    NTFS_TRACE1("User Callback has processed this Attribute: 0x%04X\n", ahc->Type);
        //		    return TRUE;
        //	    }
        //    }
        //    else
        //    {
        //	    NTFS_TRACE1("Invalid Attribute Type: 0x%04X\n", ahc->Type);
        //	    return FALSE;
        //    }
        //}

    };


    class file_record
    {

    };

    //class file_record
    //{
    //private:
    //    const volume& _volume;

    //    file_record(const volume& volume) : _volume(volume)
    //    {
    //        //_ASSERT(volume);
    //        //Volume = volume;
    //        //FileRecord = NULL;
    //        //FileReference = (ULONGLONG)-1;

    //        //ClearAttrRawCB();

    //        //// Default to parse all attributes
    //        //AttrMask = MASK_ALL;
    //    }

    //    ~file_record()
    //    {
    //        //ClearAttrs();

    //        //if (FileRecord)
    //        //    delete FileRecord;
    //    }

    //    // Read File Record, verify and patch the US (update sequence)
    //    BOOL ParseFileRecord(ULONGLONG fileRef)
    //    {
    //        FileRecordHeader* fr = ReadFileRecord(fileRef);
    //        if (fr == NULL)
    //        {
    //            NTFS_TRACE1("Cannot read file record %I64u\n", fileRef);

    //            FileReference = (ULONGLONG)-1;
    //        }
    //        else
    //        {
    //            FileReference = fileRef;

    //            if (fr->Magic == FILE_RECORD_MAGIC)
    //            {
    //                // Patch US
    //                WORD* usnaddr = (WORD*)((BYTE*)fr + fr->OffsetOfUS);
    //                WORD usn = *usnaddr;
    //                WORD* usarray = usnaddr + 1;
    //                if (PatchUS((WORD*)fr, Volume->FileRecordSize / Volume->SectorSize, usn, usarray))
    //                {
    //                    NTFS_TRACE1("File Record %I64u Found\n", fileRef);
    //                    FileRecord = fr;

    //                    return TRUE;
    //                }
    //                else
    //                {
    //                    NTFS_TRACE("Update Sequence Number error\n");
    //                }
    //            }
    //            else
    //            {
    //                NTFS_TRACE("Invalid file record\n");
    //            }

    //            delete fr;
    //        }

    //        return FALSE;
    //    }
    //    
    //    // Read File Record
    //    FileRecordHeader* ReadFileRecord(ULONGLONG& fileRef)
    //    {
    //        FileRecordHeader* fr = NULL;
    //        DWORD len;

    //        if (fileRef < MFT_IDX_USER)
    //            // || _volume.MFTData == NULL)
    //        {
    //            // Take as continuous disk allocation
    //            LARGE_INTEGER frAddr;
    //            frAddr.QuadPart = _volume._mft_offset + (_volume._file_record_size) * fileRef;
    //            frAddr.LowPart = SetFilePointer(_volume._handle, frAddr.LowPart, &frAddr.HighPart, FILE_BEGIN);

    //            if (frAddr.LowPart == INVALID_SET_FILE_POINTER)
    //                throw nstd::runtime_error("seek raw volume error: %d", GetLastError());

    //            fr = (FileRecordHeader*)new BYTE[_volume._file_record_size];

    //            if (ReadFile(Volume->hVolume, fr, Volume->FileRecordSize, &len, NULL)
    //                && len == Volume->FileRecordSize)
    //                return fr;
    //            else
    //            {
    //                delete fr;
    //                return NULL;
    //            }
    //        }
    //        else
    //        {
    //            // May be fragmented $MFT
    //            ULONGLONG frAddr;
    //            frAddr = (Volume->FileRecordSize) * fileRef;

    //            fr = (FileRecordHeader*)new BYTE[Volume->FileRecordSize];

    //            if (Volume->MFTData->ReadData(frAddr, fr, Volume->FileRecordSize, &len)
    //                && len == Volume->FileRecordSize)
    //                return fr;
    //            else
    //            {
    //                delete fr;
    //                return NULL;
    //            }
    //        }
    //    }

    //    //// Free all CAttr_xxx
    //    //void CFileRecord::ClearAttrs()
    //    //{
    //    //	for (int i = 0; i < ATTR_NUMS; i++)
    //    //	{
    //    //		AttrList[i].RemoveAll();
    //    //	}
    //    //}



    //    //// Call user defined Callback routines for an attribute
    //    //__inline void CFileRecord::UserCallBack(DWORD attType, ATTR_HEADER_COMMON* ahc, BOOL* bDiscard)
    //    //{
    //    //	*bDiscard = FALSE;

    //    //	if (AttrRawCallBack[attType])
    //    //		AttrRawCallBack[attType](ahc, bDiscard);
    //    //	else if (Volume->AttrRawCallBack[attType])
    //    //		Volume->AttrRawCallBack[attType](ahc, bDiscard);
    //    //}

    //    //CAttrBase* CFileRecord::AllocAttr(ATTR_HEADER_COMMON* ahc, BOOL* bUnhandled)
    //    //{
    //    //	switch (ahc->Type)
    //    //	{
    //    //	case ATTR_TYPE_STANDARD_INFORMATION:
    //    //		return new CAttr_StdInfo(ahc, this);

    //    //	case ATTR_TYPE_ATTRIBUTE_LIST:
    //    //		if (ahc->NonResident)
    //    //			return new CAttr_AttrList<CAttrNonResident>(ahc, this);
    //    //		else
    //    //			return new CAttr_AttrList<CAttrResident>(ahc, this);

    //    //	case ATTR_TYPE_FILE_NAME:
    //    //		return new CAttr_FileName(ahc, this);

    //    //	case ATTR_TYPE_VOLUME_NAME:
    //    //		return new CAttr_VolName(ahc, this);

    //    //	case ATTR_TYPE_VOLUME_INFORMATION:
    //    //		return new CAttr_VolInfo(ahc, this);

    //    //	case ATTR_TYPE_DATA:
    //    //		if (ahc->NonResident)
    //    //			return new CAttr_Data<CAttrNonResident>(ahc, this);
    //    //		else
    //    //			return new CAttr_Data<CAttrResident>(ahc, this);

    //    //	case ATTR_TYPE_INDEX_ROOT:
    //    //		return new CAttr_IndexRoot(ahc, this);

    //    //	case ATTR_TYPE_INDEX_ALLOCATION:
    //    //		return new CAttr_IndexAlloc(ahc, this);

    //    //	case ATTR_TYPE_BITMAP:
    //    //		if (ahc->NonResident)
    //    //			return new CAttr_Bitmap<CAttrNonResident>(ahc, this);
    //    //		else
    //    //			// Resident Bitmap may exist in a directory's FileRecord
    //    //			// or in $MFT for a very small volume in theory
    //    //			return new CAttr_Bitmap<CAttrResident>(ahc, this);

    //    //		// Unhandled Attributes
    //    //	default:
    //    //		*bUnhandled = TRUE;
    //    //		if (ahc->NonResident)
    //    //			return new CAttrNonResident(ahc, this);
    //    //		else
    //    //			return new CAttrResident(ahc, this);
    //    //	}
    //    //}

    

    //    //// Visit IndexBlocks recursivly to find a specific FileName
    //    //BOOL CFileRecord::VisitIndexBlock(const ULONGLONG& vcn, const _TCHAR* fileName, CIndexEntry& ieFound) const
    //    //{
    //    //	CAttr_IndexAlloc* ia = (CAttr_IndexAlloc*)FindFirstAttr(ATTR_TYPE_INDEX_ALLOCATION);
    //    //	if (ia == NULL)
    //    //		return FALSE;

    //    //	CIndexBlock ib;
    //    //	if (ia->ParseIndexBlock(vcn, ib))
    //    //	{
    //    //		CIndexEntry* ie = ib.FindFirstEntry();
    //    //		while (ie)
    //    //		{
    //    //			if (ie->HasName())
    //    //			{
    //    //				// Compare name
    //    //				int i = ie->Compare(fileName);
    //    //				if (i == 0)
    //    //				{
    //    //					ieFound = *ie;
    //    //					return TRUE;
    //    //				}
    //    //				else if (i < 0)		// fileName is smaller than IndexEntry
    //    //				{
    //    //					// Visit SubNode
    //    //					if (ie->IsSubNodePtr())
    //    //					{
    //    //						// Search in SubNode (IndexBlock), recursive call
    //    //						if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
    //    //							return TRUE;
    //    //					}
    //    //					else
    //    //						return FALSE;	// not found
    //    //				}
    //    //				// Just step forward if fileName is bigger than IndexEntry
    //    //			}
    //    //			else if (ie->IsSubNodePtr())
    //    //			{
    //    //				// Search in SubNode (IndexBlock), recursive call
    //    //				if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
    //    //					return TRUE;
    //    //			}

    //    //			ie = ib.FindNextEntry();
    //    //		}
    //    //	}

    //    //	return FALSE;
    //    //}

    //    //// Traverse SubNode recursivly in ascending order
    //    //// Call user defined callback routine once found an subentry
    //    //void CFileRecord::TraverseSubNode(const ULONGLONG& vcn, SUBENTRY_CALLBACK seCallBack) const
    //    //{
    //    //	CAttr_IndexAlloc* ia = (CAttr_IndexAlloc*)FindFirstAttr(ATTR_TYPE_INDEX_ALLOCATION);
    //    //	if (ia == NULL)
    //    //		return;

    //    //	CIndexBlock ib;
    //    //	if (ia->ParseIndexBlock(vcn, ib))
    //    //	{
    //    //		CIndexEntry* ie = ib.FindFirstEntry();
    //    //		while (ie)
    //    //		{
    //    //			if (ie->IsSubNodePtr())
    //    //				TraverseSubNode(ie->GetSubNodeVCN(), seCallBack);	// recursive call

    //    //			if (ie->HasName())
    //    //				seCallBack(ie);

    //    //			ie = ib.FindNextEntry();
    //    //		}
    //    //	}
    //    //}

    //    // Parse all the attributes in a File Record
    //    // And insert them into a link list
    

    //    //// Install Attribute raw data CallBack routines for a single File Record
    //    //BOOL CFileRecord::InstallAttrRawCB(DWORD attrType, ATTR_RAW_CALLBACK cb)
    //    //{
    //    //	DWORD atIdx = ATTR_INDEX(attrType);
    //    //	if (atIdx < ATTR_NUMS)
    //    //	{
    //    //		AttrRawCallBack[atIdx] = cb;
    //    //		return TRUE;
    //    //	}
    //    //	else
    //    //		return FALSE;
    //    //}

    //    //// Clear all Attribute CallBack routines
    //    //__inline void CFileRecord::ClearAttrRawCB()
    //    //{
    //    //	for (int i = 0; i < ATTR_NUMS; i++)
    //    //		AttrRawCallBack[i] = NULL;
    //    //}

    //    //// Choose attributes to handle, unwanted attributes will be discarded silently
    //    //__inline void CFileRecord::SetAttrMask(DWORD mask)
    //    //{
    //    //	// Standard Information and Attribute List is needed always
    //    //	AttrMask = mask | MASK_STANDARD_INFORMATION | MASK_ATTRIBUTE_LIST;
    //    //}

    //    //// Traverse all Attribute and return CAttr_xxx classes to User Callback routine
    //    //void CFileRecord::TraverseAttrs(ATTRS_CALLBACK attrCallBack, void* context)
    //    //{
    //    //	_ASSERT(attrCallBack);

    //    //	for (int i = 0; i < ATTR_NUMS; i++)
    //    //	{
    //    //		if (AttrMask & (((DWORD)1) << i))	// skip masked attributes
    //    //		{
    //    //			const CAttrBase* ab = AttrList[i].FindFirstEntry();
    //    //			while (ab)
    //    //			{
    //    //				BOOL bStop;
    //    //				bStop = FALSE;
    //    //				attrCallBack(ab, context, &bStop);
    //    //				if (bStop)
    //    //					return;

    //    //				ab = AttrList[i].FindNextEntry();
    //    //			}
    //    //		}
    //    //	}
    //    //}

    //    //// Find Attributes
    //    //__inline const CAttrBase* CFileRecord::FindFirstAttr(DWORD attrType) const
    //    //{
    //    //	DWORD attrIdx = ATTR_INDEX(attrType);

    //    //	return attrIdx < ATTR_NUMS ? AttrList[attrIdx].FindFirstEntry() : NULL;
    //    //}

    //    //const CAttrBase* CFileRecord::FindNextAttr(DWORD attrType) const
    //    //{
    //    //	DWORD attrIdx = ATTR_INDEX(attrType);

    //    //	return attrIdx < ATTR_NUMS ? AttrList[attrIdx].FindNextEntry() : NULL;
    //    //}

    //    //// Get File Name (First Win32 name)
    //    //int CFileRecord::GetFileName(_TCHAR* buf, DWORD bufLen) const
    //    //{
    //    //	// A file may have several filenames
    //    //	// Return the first Win32 filename
    //    //	CAttr_FileName* fn = (CAttr_FileName*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindFirstEntry();
    //    //	while (fn)
    //    //	{
    //    //		if (fn->IsWin32Name())
    //    //		{
    //    //			int len = fn->GetFileName(buf, bufLen);
    //    //			if (len != 0)
    //    //				return len;	// success or fail
    //    //		}

    //    //		fn = (CAttr_FileName*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindNextEntry();
    //    //	}

    //    //	return 0;
    //    //}

    //    //// Get File Size
    //    //__inline ULONGLONG CFileRecord::GetFileSize() const
    //    //{
    //    //	CAttr_FileName* fn = (CAttr_FileName*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindFirstEntry();
    //    //	return fn ? fn->GetFileSize() : 0;
    //    //}

    //    //// Get File Times
    //    //void CFileRecord::GetFileTime(FILETIME* writeTm, FILETIME* createTm, FILETIME* accessTm) const
    //    //{
    //    //	// Standard Information attribute hold the most updated file time
    //    //	CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
    //    //	if (si)
    //    //		si->GetFileTime(writeTm, createTm, accessTm);
    //    //	else
    //    //	{
    //    //		writeTm->dwHighDateTime = 0;
    //    //		writeTm->dwLowDateTime = 0;
    //    //		if (createTm)
    //    //		{
    //    //			createTm->dwHighDateTime = 0;
    //    //			createTm->dwLowDateTime = 0;
    //    //		}
    //    //		if (accessTm)
    //    //		{
    //    //			accessTm->dwHighDateTime = 0;
    //    //			accessTm->dwLowDateTime = 0;
    //    //		}
    //    //	}
    //    //}

    //    //// Traverse all sub directories and files contained
    //    //// Call user defined callback routine once found an entry
    //    //void CFileRecord::TraverseSubEntries(SUBENTRY_CALLBACK seCallBack) const
    //    //{
    //    //	_ASSERT(seCallBack);

    //    //	// Start traversing from IndexRoot (B+ tree root node)

    //    //	CAttr_IndexRoot* ir = (CAttr_IndexRoot*)FindFirstAttr(ATTR_TYPE_INDEX_ROOT);
    //    //	if (ir == NULL || !ir->IsFileName())
    //    //		return;

    //    //	CIndexEntryList* ieList = (CIndexEntryList*)ir;
    //    //	CIndexEntry* ie = ieList->FindFirstEntry();
    //    //	while (ie)
    //    //	{
    //    //		// Visit subnode first
    //    //		if (ie->IsSubNodePtr())
    //    //			TraverseSubNode(ie->GetSubNodeVCN(), seCallBack);

    //    //		if (ie->HasName())
    //    //			seCallBack(ie);

    //    //		ie = ieList->FindNextEntry();
    //    //	}
    //    //}

    //    //// Find a specific FileName from InexRoot described B+ tree
    //    //__inline const BOOL CFileRecord::FindSubEntry(const _TCHAR* fileName, CIndexEntry& ieFound) const
    //    //{
    //    //	// Start searching from IndexRoot (B+ tree root node)
    //    //	CAttr_IndexRoot* ir = (CAttr_IndexRoot*)FindFirstAttr(ATTR_TYPE_INDEX_ROOT);
    //    //	if (ir == NULL || !ir->IsFileName())
    //    //		return FALSE;

    //    //	CIndexEntryList* ieList = (CIndexEntryList*)ir;
    //    //	CIndexEntry* ie = ieList->FindFirstEntry();
    //    //	while (ie)
    //    //	{
    //    //		if (ie->HasName())
    //    //		{
    //    //			// Compare name
    //    //			int i = ie->Compare(fileName);
    //    //			if (i == 0)
    //    //			{
    //    //				ieFound = *ie;
    //    //				return TRUE;
    //    //			}
    //    //			else if (i < 0)		// fileName is smaller than IndexEntry
    //    //			{
    //    //				// Visit SubNode
    //    //				if (ie->IsSubNodePtr())
    //    //				{
    //    //					// Search in SubNode (IndexBlock)
    //    //					if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
    //    //						return TRUE;
    //    //				}
    //    //				else
    //    //					return FALSE;	// not found
    //    //			}
    //    //			// Just step forward if fileName is bigger than IndexEntry
    //    //		}
    //    //		else if (ie->IsSubNodePtr())
    //    //		{
    //    //			// Search in SubNode (IndexBlock)
    //    //			if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
    //    //				return TRUE;
    //    //		}

    //    //		ie = ieList->FindNextEntry();
    //    //	}

    //    //	return FALSE;
    //    //}

    //    //// Find Data attribute class of 
    //    //const CAttrBase* CFileRecord::FindStream(_TCHAR* name)
    //    //{
    //    //	const CAttrBase* data = FindFirstAttr(ATTR_TYPE_DATA);
    //    //	while (data)
    //    //	{
    //    //		if (data->IsUnNamed() && name == NULL)	// Unnamed stream
    //    //			break;
    //    //		if ((!data->IsUnNamed()) && name)	// Named stream
    //    //		{
    //    //			_TCHAR an[MAX_PATH];
    //    //			if (data->GetAttrName(an, MAX_PATH))
    //    //			{
    //    //				if (_tcscmp(an, name) == 0)
    //    //					break;
    //    //			}
    //    //		}

    //    //		data = FindNextAttr(ATTR_TYPE_DATA);
    //    //	}

    //    //	return data;
    //    //}

    //    //// Check if it's deleted or in use
    //    //__inline BOOL CFileRecord::IsDeleted() const
    //    //{
    //    //	return !(FileRecord->Flags & FILE_RECORD_FLAG_INUSE);
    //    //}

    //    //// Check if it's a directory
    //    //__inline BOOL CFileRecord::IsDirectory() const
    //    //{
    //    //	return FileRecord->Flags & FILE_RECORD_FLAG_DIR;
    //    //}

    //    //__inline BOOL CFileRecord::IsReadOnly() const
    //    //{
    //    //	// Standard Information attribute holds the most updated file time
    //    //	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
    //    //	return si ? si->IsReadOnly() : FALSE;
    //    //}

    //    //__inline BOOL CFileRecord::IsHidden() const
    //    //{
    //    //	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
    //    //	return si ? si->IsHidden() : FALSE;
    //    //}

    //    //__inline BOOL CFileRecord::IsSystem() const
    //    //{
    //    //	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
    //    //	return si ? si->IsSystem() : FALSE;
    //    //}

    //    //__inline BOOL CFileRecord::IsCompressed() const
    //    //{
    //    //	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
    //    //	return si ? si->IsCompressed() : FALSE;
    //    //}

    //    //__inline BOOL CFileRecord::IsEncrypted() const
    //    //{
    //    //	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
    //    //	return si ? si->IsEncrypted() : FALSE;
    //    //}

    //    //__inline BOOL CFileRecord::IsSparse() const
    //    //{
    //    //	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
    //    //	return si ? si->IsSparse() : FALSE;
    //    //}


    //};
}
#endif
