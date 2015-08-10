// XBE stuff
// Not used in any exported kernel calls, but still useful.

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/


#include <stdint.h>

// XBE header information
typedef struct _XBE_HEADER {
	// 000 "XBEH"
	uint8_t Magic[4];
	// 004 RSA digital signature of the entire header area
	uint8_t HeaderSignature[256];
	//uint32_t  HeaderSignature[64];
	// 104 Base address of XBE image (must be 0x00010000?)
	uint32_t  BaseAddress;
	// 108 Size of all headers combined - other headers must be within this
	uint32_t  HeaderSize;
	// 10C Size of entire image
	uint32_t  ImageSize;
	// 110 Size of this header (always 0x178?)
	uint32_t  XbeHeaderSize;
	// 114 Image timestamp - unknown format
	uint32_t  Timestamp;
	// 118 Pointer to certificate data (must be within HeaderSize)
	/*struct _XBE_CERTIFICATE */ uint32_t Certificate;
	// 11C Number of sections
	int32_t NumSections;
	// 120 Pointer to section headers (must be within HeaderSize)
	/*struct _XBE_SECTION */ uint32_t Sections;
	// 124 Initialization flags
	uint32_t  InitFlags;
	// 128 Entry point32_t (XOR'd; see xboxhacker.net)
	uint32_t  EntryPoint;
	// 12C Pointer to TLS directory
	/*struct _XBE_TLS_DIRECTORY */ uint32_t TlsDirectory;
	// 130 Stack commit size
	uint32_t  StackCommit;
	// 134 Heap reserve size
	uint32_t  HeapReserve;
	// 138 Heap commit size
	uint32_t  HeapCommit;
	// 13C PE base address (?)
	uint32_t  PeBaseAddress;
	// 140 PE image size (?)
	uint32_t  PeImageSize;
	// 144 PE checksum (?)
	uint32_t  PeChecksum;
	// 148 PE timestamp (?)
	uint32_t  PeTimestamp;
	// 14C PC path and filename to EXE file from which XBE is derived
	/*uint8_t*/ uint32_t PcExePath;
	// 150 PC filename (last part of PcExePath) from which XBE is derived
	/*uint8_t*/ uint32_t PcExeFilename;
	// 154 PC filename (Unicode version of PcExeFilename)
	uint32_t  PcExeFilenameUnicode;
	// 158 Pointer to kernel thunk table (XOR'd; EFB1F152 debug)
	uint32_t  KernelThunkTable;
	// 15C Non-kernel import table (debug only)
	uint32_t  DebugImportTable;
	// 160 Number of library headers
	int32_t NumLibraries;
	// 164 Pointer to library headers
	/*struct _XBE_LIBRARY */ uint32_t Libraries;
	// 168 Pointer to kernel library header
	/*struct _XBE_LIBRARY */ uint32_t KernelLibrary;
	// 16C Pointer to XAPI library
	/*struct _XBE_LIBRARY */ uint32_t XapiLibrary;
	// 170 Pointer to logo bitmap (NULL = use default of Microsoft)
	uint32_t  LogoBitmap;
	// 174 Size of logo bitmap
	uint32_t  LogoBitmapSize;
	// 178
} XBE_HEADER, *PXBE_HEADER;

// Certificate structure
typedef struct _XBE_CERTIFICATE {
	// 000 Size of certificate
	uint32_t  Size;
	// 004 Certificate timestamp (unknown format)
	uint32_t  Timestamp;
	// 008 Title ID
	uint32_t  TitleId;
	// 00C Name of the game (Unicode)
	int16_t TitleName[40];
	// 05C Alternate title ID's (0-terminated)
	uint32_t  AlternateTitleIds[16];
	// 09C Allowed media types - 1 bit match between XBE and media = boots
	uint32_t  MediaTypes;
	// 0A0 Allowed game regions - 1 bit match between this and XBOX = boots
	uint32_t  GameRegion;
	// 0A4 Allowed game ratings - 1 bit match between this and XBOX = boots
	uint32_t  GameRating;
	// 0A8 Disk number (?)
	uint32_t  DiskNumber;
	// 0AC Version (?)
	uint32_t  Version;
	// 0B0 LAN key for this game
	uint8_t LanKey[16];
	// 0C0 Signature key for this game
	uint8_t SignatureKey[16];
	// 0D0 Signature keys for the alternate title ID's
	uint8_t AlternateSignatureKeys[16][16];
	// 1D0
} XBE_CERTIFICATE, *PXBE_CERTIFICATE;

// Section headers
typedef struct _XBE_SECTION {
	// 000 Flags
	uint32_t  Flags;
	// 004 Virtual address (where this section loads in RAM)
	//uint32_t  VirtualAddress;
	uint32_t  VirtualAddress;
	// 008 Virtual size (size of section in RAM; after FileSize it's 00'd)
	uint32_t  VirtualSize;
	// 00C File address (where in the file from which this section comes)
	uint32_t  FileAddress;
	// 010 File size (size of the section in the XBE file)
	uint32_t  FileSize;
	// 014 Pointer to section name
	/*uint8_t*/ uint32_t SectionName;
	// 018 Section reference count - when >= 1, section is loaded
	int32_t SectionReferenceCount;
	// 01C Pointer to head shared page reference count
	/*int16_t */ uint32_t HeadReferenceCount;
	// 020 Pointer to tail shared page reference count
	/*int16_t */ uint32_t TailReferenceCount;
	// 024 SHA1 hash.  Hash int32_t containing FileSize, then hash section.
	uint8_t ShaHash[20];
	// 038
} XBE_SECTION, *PXBE_SECTION;

// TLS directory information
typedef struct _XBE_TLS {
        // 000 raw data start address
        int32_t RawStart;
        // 004 raw data end address
        int32_t RawEnd;
        // 008 TLS index address
        int32_t TlsIndex;
        // 00C TLS callbacks address
        int32_t TlsCallbacks;
        // 010 size of zero fill
        int32_t SizeZeroFill;
        // 014 uint8_tacteristics
        uint8_t uint8_tacteristics[8];
        // 01C
} XBE_TLS, *PXBE_TLS;

// Library version data
typedef struct _XBE_LIBRARY {
    // 000 Library Name
    uint8_t Name[8];
    // 008 Major Version
    int16_t MajorVersion;
    // 00A Middle Version
    int16_t MiddleVersion;
    // 00C Minor Version
    int16_t MinorVersion;
    // 00E Flags
    int16_t Flags;
    // 010
} XBE_LIBRARY, *PXBELIBRARY;

// Initialization flags
#define XBE_INIT_MOUNT_UTILITY          0x00000001
#define XBE_INIT_FORMAT_UTILITY         0x00000002
#define XBE_INIT_64M_RAM_ONLY           0x00000004
#define XBE_INIT_DONT_SETUP_HDD         0x00000008

// Region codes
#define XBE_REGION_US_CANADA            0x00000001
#define XBE_REGION_JAPAN                0x00000002
#define XBE_REGION_ELSEWHERE            0x00000004
#define XBE_REGION_DEBUG                0x80000000

// Media types
#define XBE_MEDIA_HDD                   0x00000001
#define XBE_MEDIA_XBOX_DVD              0x00000002
#define XBE_MEDIA_ANY_CD_OR_DVD         0x00000004
#define XBE_MEDIA_CD                    0x00000008
#define XBE_MEDIA_1LAYER_DVDROM         0x00000010
#define XBE_MEDIA_2LAYER_DVDROM         0x00000020
#define XBE_MEDIA_1LAYER_DVDR           0x00000040
#define XBE_MEDIA_2LAYER_DVDR           0x00000080
#define XBE_MEDIA_USB                   0x00000100
#define XBE_MEDIA_ALLOW_UNLOCKED_HDD    0x40000000

// Section flags
#define XBE_SEC_WRITABLE                0x00000001
#define XBE_SEC_PRELOAD                 0x00000002
#define XBE_SEC_EXECUTABLE              0x00000004
#define XBE_SEC_INSERTED_FILE           0x00000008
#define XBE_SEC_RO_HEAD_PAGE            0x00000010
#define XBE_SEC_RO_TAIL_PAGE            0x00000020

void shax(uint8_t *result, uint8_t *data, uint32_t  len);
int32_t validatexbe(void *xbe,uint32_t  filesize,uint32_t  option_flag);
int32_t dumpxbe (void *xbe,uint32_t  option_flag);

