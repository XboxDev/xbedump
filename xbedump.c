/* Note: this code will work on little-endian 32-bit machines only! */

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/


#include <errno.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>




#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#include "xbestructure.h"
#include "xboxlib.h"


void printdate(unsigned int t_time) {
    
    time_t rawtime=t_time;
    printf("%s",ctime(&rawtime)); 
}

void printhex(unsigned char d) {
    if (d<16) printf("0");
    printf("%x ", d);
}

void printhexm(unsigned char *d, int size) {
    int i;
    for (i = 0; i < size; i++, d++) {
        if (!(i & 15)) printf("\n                                      ");
        printhex(*d);
    }
    printf("\n");
}

void printhex32(unsigned int d) {
    printf("0x%x ", d);
}

void printhex32mz(unsigned int *d, int size) {
    int i;
    if (!*d) {
        printf("\n\tnone\n");
        return;
    }
    for (i = 0; i < size; i++, d++) {
        if (!*d) return;
        if (!(i & 7)) printf("\n\t");
        printhex32(*d);
    }
    printf("\n");
}

void printhex32m(unsigned int *d, int size) {
    int i;
    for (i = 0; i < size; i++, d++) {
        if (!(i & 7)) printf("\n\t");
        printhex32(*d);
    }
    printf("\n");
}

void printunicode(short *s) {
    while (*s) {
        printf("%c", *s);
        s++;
    }
}

void printn(char *s, int len) {
    int i;
    for (i = 0; (i < len) && *s; i++, s++) {
        printf("%c", *s);
    }
}

void printw(char *s) {
    printf("** warning: %s\n", s);
}

void printInitFlags(int f) {
    if (!f) printf("none");
    if (f & XBE_INIT_MOUNT_UTILITY) printf("XBE_INIT_MOUNT_UTILITY ");
    if (f & XBE_INIT_FORMAT_UTILITY) printf("XBE_INIT_FORMAT_UTILITY ");
    if (f & XBE_INIT_64M_RAM_ONLY) printf("XBE_INIT_64M_RAM_ONLY ");
    if (f & XBE_INIT_DONT_SETUP_HDD) printf("XBE_INIT_DONT_SETUP_HDD ");
}

void printMediaTypes(int f) {
    if (!f) printf("none");
    if (f & XBE_MEDIA_HDD) printf("XBE_MEDIA_HDD ");
    if (f & XBE_MEDIA_XBOX_DVD) printf("XBE_MEDIA_XBOX_DVD ");
    if (f & XBE_MEDIA_ANY_CD_OR_DVD) printf("XBE_MEDIA_ANY_CD_OR_DVD ");
    if (f & XBE_MEDIA_CD) printf("XBE_MEDIA_CD ");
    if (f & XBE_MEDIA_1LAYER_DVDROM) printf("XBE_MEDIA_1LAYER_DVDROM ");
    if (f & XBE_MEDIA_2LAYER_DVDROM) printf("XBE_MEDIA_2LAYER_DVDROM ");
    if (f & XBE_MEDIA_1LAYER_DVDR) printf("XBE_MEDIA_1LAYER_DVDR ");
    if (f & XBE_MEDIA_2LAYER_DVDR) printf("XBE_MEDIA_2LAYER_DVDR ");
    if (f & XBE_MEDIA_USB) printf("XBE_MEDIA_USB ");
    if (f & XBE_MEDIA_ALLOW_UNLOCKED_HDD) printf("XBE_MEDIA_ALLOW_UNLOCKED_HDD ");
}

void printGameRegion(int f) {
    if (!f) printf("none");
    if (f & XBE_REGION_US_CANADA) printf("XBE_REGION_US_CANADA ");
    if (f & XBE_REGION_JAPAN) printf("XBE_REGION_JAPAN ");
    if (f & XBE_REGION_ELSEWHERE) printf("XBE_REGION_ELSEWHERE ");
    if (f & XBE_REGION_DEBUG) printf("XBE_REGION_DEBUG ");
}

void printFlags(int f) {
    if (!f) printf("none");
    if (f & XBE_SEC_WRITABLE) printf("XBE_SEC_WRITABLE ");
    if (f & XBE_SEC_PRELOAD) printf("XBE_SEC_PRELOAD ");
    if (f & XBE_SEC_EXECUTABLE) printf("XBE_SEC_EXECUTABLE ");
    if (f & XBE_SEC_INSERTED_FILE) printf("XBE_SEC_INSERTED_FILE ");
    if (f & XBE_SEC_RO_HEAD_PAGE) printf("XBE_SEC_RO_HEAD_PAGE ");
    if (f & XBE_SEC_RO_TAIL_PAGE) printf("XBE_SEC_RO_TAIL_PAGE ");
}



int dumpxbe (void *xbe,unsigned int option_flag){
    int warn;
    int i;
    int a;
 
    XBE_HEADER *header;
    XBE_CERTIFICATE *cert;
    XBE_SECTION *sechdr;
    XBE_TLS *tls;
    XBE_LIBRARY *lib;
  
    unsigned int KernelThunkTable;     
    unsigned char sha_Message_Digest[20];
    unsigned int xorkey;
    

    
    warn = 1;
    

     /* header */
         header = (XBE_HEADER*) xbe;

if (option_flag & 0x00000001) {

         printf("\nXBE header\n~~~~~~~~~~\n");
         printf("Magic                               : %c%c%c%c\n", header->Magic[0], header->Magic[1], header->Magic[2], header->Magic[3]);
//         if (warn) if (strncmp("XBEH", header->Magic, 4)) printw("must be \"XBEH\"");
         printf("RSA digital signature               : ");   
        if (VerifySignaturex(xbe,0)== 1) printf("(Valid)");  else  printf("(Fail)");
         printhexm(header->HeaderSignature, sizeof(header->HeaderSignature));
         //for (i=0;i<sizeof(header->HeaderSignature);i++)  printf( "%02X",header->HeaderSignature[i]);
         
         printf("Base address                        : 0x%08X\n", ((unsigned int)header->BaseAddress));

         printf("Size of all headers:                : 0x%08X\n", header->HeaderSize);
         /* TODO */
         printf("Size of entire image                : 0x%08X\n", header->ImageSize);
  
         printf("Size of this header                 : 0x%08X\n",header->XbeHeaderSize);
         printf("Image timestamp                     : 0x%08X ",(unsigned int)header->Timestamp);
         printdate(header->Timestamp);
         printf("Pointer to certificate data         : 0x%08X\n", (unsigned int)header->Certificate);
         printf("Number of sections                  : 0x%08X\n", (unsigned int)header->NumSections);
         printf("Pointer to section headers          : 0x%08X\n", (unsigned int)header->Sections);
         printf("Initialization flags                : 0x%08X", (unsigned int) header->InitFlags); 
         printInitFlags(header->InitFlags); printf("\n");

}
   //      EntryPoint = (unsigned int)header->EntryPoint ^ 0xa8fc57ab; /* debug: 0x0x94859d4b */
if (option_flag & 0x00000001) {                      
	 xorkey=xorentry(0);
         printf("Entry Point                         : 0x%08X (Actual: 0x%08X  Retail: 0x%08X Debug: 0x%08X)\n", 
         (unsigned int)header->EntryPoint,
         (unsigned int)header->EntryPoint^xorkey,
         (unsigned int)header->EntryPoint^0xa8fc57ab,
         (unsigned int)header->EntryPoint^0x94859d4b);
         
         printf("Pointer to TLS directory            : 0x%08X\n", (unsigned int)header->TlsDirectory);
         printf("Stack commit size                   : 0x%08X\n", (unsigned int)header->StackCommit);
         printf("Heap reserve size                   : 0x%08X\n", (unsigned int)header->HeapReserve);
         printf("Heap commit size                    : 0x%08X\n", (unsigned int)header->HeapCommit);
         printf("PE base address                     : 0x%08X\n", (unsigned int)header->PeBaseAddress);
         printf("PE image size                       : 0x%08X\n", (unsigned int)header->PeImageSize);
         printf("PE checksum                         : 0x%08X\n", (unsigned int)header->PeChecksum);
         printf("PE timestamp                        : 0x%08X ",(unsigned int)header->PeTimestamp);
         	printdate(header->PeTimestamp);
         printf("PC path and filename to EXE         : 0x%08X (\"%s\")\n",(unsigned int)header->PcExePath, ((char *)xbe)+(int)header->PcExePath-(int)header->BaseAddress);
         printf("PC filename to EXE                  : 0x%08X (\"%s\"\n", (unsigned int)header->PcExeFilename,((char *)xbe)+(int)header->PcExeFilename-(int)header->BaseAddress);
         printf("PC filename to EXE (Unicode)        : 0x%08X (\"",(int)header->PcExeFilenameUnicode);
         printunicode( (short int *) (((char *)xbe)+(unsigned int)header->PcExeFilenameUnicode-(unsigned int)header->BaseAddress));
         printf("\")\n");
}         
         //KernelThunkTable = (unsigned int)header->KernelThunkTable ^ 0x5b6d40b6; /* debug: 0xEFB1F152 */

         xorkey=xorthunk(0);
         KernelThunkTable = (unsigned int)header->KernelThunkTable ^ xorkey; 

if (option_flag & 0x00000001) {

         printf("Pointer to kernel thunk table       : 0x%08X (Actual: 0x%08X  Retail: 0x%08X Debug: 0x%08X)\n", 
         (unsigned int)header->KernelThunkTable,
         (unsigned int)header->KernelThunkTable^xorkey,
         (unsigned int)header->KernelThunkTable^0x5b6d40b6,
         (unsigned int)header->KernelThunkTable^0xEFB1F152);   
	 
	 
     
         
         printf("Non-kernel import table (debug only): 0x%08X\n", (unsigned int)header->DebugImportTable);
         printf("Number of library headers           : 0x%08X\n", header->NumLibraries);
         printf("Pointer to library headers          : 0x%08X\n", (unsigned int)header->Libraries);
         printf("Pointer to kernel library header    : 0x%08X\n", (unsigned int)(header->KernelLibrary));
         printf("Pointer to XAPI library header      : 0x%08X\n", (unsigned int)(header->XapiLibrary));
         printf("Pointer to logo bitmap              : 0x%08X\n", (unsigned int)(header->LogoBitmap));
         printf("Size of logo bitmap                 : 0x%08X\n", header->LogoBitmapSize);
}
         cert = (XBE_CERTIFICATE *)(((char *)xbe) + (int)header->Certificate - (int)header->BaseAddress);

if (option_flag & 0x00000002) {
         printf("\nCertificate\n~~~~~~~~~~~\n");
         printf("Size of certificate                 : 0x%08X\n", cert->Size);
         printf("Certificate timestamp               : 0x%08X ",cert->Timestamp); printdate(cert->Timestamp);
         printf("Title ID                            : 0x%08X\n", cert->TitleId);
         printf("Title name                          : \""); printunicode(cert->TitleName); printf("\"\n");
         printf("Alternate title ID's                : "); printhex32mz(cert->AlternateTitleIds, 16);
         printf("Allowed media types                 : "); printMediaTypes(cert->MediaTypes); printf("\n");
         printf("Allowed game regions                : "); printGameRegion(cert->GameRegion); printf("\n");
         printf("Allowed game rating                 : 0x%08X\n", cert->GameRating);
         printf("Disk number                         : 0x%08X\n", cert->DiskNumber);
         printf("Version                             : 0x%08X\n", cert->Version);
         printf("LAN key                             : "); 
         printhexm(cert->LanKey, sizeof(cert->LanKey));
         printf("Signature key                       : "); 
         printhexm(cert->SignatureKey, sizeof(cert->SignatureKey));
         printf("Alternate signature keys            : "); 
         printhexm((unsigned char*)cert->AlternateSignatureKeys, sizeof(cert->AlternateSignatureKeys));

}	
	
       
         sechdr = (XBE_SECTION *)(((char *)xbe) + (int)header->Sections - (int)header->BaseAddress);
         for (i = 0; i < header->NumSections; i++, sechdr++) {
 if (option_flag & 0x00000004) {
         printf("\nSection Header %i\n~~~~~~~~~~~~~~~~~\n", i);
 
         printf("Flags                               : "); printFlags(sechdr->Flags); printf("\n");
         printf("Flags                               : 0x%08X \n",sechdr->Flags);
         printf("Virtual address                     : 0x%08X\n", sechdr->VirtualAddress);
         printf("Virtual size                        : 0x%08X\n", sechdr->VirtualSize);
         printf("File address                        : 0x%08X\n", sechdr->FileAddress);
         printf("File size                           : 0x%08X\n", sechdr->FileSize);
         printf("Section name Address                : 0x%08X (\"%s\")\n",(int)sechdr->SectionName, ((unsigned char *)xbe)+(int)sechdr->SectionName-(int)header->BaseAddress);
         printf("Section reference count             : 0x%08X\n", sechdr->SectionReferenceCount);
         printf("Head shared page reference count    : 0x%08X\n", (unsigned int)sechdr->HeadReferenceCount);
         printf("Tail shared page reference count    : 0x%08X\n", (unsigned int)sechdr->TailReferenceCount);

         printf("SHA1 hash                           : "); 
             
             shax(&sha_Message_Digest[0], ((unsigned char *)xbe)+(int)sechdr->FileAddress ,sechdr->FileSize);
             
             for (a=0;a<20;a++) printf("%02X",sechdr->ShaHash[a]);
             
             	if (memcmp(&sha_Message_Digest[0],&sechdr->ShaHash[0],20)==0) {
	  		 printf("  (Valid)"); 
		} else {       
			//fail=1; 
			printf("   (False)"); 
		}
             
             printf("\n");
	}           
       
         }

         lib = (XBE_LIBRARY *)(((char *)xbe) + (int)header->Libraries - (int)header->BaseAddress);
     
         for (i = 0; i < header->NumLibraries; i++, lib++) {

       if (option_flag & 0x00000008) { 
     	printf("\nLibrary %i\n~~~~~~~~~~\n", i);
        printf("Library name                        : \""); printn(lib->Name, sizeof(lib->Name)); printf("\"\n");
        printf("Major Version                       : 0x%08X\n", lib->MajorVersion);
        printf("Middle Version                      : 0x%08X\n", lib->MiddleVersion);
        printf("Minor Version                       : 0x%08X\n", lib->MinorVersion);
        printf("Flags                               : 0x%08X\n", lib->Flags);
       }
       
       }


    //     tls = (XBE_TLS *)(((char *)xbe) + (int)header->TlsDirectory - (int)header->BaseAddress);
     	tls = (XBE_TLS *)(((char *)xbe) + (int)header->TlsDirectory - KernelThunkTable );//
     	//(int)header->BaseAddress);
         
	if (option_flag & 0x00000001) {
     /*
         printf("\nThread Local Storage Directory - Still Buggy\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
         printf("Raw data start address              : 0x%08X\n", tls->RawStart);
         printf("Raw data end address                : 0x%08X\n", tls->RawEnd);
         printf("TLS index address                   : 0x%08X\n", tls->TlsIndex);
         printf("TLS callbacks address               : 0x%08X\n", tls->TlsCallbacks);
         printf("Size of zero fill                   : 0x%08x\n", tls->SizeZeroFill);
         //printf("Characteristics                     : 0x%08X\n", (unsigned char *)xbe+(unsigned int)tls->Characteristics-(unsigned int)header->BaseAddress);
         printf("Characteristics                     : %s\n", tls->Characteristics);
         */
	}    
             
   //   free(xbe);  
      

    return 0;
}

