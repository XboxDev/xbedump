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
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include "openssl/e_os.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include "xbestructure.h"
#include "xboxlib.h"


void printdate(unsigned int t_time) {
    time_t rawtime=t_time;
    struct tm *timeinfo;
    timeinfo= localtime(&rawtime);
    printf("%s",asctime(timeinfo));
}

void printhex(unsigned char d) {
    if (d<16) printf("0");
    printf("%x ", d);
}

void printhexm(unsigned char *d, int size) {
    int i;
    for (i = 0; i < size; i++, d++) {
        if (!(i & 15)) printf("\n\t");
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



int dumpxbe (char *filename,unsigned int option_flag){
    FILE *f;
    int filesize;
    int warn;
    int i;
    int a;
    void *xbe;
 
    XBE_HEADER *header;
    XBE_CERTIFICATE *cert;
    XBE_SECTION *sechdr;
    XBE_TLS *tls;
    XBE_LIBRARY *lib;
//    unsigned char sha1hashout[20];
//    unsigned char md5hashout[16];
  //  unsigned char sha_Message_Digest[20];
    
    unsigned int EntryPoint;
    unsigned int KernelThunkTable;
//    	SHA_CTX	sha_ctx;
//    unsigned char temp_char[4];
//    unsigned char temp_char1[4];
    
/* title */
    
    warn = 1;
    
/* read file */
    f = fopen(filename, "r");
    if (f!=NULL) 
    {
         
         
         
         fseek(f, 0, SEEK_END); filesize = ftell(f); fseek(f, 0, SEEK_SET);
         xbe = malloc(filesize);
         
         fread(xbe, 1, filesize, f);
         fclose(f);
       
         printf("Dumping file %s (%i bytes)\n", filename, filesize);
         
     /* header */
         header = (XBE_HEADER*) xbe;

if (option_flag & 0x00000001) {

         printf("\nXBE header\n~~~~~~~~~~\n");
         printf("Magic:\n\t\"%c%c%c%c\"\n", header->Magic[0], header->Magic[1], header->Magic[2], header->Magic[3]);
//         if (warn) if (strncmp("XBEH", header->Magic, 4)) printw("must be \"XBEH\"");
         printf("RSA digital signature: ");
         printhexm(header->HeaderSignature, sizeof(header->HeaderSignature));
         //for (i=0;i<sizeof(header->HeaderSignature);i++)  printf( "%02X",header->HeaderSignature[i]);
         printf("Base address:\n\t0x%x\n", ((unsigned int)header->BaseAddress));
         if (warn) if ((int)header->BaseAddress != 0x10000) printw("is 0x10000 on all known XBEs");
         printf("Size of all headers combined:\n\t0x%x\n", header->HeaderSize);
         /* TODO */
         printf("Size of entire image:\n\t0x%x\n", header->ImageSize);
     //    if (warn) if (header->ImageSize != filesize) printf("** should be equal to file size! %x\n", filesize);
         printf("Size of this header:\n\t0x%x\n", header->XbeHeaderSize);
         printf("Image timestamp:\n\t");
         printdate(header->Timestamp);
         printf("Pointer to certificate data:\n\t0x%x\n", (unsigned int)header->Certificate);
         printf("Number of sections:\n\t%i\n", header->NumSections);
         printf("Pointer to section headers:\n\t0x%x\n", (unsigned int)header->Sections);
         printf("Initialization flags:\n\t"); printInitFlags(header->InitFlags); printf("\n");
         printf("Initialization flags: %08X\n\t",header->InitFlags);
}
         EntryPoint = (int)header->EntryPoint ^ 0xa8fc57ab; /* debug: 0x0x94859d4b */
if (option_flag & 0x00000001) {
         printf("Entry Point:\n\t0x%x\n", EntryPoint);
         printf("Pointer to TLS directory:\n\t0x%x\n", (unsigned int)header->TlsDirectory);
         printf("Stack commit size:\n\t0x%x\n", header->StackCommit);
         printf("Heap reserve size:\n\t0x%x\n", header->HeapReserve);
         printf("Heap commit size:\n\t0x%x\n", header->HeapCommit);
         printf("PE base address:\n\t0x%x\n", (unsigned int)header->PeBaseAddress);
         printf("PE image size:\n\t0x%x\n", header->PeImageSize);
         printf("PE checksum:\n\t0x%x\n", header->PeChecksum);
         printf("PE timestamp:\n\t");printdate(header->PeTimestamp);
         printf("PC path and filename to EXE:\n\t\"%s\"\n", ((char *)xbe)+(int)header->PcExePath-(int)header->BaseAddress);
         printf("PC filename to EXE:\n\t\"%s\"\n", ((char *)xbe)+(int)header->PcExeFilename-(int)header->BaseAddress);
         printf("PC filename to EXE (Unicode):\n\t\"");
         printunicode( (short int *) (((char *)xbe)+(int)header->PcExeFilenameUnicode-(int)header->BaseAddress));
         printf("\"\n");
}         
         KernelThunkTable = (int)header->KernelThunkTable ^ 0x5b6d40b6; /* debug: 0xEFB1F152 */

if (option_flag & 0x00000001) {
         printf("Pointer to kernel thunk table:\n\t0x%x\n", (unsigned int)KernelThunkTable);
         printf("Non-kernel import table (debug only):\n\t0x%x\n", (unsigned int)header->DebugImportTable);
         printf("Number of library headers:\n\t%i\n", header->NumLibraries);
         printf("Pointer to library headers:\n\t0x%x\n", (unsigned int)header->Libraries);
         printf("Pointer to kernel library header:\n\t0x%x\n", (unsigned int)(header->KernelLibrary));
         printf("Pointer to XAPI library header:\n\t0x%x\n", (unsigned int)(header->XapiLibrary));
         printf("Pointer to logo bitmap:\n\t0x%x\n", (unsigned int)(header->LogoBitmap));
         printf("Size of logo bitmap:\n\t0x%x\n", header->LogoBitmapSize);
}
         cert = (XBE_CERTIFICATE *)(((char *)xbe) + (int)header->Certificate - (int)header->BaseAddress);

if (option_flag & 0x00000002) {
         printf("\nCertificate\n~~~~~~~~~~~\n");
         printf("Size of certificate:\n\t0x%x\n", cert->Size);
         printf("Certificate timestamp:\n\t"); printdate(cert->Timestamp);
         printf("Title ID:\n\t0x%x\n", cert->TitleId);
         printf("Title name:\n\t\""); printunicode(cert->TitleName); printf("\"\n");
         printf("Alternate title ID's:"); printhex32mz(cert->AlternateTitleIds, 16);
         printf("Allowed media types:\n\t"); printMediaTypes(cert->MediaTypes); printf("\n");
         printf("Allowed game regions:\n\t"); printGameRegion(cert->GameRegion); printf("\n");
         printf("Allowed game rating:\n\t0x%x\n", cert->GameRating);
         printf("Disk number:\n\t%i\n", cert->DiskNumber);
         printf("Version:\n\t%i\n", cert->Version);
         printf("LAN key: "); printhexm(cert->LanKey, sizeof(cert->LanKey));
         printf("Signature key: "); printhexm(cert->SignatureKey, sizeof(cert->SignatureKey));
         printf("Alternate signature keys: "); printhexm((unsigned char*)cert->AlternateSignatureKeys, sizeof(cert->AlternateSignatureKeys));

	// VerifySignaturex(xbe,1);
	
/*	 shax(&sha_Message_Digest[0], ((unsigned char *)xbe)+0x104 ,header->HeaderSize - 0x104);
         printf("\nHeader hash: calculated \n\t");
         for (a=0;a<20;a++) printf("%02X",sha_Message_Digest[a]);
         printf("\n");
        // printf("%d", (unsigned int)xbox_publicmodulus);
*/	
}	
	
       
         sechdr = (XBE_SECTION *)(((char *)xbe) + (int)header->Sections - (int)header->BaseAddress);
         for (i = 0; i < header->NumSections; i++, sechdr++) {
 if (option_flag & 0x00000004) {
             printf("\nSection Header %i\n~~~~~~~~~~~~~~~~~\n", i);
 
             printf("Flags:\n\t"); printFlags(sechdr->Flags); printf("\n");
             printf("Flags: %08X \n",sechdr->Flags);
             printf("Virtual address:\n\t0x%x\n", sechdr->VirtualAddress);
             printf("Virtual size:\n\t0x%x\n", sechdr->VirtualSize);
             printf("File address:\n\t0x%x\n", sechdr->FileAddress);
             printf("File size:\n\t0x%x\n", sechdr->FileSize);
             printf("Section name:\n\t%s\n", ((unsigned char *)xbe)+(int)sechdr->SectionName-(int)header->BaseAddress);
             printf("Section reference count:\n\t%i\n", sechdr->SectionReferenceCount);
             printf("Pointer to head shared page reference count:\n\t0x%x\n", (int)sechdr->HeadReferenceCount);
             printf("Pointer to tail shared page reference count:\n\t0x%x\n", (int)sechdr->TailReferenceCount);
 
             printf("SHA1 hash:\n\t"); 
             
             for (a=0;a<20;a++) printf("%02X",sechdr->ShaHash[a]);
}           
       /*    shax(&sha_Message_Digest[0], xbe+(int)sechdr->FileAddress ,sechdr->FileSize);
             printf("\nSHA1 hash: calculated \n\t");
             for (a=0;a<20;a++) printf("%02X",sha_Message_Digest[a]);*/
          
              
             

         }



         tls = (XBE_TLS *)(((char *)xbe) + (int)header->TlsDirectory - (int)header->BaseAddress);
         
if (option_flag & 0x00000001) {
         printf("\nThread Local Storage Directory\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
         printf("Raw data start address:\n\t0x%x\n", tls->RawStart);
         printf("Raw data end address:\n\t0x%x\n", tls->RawEnd);
         printf("TLS index address:\n\t0x%x\n", tls->TlsIndex);
         printf("TLS callbacks address:\n\t0x%x\n", tls->TlsCallbacks);
         printf("Size of zero fill:\n\t0x%x\n", tls->SizeZeroFill);
     //    printf("Characteristics:\n\t\"%s\"\n",xbe+(int)tls->Characteristics-(int)header->BaseAddress);
}        
         lib = (XBE_LIBRARY *)(((char *)xbe) + (int)header->Libraries - (int)header->BaseAddress);
     
         for (i = 0; i < header->NumLibraries; i++, lib++) {

if (option_flag & 0x00000008) { 
     
             printf("\nLibrary %i\n~~~~~~~~~~\n", i);
             printf("Library name:\n\t\""); printn(lib->Name, sizeof(lib->Name)); printf("\"\n");
             printf("Major Version:\n\t0x%x\n", lib->MajorVersion);
             printf("Middle Version:\n\t0x%x\n", lib->MiddleVersion);
             printf("Minor Version:\n\t0x%x\n", lib->MinorVersion);
             printf("Flags:\n\t0x%x\n", lib->Flags);
      
       }
       
       }
             
      free(xbe);  
      
    } else {
     
      printf("File Not found %s, use parameter filename \n",filename);
    }
    return 0;
}

