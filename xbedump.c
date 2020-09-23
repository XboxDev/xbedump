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
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#include "xbestructure.h"
#include "xboxlib.h"
#include "xboxkrnl.h"


void printdate(uint32_t  t_time) {
    
    time_t rawtime=t_time;
    printf("%s",ctime(&rawtime)); 
}

void printhex_strip(uint8_t  d) {
    if (d<16) printf("0");
    printf("%x", d);
}

void printhexm_strip(uint8_t  *d, int size) {
    int i;
    for (i = 0; i < size; i++, d++) {
        if (!(i & 15) && i != 0) printf("\n");
        printhex_strip(*d);
    }
    printf("\n");
}

void printhex_cert(uint8_t  *d, int size) {
    int i;
    int line = 0;
    for (i = 0; i < size; i++, d++) {
        if (!(i & 15)) {
		line ++;
		printf("\n	KEY_ALT%d=",line);
	}
        printhex_strip(*d);
    }
    printf("\n");
}

void printhex(uint8_t  d) {
    if (d<16) printf("0");
    printf("%x ", d);
}

void printhexm(uint8_t  *d, int size) {
    int i;
    for (i = 0; i < size; i++, d++) {
        if (!(i & 15)) printf("\n                                      ");
        printhex(*d);
    }
    printf("\n");
}

void printhex32(uint32_t  d) {
    printf("0x%x ", d);
}

void printhex32mz(uint32_t  *d, int size) {
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

void printhex32m(uint32_t  *d, int size) {
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
    if (!f) {
  		printf("\n                                    : ");
	    	printf("none");
    } else {
	printf("0x%08X",f);
    	if (f & XBE_INIT_MOUNT_UTILITY) {
      		printf("\n                                    : ");
		printf("XBE_INIT_MOUNT_UTILITY ");
		}
    	if (f & XBE_INIT_FORMAT_UTILITY) {
   		printf("\n                                    : ");
		printf("XBE_INIT_FORMAT_UTILITY ");
		}
    	if (f & XBE_INIT_64M_RAM_ONLY) {
    		printf("\n                                    : ");
		printf("XBE_INIT_64M_RAM_ONLY ");
		}
    	if (f & XBE_INIT_DONT_SETUP_HDD) {
    		printf("\n                                    : ");
		printf("XBE_INIT_DONT_SETUP_HDD ");
		}	
	}
}

void printMediaTypes(int f) {
    if (!f) {
	printf("\n                                    : ");
    	printf("none"); 
    } else {
	printf("0x%08X",f);
    	if (f & XBE_MEDIA_HDD) {
    		printf("\n                                    : ");
    		printf("XBE_MEDIA_HDD ");                  
    		}
    	if (f & XBE_MEDIA_XBOX_DVD) {
    		printf("\n                                    : ");
    		printf("XBE_MEDIA_XBOX_DVD ");
    		}
    	if (f & XBE_MEDIA_ANY_CD_OR_DVD) {
    		printf("\n                                    : ");
    		printf("XBE_MEDIA_ANY_CD_OR_DVD ");
    		}
    	if (f & XBE_MEDIA_CD) {
    		printf("\n                                    : ");
    		printf("XBE_MEDIA_CD ");
    		}
    	if (f & XBE_MEDIA_1LAYER_DVDROM) {
    		printf("\n                                    : ");
    		printf("XBE_MEDIA_1LAYER_DVDROM ");
    		}
    	if (f & XBE_MEDIA_2LAYER_DVDROM) {
    		printf("\n                                    : ");
    		printf("XBE_MEDIA_2LAYER_DVDROM ");
    		}
    	if (f & XBE_MEDIA_1LAYER_DVDR) {
    		printf("\n                                    : ");
    		printf("XBE_MEDIA_1LAYER_DVDR ");
    		}
    	if (f & XBE_MEDIA_2LAYER_DVDR) {
    		printf("\n                                    : ");
    		printf("XBE_MEDIA_2LAYER_DVDR ");
    		}
    	if (f & XBE_MEDIA_USB) {
    		printf("\n                                    : ");
    		printf("XBE_MEDIA_USB ");
    		}
    	if (f & XBE_MEDIA_ALLOW_UNLOCKED_HDD) {
    		printf("\n                                    : ");
    		printf("XBE_MEDIA_ALLOW_UNLOCKED_HDD ");
    		}
    }
}

void printGameRegion(int f) {
    if (!f) {
    	printf("\n                                    : ");
	printf("none");
    } else {
	printf("0x%08X",f);
    	if (f & XBE_REGION_US_CANADA) {
    		printf("\n                                    : ");
    		printf("XBE_REGION_US_CANADA ");
    		}
    	if (f & XBE_REGION_JAPAN) {
    		printf("\n                                    : ");
    		printf("XBE_REGION_JAPAN ");
    		}    	
    	if (f & XBE_REGION_ELSEWHERE) {
    		printf("\n                                    : ");
    		printf("XBE_REGION_ELSEWHERE ");
    		}
    	if (f & XBE_REGION_DEBUG) {
    		printf("\n                                    : ");
    		printf("XBE_REGION_DEBUG ");
    		}    	
    }
}

void printFlags(int f) {
    if (!f) {
    		printf("\n                                    : ");
	   	printf("none"); 
    } else {
	printf("0x%08X",f);
    	if (f & XBE_SEC_WRITABLE) {
    		printf("\n                                    : ");
    		printf("XBE_SEC_WRITABLE ");
    		}
    	if (f & XBE_SEC_PRELOAD) {
    		printf("\n                                    : ");
    		printf("XBE_SEC_PRELOAD ");
    		}
    	if (f & XBE_SEC_EXECUTABLE) {
    		printf("\n                                    : ");
		printf("XBE_SEC_EXECUTABLE ");
		}
    	if (f & XBE_SEC_INSERTED_FILE) {
    		printf("\n                                    : ");
    		printf("XBE_SEC_INSERTED_FILE ");
    		}
    	if (f & XBE_SEC_RO_HEAD_PAGE) {
    		printf("\n                                    : ");
    		printf("XBE_SEC_RO_HEAD_PAGE ");
    		}
    	if (f & XBE_SEC_RO_TAIL_PAGE) {
    		printf("\n                                    : ");
    		printf("XBE_SEC_RO_TAIL_PAGE ");
    		}
    }
}

XBE_SECTION *findSection(void *xbe, uint32_t addr) {
    int i;
    XBE_HEADER *header = (XBE_HEADER*) xbe;
    XBE_SECTION *sechdr = (XBE_SECTION *)(((char *)xbe) + (int)header->Sections - (int)header->BaseAddress);
    for (i = 0; i < header->NumSections; i++, sechdr++) {
        if (addr < sechdr->VirtualAddress) { continue; }
        if (addr >= sechdr->VirtualAddress + sechdr->VirtualSize) { continue; }
        return sechdr;
    }
printf("Couldn't find 0x%X\n",addr);
    return NULL;
}

int dumpxbe (void *xbe,uint32_t  option_flag){
    int i;
    unsigned int j;
    int a;
 
    XBE_HEADER *header;
    XBE_CERTIFICATE *cert;
    XBE_SECTION *sechdr;
    //XBE_TLS *tls;
    XBE_LIBRARY *lib;
  
    uint32_t  KernelThunkTable;     
    uint8_t  sha_Message_Digest[20];
    uint32_t  xorkey;
    

    

     /* header */
         header = (XBE_HEADER*) xbe;

if (option_flag == 0x0000000A) {
	cert = (XBE_CERTIFICATE *)(((char *)xbe) + (int)header->Certificate - (int)header->BaseAddress);
	printf("#\n# "); printunicode(cert->TitleName); printf("\n#\n");
        printf("[Game-%08X]\n\n",cert->TitleId);
	printf("	NAME=");printunicode(cert->TitleName); printf("\n\n");
	printf("	ID=%08X\n",cert->TitleId); printf("\n");
	printf("	HASH_METHOD=HM_UNKNOWN\n\n");
	printf("	WHICH_KEY=KEY_SIG\n\n");
	printf("	KEY_SIG="); printhexm_strip(cert->SignatureKey, sizeof(cert->SignatureKey));
	printf("	KEY_LAN="); printhexm_strip(cert->LanKey, sizeof(cert->LanKey));
	printhex_cert((uint8_t *)cert->AlternateSignatureKeys, sizeof(cert->AlternateSignatureKeys));
	printf("\n");
	return 0;
}
				   
if (option_flag & 0x00000001) {

         printf("\nXBE header\n~~~~~~~~~~\n");
         printf("Magic                               : %c%c%c%c\n", header->Magic[0], header->Magic[1], header->Magic[2], header->Magic[3]);
//         if (warn) if (strncmp("XBEH", header->Magic, 4)) printw("must be \"XBEH\"");
         printf("RSA digital signature               : ");   
        if (VerifySignaturex(xbe,0)== 1) printf("(Valid)");  else  printf("(Fail)");
         printhexm(header->HeaderSignature, sizeof(header->HeaderSignature));
         //for (i=0;i<sizeof(header->HeaderSignature);i++)  printf( "%02X",header->HeaderSignature[i]);
         
         printf("Base address                        : 0x%08X\n", ((uint32_t )header->BaseAddress));

         printf("Size of all headers:                : 0x%08X\n", header->HeaderSize);
         /* TODO */
         printf("Size of entire image                : 0x%08X\n", header->ImageSize);
  
         printf("Size of this header                 : 0x%08X\n",header->XbeHeaderSize);
         printf("Image timestamp                     : 0x%08X ",(uint32_t )header->Timestamp);
         printdate(header->Timestamp);
         printf("Pointer to certificate data         : 0x%08X\n", (uint32_t )header->Certificate);
         printf("Number of sections                  : 0x%08X\n", (uint32_t )header->NumSections);
         printf("Pointer to section headers          : 0x%08X\n", (uint32_t )header->Sections);
         printf("Initialization flags                : ");

         printInitFlags(header->InitFlags); printf("\n");

}
   //      EntryPoint = (uint32_t )header->EntryPoint ^ 0xa8fc57ab; /* debug: 0x0x94859d4b */
if (option_flag & 0x00000001) {                      
	 xorkey=xorentry(0);
         printf("Entrypoint                          : 0x%08X \n"
         	"                                    : 0x%08X  (Actual)\n"
         	"                                    : 0x%08X  (Retail)\n"
         	"                                    : 0x%08X  (Debug)\n", 
         (uint32_t )header->EntryPoint,
         (uint32_t )header->EntryPoint^xorkey,
         (uint32_t )header->EntryPoint^0xa8fc57ab,
         (uint32_t )header->EntryPoint^0x94859d4b);
         
         printf("Pointer to TLS directory            : 0x%08X\n", (uint32_t )header->TlsDirectory);
         printf("Stack commit size                   : 0x%08X\n", (uint32_t )header->StackCommit);
         printf("Heap reserve size                   : 0x%08X\n", (uint32_t )header->HeapReserve);
         printf("Heap commit size                    : 0x%08X\n", (uint32_t )header->HeapCommit);
         printf("PE base address                     : 0x%08X\n", (uint32_t )header->PeBaseAddress);
         printf("PE image size                       : 0x%08X\n", (uint32_t )header->PeImageSize);
         printf("PE checksum                         : 0x%08X\n", (uint32_t )header->PeChecksum);
         printf("PE timestamp                        : 0x%08X ",(uint32_t )header->PeTimestamp);
         	printdate(header->PeTimestamp);
         printf("PC path and filename to EXE         : 0x%08X (\"%s\")\n",(uint32_t)header->PcExePath, ((char *)xbe)+(uintptr_t)header->PcExePath-(uintptr_t)header->BaseAddress);
         printf("PC filename to EXE                  : 0x%08X (\"%s\")\n", (uint32_t)header->PcExeFilename,((char *)xbe)+(uintptr_t)header->PcExeFilename-(uintptr_t)header->BaseAddress);
         printf("PC filename to EXE (Unicode)        : 0x%08X (\"",(uint32_t)header->PcExeFilenameUnicode);
         printunicode( (short int*) (((char *)xbe)+(uintptr_t)header->PcExeFilenameUnicode-(uintptr_t)header->BaseAddress));
         printf("\")\n");
}         
         //KernelThunkTable = (uint32_t )header->KernelThunkTable ^ 0x5b6d40b6; /* debug: 0xEFB1F152 */

         xorkey=xorthunk(0);
         KernelThunkTable = (uint32_t )header->KernelThunkTable ^ xorkey; 

if (option_flag & 0x00000001) {

         printf("Pointer to kernel thunk table       : 0x%08X \n"
         	"                                    : 0x%08X  (Actual)\n"
         	"                                    : 0x%08X  (Retail)\n"
         	"                                    : 0x%08X  (Debug)\n", 
         (uint32_t )header->KernelThunkTable,
         (uint32_t )header->KernelThunkTable^xorkey,
         (uint32_t )header->KernelThunkTable^0x5b6d40b6,
         (uint32_t )header->KernelThunkTable^0xEFB1F152);

         /* FIXME: Move elsewhere */
         /* FIXME: Allow use of other keys from cli! */
         uint32_t kt = KernelThunkTable;
         while(1) {
             XBE_SECTION *kt_section = findSection(xbe, kt);
             if (kt_section == NULL) {
                 printf("Kernel thunk table broken!\n");
                 break;
             }
             uint32_t* kt_entry = (uint32_t *)((uint8_t *)xbe + kt_section->FileAddress + kt - kt_section->VirtualAddress);
             if (*kt_entry == 0) {
                 break;
             }
             const char *name;
             unsigned int index = *kt_entry & 0x7FFFFFFF;
             if (index < sizeof(xboxkrnlExports) / sizeof(const char*)) {
                name = xboxkrnlExports[index];
             } else {
                name = NULL;
             }
             printf("Kernel import                       : 0x%08X (@%d%s%s)\n",
             *kt_entry,
             index,
             name ? ", " : "",
             name ? name : "");
             kt += 4;
         }

         
         printf("Non-kernel import table (debug only): 0x%08X\n", (uint32_t )header->DebugImportTable);
         printf("Number of library headers           : 0x%08X\n", header->NumLibraries);
         printf("Pointer to library headers          : 0x%08X\n", (uint32_t )header->Libraries);
         printf("Pointer to kernel library header    : 0x%08X\n", (uint32_t )(header->KernelLibrary));
         printf("Pointer to XAPI library header      : 0x%08X\n", (uint32_t )(header->XapiLibrary));
         printf("Pointer to logo bitmap              : 0x%08X\n", (uint32_t )(header->LogoBitmap));
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
         for (j = 0; j< sizeof(cert->LanKey);j++) printf("%02X ",cert->LanKey[j]);
         printf("\n");
         printf("Signature key                       : "); 
         for (j = 0; j< sizeof(cert->SignatureKey);j++) printf("%02X ",cert->SignatureKey[j]);
         printf("\n");
	 printf("Alternate signature keys            : "); 
         printhexm((uint8_t *)cert->AlternateSignatureKeys, sizeof(cert->AlternateSignatureKeys));

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
         printf("Section name Address                : 0x%08X (\"%s\")\n",(int)sechdr->SectionName, ((uint8_t  *)xbe)+(int)sechdr->SectionName-(int)header->BaseAddress);
         printf("Section reference count             : 0x%08X\n", sechdr->SectionReferenceCount);
         printf("Head shared page reference count    : 0x%08X\n", (uint32_t )sechdr->HeadReferenceCount);
         printf("Tail shared page reference count    : 0x%08X\n", (uint32_t )sechdr->TailReferenceCount);

         printf("SHA1 hash                           : "); 
             
             shax(&sha_Message_Digest[0], ((uint8_t  *)xbe)+(int)sechdr->FileAddress ,sechdr->FileSize);
             
             for (a=0;a<20;a++) printf("%02X",sechdr->ShaHash[a]);

             	if (memcmp(&sha_Message_Digest[0],&sechdr->ShaHash[0],20)==0) {
	  		 printf("  (Valid)"); 
		} else {       
			//fail=1; 
			printf("   (False)"); 
       printf("\nSHA1 hash (Needed)                  : "); 
           for (a=0;a<20;a++) printf("%02X",sha_Message_Digest[a]);             
		}
             
             printf("\n");
	}           
       
         }

         lib = (XBE_LIBRARY *)(((char *)xbe) + (uint32_t)header->Libraries - (uint32_t)header->BaseAddress);
     
         for (i = 0; i < header->NumLibraries; i++, lib++) {

       if (option_flag & 0x00000008) { 
     	printf("\nLibrary %i\n~~~~~~~~~~\n", i);
        printf("Library name                        : \""); printn((char*)lib->Name, sizeof(lib->Name)); printf("\"\n");
        printf("Major Version                       : 0x%08X\n", lib->MajorVersion);
        printf("Middle Version                      : 0x%08X\n", lib->MiddleVersion);
        printf("Minor Version                       : 0x%08X\n", lib->MinorVersion);
        printf("Flags                               : 0x%08X\n", lib->Flags);
       }
       
       }


    //     tls = (XBE_TLS *)(((char *)xbe) + (int)header->TlsDirectory - (int)header->BaseAddress);
        //tls = (XBE_TLS *)(((char *)xbe) + (int)header->TlsDirectory - KernelThunkTable );//
     	//(int)header->BaseAddress);
         
	if (option_flag & 0x00000001) {
     /*
         printf("\nThread Local Storage Directory - Still Buggy\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
         printf("Raw data start address              : 0x%08X\n", tls->RawStart);
         printf("Raw data end address                : 0x%08X\n", tls->RawEnd);
         printf("TLS index address                   : 0x%08X\n", tls->TlsIndex);
         printf("TLS callbacks address               : 0x%08X\n", tls->TlsCallbacks);
         printf("Size of zero fill                   : 0x%08x\n", tls->SizeZeroFill);
         //printf("Characteristics                     : 0x%08X\n", (uint8_t  *)xbe+(uint32_t )tls->Characteristics-(uint32_t )header->BaseAddress);
         printf("Characteristics                     : %s\n", tls->Characteristics);
         */
	}    
             
   //   free(xbe);  
      

    return 0;
}

