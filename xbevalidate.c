/* Note: this code will work on little-endian 32-bit machines only! */
#include <errno.h>
#include <stdio.h>

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>


#include "xbestructure.h"
#include "xboxlib.h"


int validatexbe(char *filename,unsigned int option_flag){
    FILE *f;
    int filesize;
//    int warn;
    int i;
    void *xbe;
    
    XBE_HEADER *header;
    XBE_CERTIFICATE *cert;
    XBE_SECTION *sechdr;
 //   XBE_TLS *tls;
 //   XBE_LIBRARY *lib;
//    unsigned char sha1hashout[20];
//    unsigned char md5hashout[16];

//    unsigned int EntryPoint;
//    unsigned int KernelThunkTable;
    unsigned char sha_Message_Digest[20];
    int eax;
    
    
/* title */

/* read file */
    f = fopen(filename, "r");
    if (f!=NULL) 
    {    
        fseek(f, 0, SEEK_END); filesize = ftell(f); fseek(f, 0, SEEK_SET);
        xbe = malloc(filesize);
       
         
        fread(xbe, 1, filesize, f);
       
         
        fclose(f);
       
        printf("Validating file %s (%i bytes)\n", filename, filesize);

	header = (XBE_HEADER*) xbe;
	 
       	 // If the magic value XBEH is not present, error
	printf("Magic XBEH value:      ");
	if (memcmp(header->Magic, "XBEH", 4)==0) { printf("pass\n"); } else { printf("fail\n"); }
	
	// If the header has the correct size, error ???  
	printf("Header Size:           ");
	if (header->XbeHeaderSize == 0x178) { printf("pass\n"); } else { printf("fail\n"); }
		
	// If the image base is not 00010000,
	printf("Image Base Address:    ");
	if (((int)header->BaseAddress)== 0x10000)  { printf("pass\n"); } else { printf("fail\n"); }
	
	//eax = header->HeaderSize;
	eax = header->XbeHeaderSize;
	eax += 0x10000;
	
	// Validates the Certificate Entry Address 
	printf("Certificate Adress:    ");
	if (eax == (int)header->Certificate) { printf("pass\n"); } else { printf("fail\n"); }

	printf("Certificate Size  :    ");
	cert = (XBE_CERTIFICATE *)(((char *)xbe) + (int)header->Certificate - (int)header->BaseAddress);
	if (cert->Size==0x1d0) { printf("pass\n"); } else { printf("fail\n"); }
		
	// Validates the Section Header Address 
	printf("Section Address:       ");
	eax +=0x1D0;
	if (eax == (int)header->Sections) { printf("pass\n"); } else { printf("fail\n"); }
	

	// Check, that Debug Address is not set
	printf("Debug Address:         ");
	if ((int)header->DebugImportTable== 0) { printf("pass\n"); } else { printf("fail\n"); }

	// XOR Entry Address
	//header->EntryPoint = (void *)((int) header->EntryPoint ^0xA8FC57AB); 
	// XOR Kernel Image thunk Address
	//header->KernelThunkTable = (unsigned int *)((int) header->KernelThunkTable ^ 0x5B6D40B6);
	
	printf("Kernel Entry:          %08X\n",(int)header->EntryPoint^0xA8FC57AB);
	printf("Kernel Thunk Table:    %08X\n",(int)header->KernelThunkTable^ 0x5B6D40B6);
	// Check the Hash of the Sections
         sechdr = (XBE_SECTION *)(((char *)xbe) + (int)header->Sections - (int)header->BaseAddress);
    	 
         for (i = 0; i < header->NumSections; i++, sechdr++) {
	  	shax(&sha_Message_Digest[0], ((unsigned char *)xbe)+(int)sechdr->FileAddress ,sechdr->FileSize);
	  	
	  	printf("Section: %2d Hash:      ",i);
	  	
	  	if (memcmp(&sha_Message_Digest[0],&sechdr->ShaHash[0],20)==0) { printf("pass\n"); 
		} else { 
		printf("fail"); 
		if (option_flag & 0x00020000) {
			memcpy(&sechdr->ShaHash[0],&sha_Message_Digest[0],20);
			printf(" -> corrected"); 
		}
		printf("\n"); 
		}
	
	 }	
	
	printf("2048 RSA Signature:    ");
	if (VerifySignaturex(xbe,0)== 1) { 
		printf("pass\n"); 
	} else { 
		printf("fail\n"); 
		VerifySignaturex(xbe,1);
		if (option_flag & 0x00080000) {
			printf("Correcting Signature:\n"); 
			GenarateSignaturex(xbe);
			
		}
		
		
	}
	
	if (option_flag & 0x00020000){
	 f = fopen("out.xbe", "w");
	 fwrite(xbe, 1, filesize, f);
         
         fclose(f);	
		
	}
	free(xbe);
	
	
    }
	return 0;
}

