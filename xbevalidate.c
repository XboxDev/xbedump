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
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>


#include "xbestructure.h"
#include "xboxlib.h"


int validatexbe(void *xbe,unsigned int filesize,unsigned int option_flag){
    FILE *f;
    
//    int warn;
    int i;
    
    int fail=0;
    unsigned int xorkey;
        
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
    
    


	header = (XBE_HEADER*) xbe;
	 
       	 // If the magic value XBEH is not present, error
	printf("Magic XBEH value:      ");
	if (memcmp(header->Magic, "XBEH", 4)==0) { printf("pass\n"); } else { fail=1; printf("fail\n"); }
	
#if 0
	// If the header has the correct size, error ???  
	printf("Header Size:           ");
	if (header->XbeHeaderSize == 0x178) { printf("pass\n"); } else { fail=1; printf("fail (0x%X)\n",header->XbeHeaderSize); }
#endif		

	// If the image base is not 00010000,
	printf("Image Base Address:    ");
	if (((int)header->BaseAddress)== 0x10000)  { printf("pass\n"); } else { fail=1; printf("fail\n"); }
	
	//eax = header->HeaderSize;
	eax = header->XbeHeaderSize;
	eax += 0x10000;
	
	// Validates the Certificate Entry Address 
	printf("Certificate Address:   ");
	if (eax == (int)header->Certificate) { printf("pass\n"); } else { fail=1; printf("fail\n"); }

	// Only continue if xbe is valid
	//if (fail == 1) { fprintf(stderr,"Invalid xbe\n"); exit(1); }
	
	printf("Certificate Size  :    ");
	cert = (XBE_CERTIFICATE *)(((char *)xbe) + (int)header->Certificate - (int)header->BaseAddress);
	if (cert->Size>=0x1d0) { printf("pass\n"); } else { fail=1; printf("fail\n"); }
	
	// Correct it, if Correct Bit Set
	if (option_flag & 0x00020000) {
		if (option_flag & 0x20000000) { // Habibi Option 
			printf("Correcting Mediatypes and Regions  \n");
			cert->MediaTypes = 0x800000FF;
			cert->GameRegion = 0x80000007;
		}
	}
	// Validates the Section Header Address 
	printf("Section Address:       ");
	//eax +=0x1D0;
	eax += cert->Size;
	if (eax == (int)header->Sections) { printf("pass\n"); } else { fail=1; printf("fail\n"); }
	

	// Check, that Debug Address is not set
	printf("Debug Address:         ");
	if ((int)header->DebugImportTable== 0) { printf("pass\n"); } else { fail=1; printf("fail\n"); }

	// XOR Entry Address
	//header->EntryPoint = (void *)((int) header->EntryPoint ^0xA8FC57AB); 
	// XOR Kernel Image thunk Address
	//header->KernelThunkTable = (unsigned int *)((int) header->KernelThunkTable ^ 0x5B6D40B6);

	if (option_flag & 0x00100000) {
		// Patch XOR keys   
		printf("Patch XOR Keys\n");
		header->EntryPoint ^= xorentry(1);
		header->KernelThunkTable ^= xorthunk(1);

	}
	xorkey=xorentry(0);
	printf("Kernel Entry:          %08X  (KEY: %08X)\n",(int)header->EntryPoint^xorkey,xorkey);
	xorkey=xorthunk(0);
	printf("Kernel Thunk Table:    %08X  (KEY: %08X)\n",(int)header->KernelThunkTable^xorkey,xorkey);
	// Check the Hash of the Sections                      
	
	//printf("THUNK-ENTRY XOR: %08X\n",xorthunk()) ;
	//printf("DEGUG-ENTRY XOR: %08X\n",xorentry()) ;
	
         sechdr = (XBE_SECTION *)(((char *)xbe) + (int)header->Sections - (int)header->BaseAddress);
    	 
         for (i = 0; i < header->NumSections; i++, sechdr++) {
	  	shax(&sha_Message_Digest[0], ((unsigned char *)xbe)+(int)sechdr->FileAddress ,sechdr->FileSize);
	  	
	  	printf("Section: %2d Hash:      ",i);
	  	
	  	
	  	if (memcmp(&sha_Message_Digest[0],&sechdr->ShaHash[0],20)==0) {
	  		 printf("pass"); 
		} else {       
			fail=1; 
			printf("fail"); 
		}

	  	// Debug Message D1
	  	if (option_flag & 0x01000000) {
	  		printf("\n             in File -> "); 
	  		for (int a=0;a<20;a++) printf("%02x",sechdr->ShaHash[a]);
	  		printf("\n           should be -> "); 
	  		for (int a=0;a<20;a++) printf("%02x",sha_Message_Digest[a]);
	  	
	  	}
		
		// Correct it, if Correct Bit Set
		if (option_flag & 0x00020000) {
			memcpy(&sechdr->ShaHash[0],&sha_Message_Digest[0],20);
			printf(" -> corrected"); 
		}
	
		printf("\n"); 
	 }	

	if (option_flag & 0x00080000) {
		printf("Correcting Signature:\n"); 
		GenarateSignaturex(xbe);
	}
	
	printf("2048 RSA Signature:    ");
	if (VerifySignaturex(xbe,0)== 1) { 
		printf("pass"); 
		// Debug Message D1
	  	if (option_flag & 0x01000000) {
			VerifySignaturex(xbe,1);
		}
	} else { 
		fail=1; 
		printf("fail"); 
	  	if (option_flag & 0x01000000) {
			VerifySignaturex(xbe,1);
		}
	}                   
	

	printf("\n");
	if (!(option_flag & 0x00020000)){
		if (fail==0) {
			printf("\nXBE file integrity:    OK\n");
		}
		else {
			printf("\nXBE file integrity:    FALSE !!!!!!! FALSE !!!!!\n");
		}
	}
	
	if (option_flag & 0x00020000){
		f = fopen("out.xbe", "wb");
		if (f==NULL) {
			fprintf(stderr,"\nError writing out.xbe - %s\n",strerror(errno));
			exit(1);
		}
		else {
			fwrite(xbe, 1, filesize, f);
			fclose(f);	
		}	
	}

	
	
    
	return 0;
}


