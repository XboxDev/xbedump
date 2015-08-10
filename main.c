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

#include "xbestructure.h"
#include "xboxlib.h"


void usage(){
	
 printf(
	"Usage: xbe [xbefile] [options]\n\n"
	
	"  -da          Dumps the complete XBE Header Structure\n"
	"  -dh          Dumps the Header info\n"
	"  -dc          Dumps the Certificate\n"
	"  -ds          Dumps the Sections\n"
	"  -dl          Dumps the Library Sections\n\n"
	
	"  -vh          Verifies the .xbe Header \n"
	"  -wb          Writes back the update to file out.xbe \n\n"
	
	"  -sm          Uses Microsoft Signature (default mode)\n"
	"               (Note: Signing not possible, as we do not have the private key)\n"
	"  -shabibi     Uses the Habibi Signature Keys\n"
	"  -st          Uses the Test Keys i have created .. leaves the XOR unchanged\n\n"
		
	"  -d1          Debug output for option -vh\n\n"
	
	"  ---- Special Options -----\n\n"
	
	"  -habibi      Special Option, Signs the xbe with Habibi Key and Sets all media flags\n"
	"  -sign        Special Option, Signs the xbe with the key who is stored in the xboxlib.c\n"
	"               patches the XOR Keys\n"
	"  -xbgs        Dumps xbgs output\n"
	"  ?            Display Help\n\n"

	"Note: This code will work on little-endian 32-bit machines only! \n\n"
	
	"(C)2002,2003 by XBL Team (hamtitampti) \n");
	
	
}

int main (int argc, const char * argv[])
{
  	int counter=0;
	unsigned int dumpflag=0;
	char filename[512];
	int verifyagain=0;
	void* xbefile;
	unsigned int filesize;
	
//      dumpxbe("secret/xboxdash.xbe");
      //validatexbe("secret/xboxdash.xbe");
	if (argc == 2) {
		if (strcmp(argv[1],"--test")==0) { 
			return 0; 
		}
	}

	if (argc > 2) {

		strcpy(&filename[0],argv[1]);

 	  	for (counter=2;counter<argc;counter++){
   	
		if (strcmp(argv[counter],"-da")==0)  dumpflag |= 0x000000ff;
 	  	if (strcmp(argv[counter],"-dh")==0)  dumpflag |= 0x00000001;
 	  	if (strcmp(argv[counter],"-dc")==0)  dumpflag |= 0x00000002;
 	  	if (strcmp(argv[counter],"-ds")==0)  dumpflag |= 0x00000004;
		if (strcmp(argv[counter],"-dl")==0)  dumpflag |= 0x00000008;
		
		if (strcmp(argv[counter],"-sm")==0)  dumpflag |= 0x00000000;
		if (strcmp(argv[counter],"-st")==0)  dumpflag |= 0x10000000;
		if (strcmp(argv[counter],"-shabibi")==0)  dumpflag |= 0x20000000;
						
		if (strcmp(argv[counter],"-vh")==0)  dumpflag |= 0x00010000;
 		if (strcmp(argv[counter],"-wb")==0)  dumpflag |= 0x00020000;
 	  	if (strcmp(argv[counter],"-xbgs")==0) dumpflag |= 0x0000000A;
 		
 		
 		if (strcmp(argv[counter],"-d1")==0)  dumpflag |= 0x01000000;
 		
 		if (strcmp(argv[counter],"?")==0)  {
 				usage();
 				return 0;
 			}
		
		if (strcmp(argv[counter],"-sign")==0) { 
				dumpflag=0;
				dumpflag |= 0x00010000;  // Verify Header
				dumpflag |= 0x00020000;  // Write Back
				dumpflag |= 0x00040000;  // Generate Certificate
				dumpflag |= 0x00080000;  // Generate Signature
				dumpflag |= 0x00100000;  // Patch the XOR Keys
				dumpflag |= 0x10000000;  // Use Linux Test Keys
				verifyagain=1;
			}

		if (strcmp(argv[counter],"-habibi")==0) { 
				dumpflag=0;
				dumpflag |= 0x00010000;  // Verify Header
				dumpflag |= 0x00020000;  // Write Back
				dumpflag |= 0x00040000;  // Generate Certificate
				dumpflag |= 0x00080000;  // Generate Signature
				dumpflag |= 0x00100000;  // Patch the XOR Keys
				dumpflag |= 0x20000000;  // Gernerate Habibi Keys
				verifyagain=1;
			}

			
		}      // End For Loop

	
	
	
		if(dumpflag != 0x0000000A) {
				printf("XBE Dumper 0.5-BETA Release\n");
		}

		//read_rsafromflash("flash.bin",dumpflag);
		load_rsa(dumpflag);
		
		if (dumpflag & 0x00000FFF) {
				load_xbefile(xbefile,filesize,&filename[0]);
				dumpxbe(xbefile,dumpflag);
				}
		if (dumpflag & 0x0fff0000) {
				load_xbefile(xbefile,filesize,&filename[0]);						
				validatexbe(xbefile,filesize,dumpflag);
				}
						
		// Verify the signed file
		
		if (verifyagain==1) { 
				dumpflag=0;
				dumpflag |= 0x00010000;  // Verify Header
				dumpflag |= 0x10000000;  // Use Linux Test Keys
				strcpy(&filename[0],"out.xbe");
				printf("\n File out.xbe created, verifying it ...\n\n");
				free(xbefile);
				load_xbefile(xbefile,filesize,&filename[0]);
				validatexbe(xbefile,filesize,dumpflag);
				
			}
		
		

	} else {

		usage();

	}

	return 0;
}




