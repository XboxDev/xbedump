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


void usage(){
	
	printf("(C)2002 Franz Lehner franz@caos.at\n(C)2002 Michael Steil mist@c64.org\n\n");	
	 
	printf("  Usage:    xbe [xbefile] [options]\n\n");
	       
	printf("   -da          Dumps the compleate XBE Header Structure\n");
	printf("   -dh          Dumps the Header info\n");
	printf("   -dc          Dumps the Certificate\n");
	printf("   -ds          Dumps the Sections\n");
	printf("   -dl          Dumps the Libary Sections\n\n");
	       
	printf("   -vh          Verifies the Section Hash\n");
	printf("   -wb          Writes back the update to file out.xbe \n\n");
	printf("\n  For checking the RSA 2048 bit Signature,\n  you need the original decompressed Flash stored in flash.bin in the same directory \n");
	printf("\n  Note: this code will work on little-endian 32-bit machines only! \n  Take an old Pentium\n\n");
	
	
}

int main (int argc, const char * argv[])
{
  int counter;
	unsigned int dumpflag=0;
	char filename[512];

	printf("XBE Dumper 0.3b  (C)2002 Franz Lehner franz@caos.at\n                 based on XBE validator by Michael Steil\n\n");

//      dumpxbe("secret/xboxdash.xbe");
      //validatexbe("secret/xboxdash.xbe");

	if (argc > 2) {

		strcpy(&filename[0],argv[1]);

 	  	for (counter=2;counter<argc;counter++){
   	
		if (strcmp(argv[counter],"-da")==0)  dumpflag |= 0x0000ffff;
 	  	if (strcmp(argv[counter],"-dh")==0)  dumpflag |= 0x00000001;
 	  	if (strcmp(argv[counter],"-dc")==0)  dumpflag |= 0x00000002;
 	  	if (strcmp(argv[counter],"-ds")==0)  dumpflag |= 0x00000004;
		if (strcmp(argv[counter],"-dl")==0)  dumpflag |= 0x00000008;

		if (strcmp(argv[counter],"-vh")==0)  dumpflag |= 0x00010000;
 		if (strcmp(argv[counter],"-wb")==0)  dumpflag |= 0x00020000;

		}

		if (dumpflag & 0x0000FFFF) dumpxbe(&filename[0],dumpflag);
		if (dumpflag & 0xffff0000) validatexbe(&filename[0],dumpflag);

	} else {

		usage();

	}

	printf("\n");
	return 0;
}




