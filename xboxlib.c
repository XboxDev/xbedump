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

#include <openssl/sha.h>


void shax(unsigned char *result, unsigned char *data, unsigned int len)
{
	SHA_CTX	sha_ctx;
	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, (unsigned char *)&len, 4);
	SHA1_Update(&sha_ctx, data, len);
	SHA1_Final(result, &sha_ctx);	
	
}

void hmacx( unsigned char *result,
		unsigned char *key, int key_length, 
		unsigned char *text1, int text1_length,
		unsigned char *text2, int text2_length )
{
	/* Note: The Result has to be the size of byte[20] */
	unsigned char state1[0x40];
	unsigned char state2[0x40+0x14];
	int i;
	SHA_CTX	sha_ctx;
	
	for(i=0x40-1; i>=key_length;--i) state1[i] = 0x36;
	for(;i>=0;--i) state1[i] = key[i] ^ 0x36;
	
	/*quick_SHA1 ( &state2[0x40],
			state1,		0x40,
			text1,		text1_length,
			text2,		text2_length,
			NULL );
	*/
	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx,state1,0x40);
	SHA1_Update(&sha_ctx,text1,text1_length);
	SHA1_Update(&sha_ctx,text2,text2_length);
	SHA1_Final(&state2[0x40], &sha_ctx);
	 
	for(i=0x40-1; i>=key_length;--i) state2[i] = 0x5C;
	for(;i>=0;--i) state2[i] = key[i] ^ 0x5C;
	
	/*quick_SHA1 ( result,
			state2,		0x40+0x14,
			NULL );
	*/
	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx,state2,0x40+0x14);
	SHA1_Final(result, &sha_ctx);		
}  
