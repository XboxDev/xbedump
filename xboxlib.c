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
#include "xboxlib.h"
#include "xbestructure.h"
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include "openssl/e_os.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

int __gxx_personality_v0=0;  

typedef struct RSA_PUBLIC_KEY
{
	char Magic[4];
	unsigned int Bitlen;
	unsigned char x[4];
	unsigned char y[4];
	unsigned char Exponent[4];
	unsigned char Modulus[256];
	unsigned char z[10];
};

struct RSA_PUBLIC_KEY xePublicKeyData;



int read_xboxpublickeydata(char *filename)
{
	FILE *f;
	unsigned char *flash=0;
	int filesize;
	int counter;
	
	//memcpy(&xePublicKeyData,xboxPublicKeyData,280);
	
	f = fopen(filename, "r");
    	if (f!=NULL) 
    	{    
        	fseek(f, 0, SEEK_END); filesize = ftell(f); fseek(f, 0, SEEK_SET);
        	
        	flash = (unsigned char*) malloc(filesize);
        	
	     	fread(flash, 1, filesize, f);
 	        fclose(f);
 	        
 	        for (counter=0; counter<filesize-6;counter++){
 	           	if ( (flash[counter+0] == 0x52) &
 	        	     (flash[counter+1] == 0x53) &
 	        	     (flash[counter+2] == 0x41) &
 	        	     (flash[counter+3] == 0x31) &
 	        	     (flash[counter+4] == 0x08) &
  	        	     (flash[counter+5] == 0x01) ) 
 	        	     {
 	        	     	memcpy(&xePublicKeyData,&flash[counter],280);
				break; 	        	       
 	        	     //	printf("RSA Found at %x",counter);
 	        	     }
 	        }
 	        free(flash);
 	        return 1;
	}
	free(flash);
	return 0;
	
}



int decrypt_signature(unsigned char *c_number,unsigned char *cryptbuffer){
  
    BN_CTX *ctx;
    BIO *out;
    BIGNUM *rsa_signature,*rsa_exp,*rsa_mod,*rsa_out; //*rsa_hash;
    int count;

    unsigned char c_modulo[256];
    unsigned char d_modulo[256];
    unsigned char c_exponent[4];
    unsigned char d_exponent[4];
    unsigned char d_number[256];
    
    memcpy(&c_modulo,xePublicKeyData.Modulus,256);
    memcpy(&c_exponent,xePublicKeyData.Exponent,4);
    
    // convert from Intel Big Endian Format
    for (count=0;count<256;count++) d_modulo[count]=c_modulo[255-count];
    for (count=0;count<256;count++) d_number[count]=c_number[255-count];
    for (count=0;count<4;count++) d_exponent[count]=c_exponent[3-count];
    
    
    ctx=BN_CTX_new();
    rsa_signature=BN_new();
    rsa_exp=BN_new();
    rsa_mod=BN_new();
    rsa_out=BN_new();
            
    out=BIO_new(BIO_s_file());
    BIO_set_fp(out,stdout,BIO_NOCLOSE);
    
    rsa_signature=BN_bin2bn(d_number,256,rsa_signature); 
    rsa_exp=BN_bin2bn(d_exponent,4,rsa_exp); 
    rsa_mod=BN_bin2bn(d_modulo,256,rsa_mod); 
 
    BN_mod_exp(rsa_out,rsa_signature,rsa_exp,rsa_mod,ctx);
  
  /*   
    //printf("\n");
    printf("Crypted:\n");
    BN_print(out,rsa_signature);printf("\n"); 
    printf("Exponent:\n");
    BN_print(out,rsa_exp);printf("\n"); 
    printf("Modulus:\n");
    BN_print(out,rsa_mod);printf("\n");
    printf("\n");
    printf("Result:\n");
    BN_print(out,rsa_out);printf("\n"); 
    
    */
    
    // as the first 00 are striped off, attach again to the string

    for (count=0;count<256;count++) cryptbuffer[count]=0x00;
    int len=BN_bn2bin(rsa_out, d_number);
    for (count=0;count<len;count++) cryptbuffer[256-len+count]=d_number[count]; 
     
    return 1;
}

int Verifyhash(unsigned char *hash,unsigned char *cryptbuffer,int debugout){

  int a;
  if (debugout!=0) {
	
        printf("Real Header Hash:      ");
        for (a=0;a<20;a++) printf("%02X",hash[a]);
        printf("\nHash from RSA:         ");
        for (a=236;a<256;a++) printf("%02X",cryptbuffer[a]);
        printf("\n");
  }

  for (int a=0;a<20;a++) {
  
    	if (cryptbuffer[a+236]!=hash[a]) {
    		// Does not match
    		return 0;	
  	}
  }
  /* 
   Padding checking , brutal, but xbox does the same in concept
  */
  
  if (cryptbuffer[0]!= 0x00) return 0;
  if (cryptbuffer[1]!= 0x01) return 0;
  if (cryptbuffer[235]!= 0x00) return 0;
  for (a=2;a<235;a++) if (cryptbuffer[a]!= 0xFF) return 0;
  return 1;
  
}


int VerifySignaturex(void *xbe,int debugout) {
 	
 	unsigned char sha_Message_Digest[20];
   	XBE_HEADER *header;
	unsigned char crypt_buffer[256];
	
	//printf("Verify Signature Entry\n");
	
	header = (XBE_HEADER*) xbe;

	shax(&sha_Message_Digest[0], ((unsigned char *)xbe)+0x104 ,header->HeaderSize - 0x104);
        
	//printf("\nCall Encrypt RSA Signature\n");

	if (read_xboxpublickeydata("flash.bin") != 0) {
	
		decrypt_signature(header->HeaderSignature,crypt_buffer);
		// for (int a=0;a<256;a++) printf("%02x",crypt_buffer[a]);
		return Verifyhash(&sha_Message_Digest[0],crypt_buffer,debugout);

	} else {
		printf("Public key / Flash not found .. File 'flash.bin' ");
		return 0;
	}
}
	
	



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
	// Note: The Result has to be the size of byte[20]
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
