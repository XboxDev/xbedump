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
#include <openssl/hmac.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

int __gxx_personality_v0=0;  

// prototype

// Test Keys
unsigned char Testkey[] = {
 	0x52,0x53,0x41,0x31, 0x08,0x01,0x00,0x00, 0x00,0x08,0x00,0x00, 0xff,0x00,0x00,0x00,
 	0x01,0x00,0x01,0x00,
 	// Public Modulus "m"
 	0x69,0xD3,0x7D,0x0A,0x8E,0xED,0x3F,0x97,0x4E,0x59,0x9B,0x04,0x60,0xC4,0x1F,0x88,
	0xF8,0xB3,0xEF,0x62,0xF4,0xF8,0xC5,0xB1,0x2B,0x56,0xA5,0x5A,0x93,0x3A,0x84,0xE7,
	0x60,0xC0,0x0E,0x27,0x42,0x2E,0x18,0x8A,0x69,0x45,0xFB,0x0B,0xFB,0x6A,0x75,0x3B,
	0x02,0x69,0x4B,0x00,0x17,0xD8,0x94,0x3E,0x71,0xBC,0x00,0x57,0x93,0x0B,0xA2,0xD2,
	0x1B,0x4E,0xF8,0xB5,0xF5,0xCA,0x59,0xD8,0xA3,0x4A,0x7E,0xB3,0x3E,0x99,0x63,0x05,
	0x0C,0xCC,0x01,0x91,0x52,0x33,0x02,0xC0,0xC3,0xA3,0xD2,0x5D,0xDE,0xD9,0xA5,0x67,
	0x4A,0x8B,0xCB,0x44,0xB4,0xFF,0x6A,0x1A,0xDB,0xDE,0x64,0xD8,0x84,0x28,0x54,0xF7,
	0x67,0xB4,0xB2,0xDC,0x07,0xF9,0x55,0x00,0xC9,0xC0,0xB5,0xA0,0x19,0xAF,0x88,0xA9,
	0xE7,0xF9,0xDC,0x8D,0x19,0x78,0x20,0xC9,0x9A,0xD0,0x5D,0x23,0xA4,0x82,0x34,0xFC,
	0x2E,0x22,0xFD,0x43,0x19,0x71,0x81,0x64,0x39,0x53,0x7F,0x81,0xFD,0x06,0x36,0x54,
	0xBE,0x06,0x8A,0xE5,0xF0,0xE1,0xF8,0x8F,0xEC,0xA7,0xC2,0x87,0x27,0xA4,0x4D,0x29,
	0x62,0xE8,0x53,0x97,0x35,0x4F,0x8E,0x5D,0xC8,0x2C,0xC4,0x21,0x5B,0x01,0x83,0x81,
	0x99,0xA2,0xBB,0x18,0xC3,0x45,0x3D,0xA1,0x3C,0x70,0xB4,0x31,0x95,0x00,0x6C,0x04,
	0x65,0x13,0x48,0xF7,0xC9,0xF3,0x26,0x38,0x46,0x7D,0x27,0xBA,0xDA,0x3B,0xEA,0xB9,
	0xAC,0x1B,0x3B,0x7F,0xE8,0xC2,0x21,0x41,0xF2,0x21,0x41,0x6B,0xF6,0x13,0xC0,0xC9,
	0xB0,0xAA,0xAA,0x6C,0x7B,0x98,0xCA,0xD6,0xF8,0xAE,0x21,0x83,0x88,0x36,0x97,0xD7,
	// Private Key "d"
	0x29,0x13,0x16,0xAC,0x0E,0x52,0x2A,0x90,0x06,0x6C,0x56,0x35,0xFD,0xB8,0xD6,0x8F,
	0x9F,0x51,0x22,0x56,0x8E,0x11,0xD8,0x0C,0xC1,0xF0,0xF1,0xFC,0x90,0x83,0x61,0xF7,
	0x04,0xF9,0x74,0xE6,0xA4,0x3A,0x65,0xC5,0x18,0x35,0x06,0x7F,0xE0,0xE8,0x67,0x68,
	0x27,0xAE,0xB0,0xEF,0xFB,0xC6,0x55,0xD3,0x00,0xD4,0xF7,0x07,0x0C,0xF6,0x4A,0xD3,
	0xF6,0x1C,0x47,0xCF,0x39,0xA4,0xA9,0x9E,0xA1,0x5A,0xB3,0x29,0x29,0x43,0x80,0x61,
	0xA0,0x55,0x17,0xA6,0x3A,0x78,0x8E,0x45,0xB1,0x66,0x12,0x2F,0xE9,0x42,0xE8,0xD5,
	0xCC,0xEE,0xC3,0x8C,0xFD,0x0D,0x74,0xD1,0xAA,0xAB,0x6F,0x6C,0xC3,0xBB,0x57,0xFE,
	0xC5,0x89,0xE0,0x7E,0x94,0x40,0xCD,0x6A,0x99,0x6E,0x29,0xF2,0xCB,0x81,0x50,0x0F,
	0x61,0xB2,0xF8,0x00,0x2D,0x8C,0x0E,0xB2,0x0B,0x64,0xB0,0xFC,0xEE,0x38,0x92,0x38,
	0x66,0xD3,0xA9,0xAD,0x20,0x0A,0x82,0x33,0xDB,0x25,0x19,0x11,0xBE,0x48,0xA7,0xA7,
	0xF1,0x09,0x7A,0x28,0xAF,0x4F,0x9F,0x05,0x6C,0xEF,0x4D,0x72,0xF3,0x64,0xFA,0xA9,
	0x8A,0x71,0x08,0x10,0xE0,0xBA,0xAE,0xAF,0xB8,0xE6,0x2A,0x3E,0xA8,0xB0,0x36,0x7C,
	0x5A,0x4F,0xDB,0xD6,0xF7,0x82,0x8C,0xC3,0x51,0x69,0x61,0x79,0x23,0x02,0x84,0x0F,
	0x81,0x07,0x64,0xEC,0x4A,0xB2,0x21,0x7E,0x94,0xC4,0x16,0x79,0x89,0xA3,0xED,0xF7,
	0xF5,0x62,0x5E,0xB8,0x39,0x68,0x3E,0x76,0x18,0x3B,0xDF,0x6D,0x70,0x1F,0xB2,0x26,
	0x29,0x1C,0xDA,0x27,0x20,0xC9,0x6F,0x11,0xEE,0x1B,0xEB,0xFB,0x00,0x6A,0xDA,0x72
 	
};

typedef struct RSA_PUBLIC_KEY
{
	char Magic[4];  		// "RSA1"
	unsigned int Bloblen; 		// 264 (Modulus + Exponent + Modulussize)
	unsigned char Bitlen[4];  	// 2048
	unsigned char ModulusSize[4];  	// 255 (bytes in the Modulus)
	unsigned char Exponent[4];
	unsigned char Modulus[256];     // Bit endian style
	unsigned char Privatekey[256];  // Private Key .. we do not have it -- Big endian style
};

struct RSA_PUBLIC_KEY xePublicKeyData;

// DE - Crypting
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
// END DE-Crypting


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


int crypt_signature(unsigned char *c_number,unsigned char *cryptbuffer){
  
    BN_CTX *ctx;
    BIO *out;
    BIGNUM *rsa_signature,*rsa_pri,*rsa_mod,*rsa_out; //*rsa_hash;
    int count;

    unsigned char c_modulo[256];
    unsigned char d_modulo[256];
    unsigned char c_private[256];
    unsigned char d_private[256];
    unsigned char d_number[256];
    
    memcpy(&c_modulo,xePublicKeyData.Modulus,256);
    memcpy(&c_private,xePublicKeyData.Privatekey,256);
    
    // convert from Intel Big Endian Format
    for (count=0;count<256;count++) d_modulo[count]=c_modulo[255-count];
   // for (count=0;count<256;count++) d_number[count]=c_number[255-count];
    for (count=0;count<256;count++) d_private[count]=c_private[255-count];
    
    // Message Padding 
    d_number[0]=0x00;
    d_number[1]=0x01;
    d_number[235]=0x00;
    for (int a=2;a<235;a++) d_number[a]=0xFF;
    for (int a=0;a<20;a++) d_number[a+236]=c_number[a];
    
    
    ctx=BN_CTX_new();
    rsa_signature=BN_new();
    rsa_pri=BN_new();
    rsa_mod=BN_new();
    rsa_out=BN_new();
            
    out=BIO_new(BIO_s_file());
    BIO_set_fp(out,stdout,BIO_NOCLOSE);
    
    rsa_signature=BN_bin2bn(d_number,256,rsa_signature); 
    rsa_pri=BN_bin2bn(d_private,256,rsa_pri); 
    rsa_mod=BN_bin2bn(d_modulo,256,rsa_mod); 
 
    BN_mod_exp(rsa_out,rsa_signature,rsa_pri,rsa_mod,ctx);
  
  /*  
    printf("crypting\n");
    
    printf("Crypted:\n");
    BN_print(out,rsa_signature);printf("\n"); 
    printf("Exponent:\n");
    BN_print(out,rsa_pri);printf("\n"); 
    printf("Modulus:\n");
    BN_print(out,rsa_mod);printf("\n");
    printf("\n");
    printf("Result:\n");
    BN_print(out,rsa_out);printf("\n"); 
    */
    
    // as the first 00 are striped off, attach again to the string

    for (count=0;count<256;count++) cryptbuffer[count]=0x00;
    int len=BN_bn2bin(rsa_out, d_number);
    
    for (count=0;count<len;count++) cryptbuffer[count]=d_number[255-count]; 
     
    return 1;
}


int GenarateSignaturex(void *xbe) {

 	unsigned char sha_Message_Digest[20];
   	XBE_HEADER *header;
//	unsigned char crypt_buffer[256];
	header = (XBE_HEADER*) xbe;
	shax(&sha_Message_Digest[0], ((unsigned char *)xbe)+0x104 ,header->HeaderSize - 0x104);
	crypt_signature(&sha_Message_Digest[0],header->HeaderSignature);
	return 0;
	
}

int VerifySignaturex(void *xbe,int debugout) {
 	
 	unsigned char sha_Message_Digest[20];
   	XBE_HEADER *header;
	unsigned char crypt_buffer[256];
	
	//printf("Verify Signature Entry\n");
	
	header = (XBE_HEADER*) xbe;

	shax(&sha_Message_Digest[0], ((unsigned char *)xbe)+0x104 ,header->HeaderSize - 0x104);
        
	//printf("\nCall Encrypt RSA Signature\n");
	
	decrypt_signature(header->HeaderSignature,crypt_buffer);
		// for (int a=0;a<256;a++) printf("%02x",crypt_buffer[a]);
	return Verifyhash(&sha_Message_Digest[0],crypt_buffer,debugout);

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


void sub_VerifyCertificatex(unsigned char* src, unsigned char* dest)
{
	unsigned char *temp;
	
	// this is not the real Certificate Key, i left it out due Copyright problems
	unsigned char Certficiatekey[]={ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	
	//EVP_md5()
	temp = HMAC(EVP_sha1(),&Certficiatekey[0], 16, src, 16,NULL,NULL);
	memcpy(dest, temp, 16);
}

int VerifyCertificatex(void *xbe){
	
	XBE_HEADER *header;	 
	XBE_CERTIFICATE *cert;
	//unsigned char text[20];
	
	header = (XBE_HEADER*) xbe;
	cert = (XBE_CERTIFICATE *)(((char *)xbe) + (int)header->Certificate - (int)header->BaseAddress);
	
	sub_VerifyCertificatex(cert->LanKey,cert->LanKey);
	sub_VerifyCertificatex(cert->SignatureKey,cert->SignatureKey);
	for (int i = 0; i < 16; i++)
	{
		sub_VerifyCertificatex(&cert->AlternateSignatureKeys[i][0],&cert->AlternateSignatureKeys[i][0]);
	}
	//for (int a=0; a<20;a++) printf("%02X",text[a]);
	return 0;

}


int read_rsafromflash(char *filename,unsigned int dumpflag)
{
	FILE *f;
	unsigned char *flash=0;
	int filesize;
	int counter;
	int found=0;
	
	// Load the Test Key
	for (counter=0;counter<256;counter++) xePublicKeyData.Privatekey[counter]=0x00;
	
	if (dumpflag & 0x10000000) {
		printf("Using Linux Test Keys \n ");
		memcpy(&xePublicKeyData,&Testkey[0],20+256+256);
		return 0;
	};
	
		
	// Load the "real Key from flash.bin"
	f = fopen(filename, "r");
    	if (f!=NULL) 
    	{    
        	fseek(f, 0, SEEK_END); filesize = ftell(f); fseek(f, 0, SEEK_SET);
        	
        	flash = (unsigned char*) malloc(filesize);
        	
	     	fread(flash, 1, filesize, f);
 	        fclose(f);
 	        
 	        for (counter=0; counter<filesize-270;counter++){
 	           	if ( (flash[counter+0] == 0x52) &
 	        	     (flash[counter+1] == 0x53) &
 	        	     (flash[counter+2] == 0x41) &
 	        	     (flash[counter+3] == 0x31) &
 	        	     (flash[counter+4] == 0x08) &
  	        	     (flash[counter+5] == 0x01) ) 
 	        	     {
 	        	     	found=1;
 				break; 	        	       
 	        	     }
 	        }
 	
 	} else {
		printf("Flash Image flash.bin not found\n");
	}
	
	
	if (found == 1) {
		printf("RSA Key Found\n");
		memcpy(&xePublicKeyData,&flash[counter],20+256);
	} else {
		printf("Public key not found .. Using TestKeys..\n ");
		memcpy(&xePublicKeyData,&Testkey[0],20+256+256);
	}
	
	
	return 0;
}

/* 
  Used to create the 2 files for implemetation on top 
  This Function is never used again, i left it for documentation

int gen_linux_rsadata(){
	
	FILE *f;
	RSA *rsa=NULL;
	int num=2048;
	unsigned char c_number[256];
	
	unsigned long f4=RSA_F4;
	
	BIGNUM *number;
	number=BN_new();
	
	rsa=RSA_generate_key(num,f4,NULL,NULL);
	
	f = fopen("linuxpub.cert", "w");
	      BN_bn2bin(rsa->n, c_number);
	      for (int y=0;y<16;y++) {
	      	for (int x=0;x<16;x++) {
	      	   fprintf(f,"0x%02X,",c_number[255 -(x+16*y)]);
	      	}
	      	fprintf(f,"\n");
	      }	
	fclose(f);
	
	f = fopen("linuxpri.cert", "w");
	      BN_bn2bin(rsa->d, c_number);
	      for (int y=0;y<16;y++) {
	      	for (int x=0;x<16;x++) {
	      	   fprintf(f,"0x%02X,",c_number[255-(x+16*y)]);
	      	}
	      	fprintf(f,"\n");
	      }	
	fclose(f);
	return 0;
}
*/
