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
#include <stdint.h>
#include <string.h>
#include "xboxlib.h"
#include "xbestructure.h"
   

#include "giants.h"
#include "sha1.h"


// prototype


// Test keys with Exponent = 1
unsigned char Testkey[] = {
 	0x52,0x53,0x41,0x31, 0x08,0x01,0x00,0x00, 0x00,0x08,0x00,0x00, 0xff,0x00,0x00,0x00,
 	0x01,0x00,0x00,0x00, 
 	// Public Modulus "m"
 	0xd3,0xd7,0x4e,0xe5, 0x66,0x3d,0xd7,0xe6, 0xc2,0xd4,0xa3,0xa1, 0xf2,0x17,0x36,0xd4, 
 	0x2e,0x52,0xf6,0xd2, 0x02,0x10,0xf5,0x64, 0x9c,0x34,0x7b,0xff, 0xef,0x7f,0xc2,0xee,
 	0xbd,0x05,0x8b,0xde, 0x79,0xb4,0x77,0x8e, 0x5b,0x8c,0x14,0x99, 0xe3,0xae,0xc6,0x73,
 	0x72,0x73,0xb5,0xfb, 0x01,0x5b,0x58,0x46, 0x6d,0xfc,0x8a,0xd6, 0x95,0xda,0xed,0x1b,
 	0x2e,0x2f,0xa2,0x29, 0xe1,0x3f,0xf1,0xb9, 0x5b,0x64,0x51,0x2e, 0xa2,0xc0,0xf7,0xba, 
 	0xb3,0x3e,0x8a,0x75, 0xff,0x06,0x92,0x5c, 0x07,0x26,0x75,0x79, 0x10,0x5d,0x47,0xbe, 
 	0xd1,0x6a,0x52,0x90, 0x0b,0xae,0x6a,0x0b, 0x33,0x44,0x93,0x5e, 0xf9,0x9d,0xfb,0x15, 
 	0xd9,0xa4,0x1c,0xcf, 0x6f,0xe4,0x71,0x94, 0xbe,0x13,0x00,0xa8, 0x52,0xca,0x07,0xbd, 
 	0x27,0x98,0x01,0xa1, 0x9e,0x4f,0xa3,0xed, 0x9f,0xa0,0xaa,0x73, 0xc4,0x71,0xf3,0xe9, 
 	0x4e,0x72,0x42,0x9c, 0xf0,0x39,0xce,0xbe, 0x03,0x76,0xfa,0x2b, 0x89,0x14,0x9a,0x81, 
 	0x16,0xc1,0x80,0x8c, 0x3e,0x6b,0xaa,0x05, 0xec,0x67,0x5a,0xcf, 0xa5,0x70,0xbd,0x60, 
 	0x0c,0xe8,0x37,0x9d, 0xeb,0xf4,0x52,0xea, 0x4e,0x60,0x9f,0xe4, 0x69,0xcf,0x52,0xdb, 
 	0x68,0xf5,0x11,0xcb, 0x57,0x8f,0x9d,0xa1, 0x38,0x0a,0x0c,0x47, 0x1b,0xb4,0x6c,0x5a, 
 	0x53,0x6e,0x26,0x98, 0xf1,0x88,0xae,0x7c, 0x96,0xbc,0xf6,0xbf, 0xb0,0x47,0x9a,0x8d, 
 	0xe4,0xb3,0xe2,0x98, 0x85,0x61,0xb1,0xca, 0x5f,0xf7,0x98,0x51, 0x2d,0x83,0x81,0x76, 
 	0x0c,0x88,0xba,0xd4, 0xc2,0xd5,0x3c,0x14, 0xc7,0x72,0xda,0x7e, 0xbd,0x1b,0x4b,0xa4,  
	// Private Key "d"

	0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,			
	
};

                  
unsigned char xboxPublicKeyData[] = {
 	0x52,0x53,0x41,0x31, 0x08,0x01,0x00,0x00, 0x00,0x08,0x00,0x00, 0xff,0x00,0x00,0x00,
 	0x03,0x00,0x00,0x00, 
 	// Public Modulus "m"
 	0xd3,0xd7,0x4e,0xe5, 0x66,0x3d,0xd7,0xe6, 0xc2,0xd4,0xa3,0xa1, 0xf2,0x17,0x36,0xd4, 
 	0x2e,0x52,0xf6,0xd2, 0x02,0x10,0xf5,0x64, 0x9c,0x34,0x7b,0xff, 0xef,0x7f,0xc2,0xee,
 	0xbd,0x05,0x8b,0xde, 0x79,0xb4,0x77,0x8e, 0x5b,0x8c,0x14,0x99, 0xe3,0xae,0xc6,0x73,
 	0x72,0x73,0xb5,0xfb, 0x01,0x5b,0x58,0x46, 0x6d,0xfc,0x8a,0xd6, 0x95,0xda,0xed,0x1b,
 	0x2e,0x2f,0xa2,0x29, 0xe1,0x3f,0xf1,0xb9, 0x5b,0x64,0x51,0x2e, 0xa2,0xc0,0xf7,0xba, 
 	0xb3,0x3e,0x8a,0x75, 0xff,0x06,0x92,0x5c, 0x07,0x26,0x75,0x79, 0x10,0x5d,0x47,0xbe, 
 	0xd1,0x6a,0x52,0x90, 0x0b,0xae,0x6a,0x0b, 0x33,0x44,0x93,0x5e, 0xf9,0x9d,0xfb,0x15, 
 	0xd9,0xa4,0x1c,0xcf, 0x6f,0xe4,0x71,0x94, 0xbe,0x13,0x00,0xa8, 0x52,0xca,0x07,0xbd, 
 	0x27,0x98,0x01,0xa1, 0x9e,0x4f,0xa3,0xed, 0x9f,0xa0,0xaa,0x73, 0xc4,0x71,0xf3,0xe9, 
 	0x4e,0x72,0x42,0x9c, 0xf0,0x39,0xce,0xbe, 0x03,0x76,0xfa,0x2b, 0x89,0x14,0x9a,0x81, 
 	0x16,0xc1,0x80,0x8c, 0x3e,0x6b,0xaa,0x05, 0xec,0x67,0x5a,0xcf, 0xa5,0x70,0xbd,0x60, 
 	0x0c,0xe8,0x37,0x9d, 0xeb,0xf4,0x52,0xea, 0x4e,0x60,0x9f,0xe4, 0x69,0xcf,0x52,0xdb, 
 	0x68,0xf5,0x11,0xcb, 0x57,0x8f,0x9d,0xa1, 0x38,0x0a,0x0c,0x47, 0x1b,0xb4,0x6c,0x5a, 
 	0x53,0x6e,0x26,0x98, 0xf1,0x88,0xae,0x7c, 0x96,0xbc,0xf6,0xbf, 0xb0,0x47,0x9a,0x8d, 
 	0xe4,0xb3,0xe2,0x98, 0x85,0x61,0xb1,0xca, 0x5f,0xf7,0x98,0x51, 0x2d,0x83,0x81,0x76, 
 	0x0c,0x88,0xba,0xd4, 0xc2,0xd5,0x3c,0x14, 0xc7,0x72,0xda,0x7e, 0xbd,0x1b,0x4b,0xa4  
 	// Private Key "d"
 	// Could somebody insert it ?
 };
 
typedef struct RSA_PUBLIC_KEY
{
	char Magic[4];  		// "RSA1"
	unsigned int Bloblen; 		// 264 (Modulus + Exponent + Modulussize)
	unsigned char Bitlen[4];  	// 2048
	unsigned int ModulusSize;	// 255 (bytes in the Modulus)
	unsigned char Exponent[4];
	unsigned char Modulus[256];     // Bit endian style
	unsigned char Privatekey[256];  // Private Key .. we do not have it -- Big endian style
};
struct RSA_PUBLIC_KEY xePublicKeyData;

// Asterix .bin File format structure
typedef struct XboxKey
{
	// Magic string ("RSA1")
	uint8_t magic[4];
	// Size of key?  Always 0x108
	uint32_t byte_size;
	// Bit size of key?  Always 2048
	uint32_t bit_size;
	// Unknown; always 0xFF
	uint32_t unknown_FF;
	// Public exponent, always 65537
	uint32_t public_exponent;
	// modulus, which is factor1 * factor2
	uint8_t modulus[256];

	// Private portions (these are kept secret to the Xbox Linux team)

	// First factor of the modulus
	uint8_t factor1[128];
	// Second factor of the modulus
	uint8_t factor2[128];
	// Random number used to make factor1 (factor1 = nextprime(random1))
	uint8_t random1[128];
	// Random number used to make factor2 (factor2 = nextprime(random2))
	uint8_t random2[128];
	// "Phi", which is (factor1 - 1) * (factor2 - 1)
	uint8_t phi[256];
	// Private exponent, which is 65537^-1 mod phi
	uint8_t private_exponent[256];
};

const unsigned char RSApkcs1paddingtable[3][16] = {
	{0x0F, 0x14,0x04,0x00,0x05,0x1A,0x02,0x03,0x0E,0x2B,0x05,0x06,0x09,0x30,0x21,0x30},
	{0x0D, 0x14,0x04,0x1A,0x02,0x03,0x0E,0x2B,0x05,0x06,0x07,0x30,0x1F,0x30,0x00,0x00},
	{0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
};


int read_rsafrombin_asterix()
{
	FILE *f;
	unsigned char *flash=0;
	int filesize=0;
	
	struct XboxKey tempkey;
	
	printf("Using Linux Test Keys from linuxkey.bin\n");
	//memcpy(&xePublicKeyData,&Testkey[0],20+256+256);

	f = fopen("linuxkey.bin", "rb");
    	if (f!=NULL) 
    	{    
        	fseek(f, 0, SEEK_END); 
		filesize = ftell(f); 
		fseek(f, 0, SEEK_SET);
        	
        	flash = (unsigned char*) malloc(filesize);
        	
		fread(flash, 1, filesize, f);
 	        fclose(f);
		printf("Key File loaded (format asterix): %d bytes",filesize);
	} else printf("linuxkey.bin not found");
	
	memcpy(&tempkey,&flash[0],filesize);
    	
	
	memcpy(&xePublicKeyData.Modulus[0],tempkey.modulus,256);
	memcpy(&xePublicKeyData.Privatekey[0],tempkey.private_exponent,256);
	
	//memcpy(&xePublicKeyData,&Testkey[0],20+256+256);
	return 0;
}     

void gigimport(giant g, unsigned char *buff,int len){

	int count;
	memcpy(g->n,buff,len);
	g->sign = len/2;
	
	// Correcting to bits now
	for (count = g->sign ;count!=0;count--) {
		
		if (g->n[count] != 0x00) {
			count = count+1;
			break;      
		}
	}                                      

	g->sign= count;
	if (g->sign==0) g->sign = 1;
	

}

// DE - Crypting
int decrypt_signature(unsigned char *c_number,unsigned char *cryptbuffer) {
	
	giant n = newgiant(INFINITY);	
	giant e = newgiant(INFINITY);	
	giant sig = newgiant(INFINITY);	
	
 	int count;
        gigimport(sig,c_number,256);

	gigimport(n,xePublicKeyData.Modulus,256);

	gigimport(e,xePublicKeyData.Exponent,4);


	/* x := x^n (mod z). */
	powermodg(sig,e, n);	

	//gout(n);
	//gout(e);
	//gout(sig);

	memset(cryptbuffer,0x00,256);
	memcpy(cryptbuffer,sig->n,256);
	//for (count=0; count < 256;count++) printf("%02X",cryptbuffer[count]);
	
	 return 1;
}

// END DE-Crypting


int Verifyhash(unsigned char *hash,unsigned char *decryptBuffer,int debugout){

  	unsigned char cmphash[20];
  	int a;
  	int zero_position = 20; 
  
  	// Convert Hash to "Big-Endian Format"
  	for (a=0;a<20;a++) cmphash[a] = hash[19-a];
  
  if (debugout!=0) {
	
        printf("\n             in File -> ");
        for (a=0;a<20;a++) printf("%02X",decryptBuffer[a]);
        printf("\n           should be -> ");
        for (a=0;a<20;a++) printf("%02X",cmphash[a]);

        printf("\n");   
        if (decryptBuffer[zero_position]!= 0x00) 
  		printf("Padding Step 1:        fail\n"); else printf("Padding Step 1:        pass\n");
  	
  	if (decryptBuffer[xePublicKeyData.ModulusSize]!= 0x00) 
  		printf("Padding Step 2:        fail\n"); else printf("Padding Step 2:        pass\n");
  
  	if (decryptBuffer[xePublicKeyData.ModulusSize-1]!= 0x01) 
  		printf("Padding Step 3:        fail\n"); else printf("Padding Step 3:        pass\n");
  
  	for (unsigned int i = zero_position+1; i < (xePublicKeyData.ModulusSize-1); i++) {
		if (decryptBuffer[i] != 0xff) 	{ 
			printf("Padding Step 4:        fail\n"); 
			break; 
		}       
	if (i==xePublicKeyData.ModulusSize-2) printf("Padding Step 4:        pass\n");

  	}   
        
  }

  	// Compare if the Hash Results (first 20 Bytes) are the same
  	if (memcmp(decryptBuffer, cmphash, 20)!=0)   return 0;

  	unsigned char *pkcspad;
  	for (int tableIndex = 0; RSApkcs1paddingtable[tableIndex][0] !=0; tableIndex++) {
  	
  		pkcspad=(unsigned char*)RSApkcs1paddingtable[tableIndex];
  		int difference = memcmp(pkcspad+1,&decryptBuffer[20],*pkcspad); 
  	
  		if (!difference)
		{
			zero_position = *pkcspad + 20;
			break;
		}
  
	}
	  
  	// Padding checking , xbox does exactly the same 
  
  	if (decryptBuffer[zero_position]!= 0x00) return 0;
  	
  	if (decryptBuffer[xePublicKeyData.ModulusSize]!= 0x00) return 0;
  
  	if (decryptBuffer[xePublicKeyData.ModulusSize-1]!= 0x01) return 0;
  
  	for (unsigned int i = zero_position+1; i < (xePublicKeyData.ModulusSize-1); i++) {
		if (decryptBuffer[i] != 0xff) return 0;
		//printf("%02X",decryptBuffer[i])  ;
  	}  


  	return 1;
  
}


int crypt_signature(unsigned char *c_number,unsigned char *cryptbuffer){
  
    	int count;
    	unsigned char c_signature[256];
    	unsigned char c_hash[20];
    	unsigned int a;

	giant n = newgiant(INFINITY);	
	giant e = newgiant(INFINITY);	
	giant sig = newgiant(INFINITY);	
	
	gigimport(n,xePublicKeyData.Modulus,256);

	
	gigimport(e,xePublicKeyData.Privatekey,256);

	
    	for (count=0;count<20;count++) c_hash[count]=c_number[19-count];
    
    	int zero_position=20;
    	// Message Padding 
    	c_signature[xePublicKeyData.ModulusSize]=0x00;
    	c_signature[xePublicKeyData.ModulusSize-1]=0x01;
    	memcpy(&c_signature[0],&c_hash[0],20);
 
    	int padmethod=2;        
    	memcpy(&c_signature[20],&RSApkcs1paddingtable[padmethod][1],RSApkcs1paddingtable[padmethod][0]);
    	zero_position += RSApkcs1paddingtable[padmethod][0];

    	c_signature[zero_position]=0x00;   
    	for (a=zero_position+1;a<(xePublicKeyData.ModulusSize-1);a++) c_signature[a]=0xFF;
 
   //     for (count=0;count<256/2;count++) printf("%04x",n->n[count]);
        

        gigimport(sig,c_signature,256);

//	gout(n);
//	gout(e);
//	gout(sig);   	


	/* x := x^n (mod z). */
	powermodg(sig,e, n);	
	
	memset(cryptbuffer,0x00,256);
	memcpy(cryptbuffer,sig->n,256);
    
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
	struct SHA1Context context;
   	
   	SHA1Reset(&context);
	SHA1Input(&context, (unsigned char *)&len, 4);
	SHA1Input(&context,data,len);
	SHA1Result(&context,result);	
}



int generate_habibi(void){
	
	unsigned int temp;
	
	giant p = newgiant(INFINITY);	
	giant phi = newgiant(INFINITY);	

	memset(&Testkey[0],0x00,20+256+256);
	memcpy(&Testkey[0],&xboxPublicKeyData[0],20+256);
	temp = 0x899c906b;
	memcpy(&Testkey[272],&temp,4); 

	gigimport(phi,&Testkey[20],256);

	idivg(3,phi); 	// phi = phi/3
	itog(1, p);   	// p=1	
	subg(p,phi);   	// phi = phi - p
	
	itog(2, p);	// p = 2
	mulg(p, phi);	// phi = phi * p
     
	gigimport(p,&Testkey[16],4); 	
	
	invg(phi,p);
        memcpy(&Testkey[20+256],p->n,256);
	//gout(phi);

}


int load_rsa(unsigned int dumpflag)
{
	int counter;
	// Reset the Keys
	for (counter=0;counter<256;counter++) xePublicKeyData.Privatekey[counter]=0x00;
	
	if (dumpflag & 0x10000000) {
		printf("Using Linux Test Keys \n");
		memcpy(&xePublicKeyData,&Testkey[0],20+256+256);
		return 0;
	};

	if (dumpflag & 0x20000000) {
		generate_habibi();
		printf("Using Habibi Keys \n");
		memcpy(&xePublicKeyData,&Testkey[0],20+256+256);
		return 0;
	};
	
	
	memcpy(&xePublicKeyData,&xboxPublicKeyData[0],20+256);
	
	//int read_rsafrombin_asterix();
	//read_rsafrombin_asterix();
	
	return 0;
}
  
unsigned int xorthunk(int modus) {
	
     	unsigned int xortemp[5+64];
	unsigned int resulting=0;	
	
	if (modus==0){
		memcpy(&xortemp[0],&xePublicKeyData,20+256);
		resulting = xortemp[0x21]^xortemp[0x22];	
	}
	if (modus==1){	
		// Patch mode
		memcpy(&xortemp[0],&xboxPublicKeyData[0],20+256);		
		resulting = xortemp[0x21]^xortemp[0x22];	
		memcpy(&xortemp[0],&Testkey[0],20+256);		
		resulting ^= xortemp[0x21]^xortemp[0x22];			
	}
	return resulting;
}

unsigned int xorentry(int modus) {
	
	unsigned int xortemp[5+64];
	unsigned int resulting=0;	

	if (modus==0){
		memcpy(&xortemp[0],&xePublicKeyData,20+256);
		resulting = xortemp[0x20]^xortemp[0x24];	
	}
	if (modus==1){	
		// Patch mode
		memcpy(&xortemp[0],&xboxPublicKeyData[0],20+256);		
		resulting = xortemp[0x20]^xortemp[0x24];	
		memcpy(&xortemp[0],&Testkey[0],20+256);		
		resulting ^= xortemp[0x20]^xortemp[0x24];			
	}
	
	return resulting;
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
	f = fopen(filename, "rb");
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
           
           
int load_xbefile(unsigned int &xbe,unsigned int &filesize,char *filename) {
  
   FILE *f;
   void *file;
   
   f = fopen(filename, "rb");
   if (f!=NULL) 
    {
         fseek(f, 0, SEEK_END); 
         filesize = ftell(f); 
         fseek(f, 0, SEEK_SET);
//         printf("Loading file %s (%i bytes)\n", filename, filesize);
         
         file = malloc(filesize);
         xbe=(unsigned int)file;
         fread(file, 1, filesize, f);
         fclose(f);	
   } else {
        printf("File Not found %s, use parameter filename \n",filename);
   	      
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
