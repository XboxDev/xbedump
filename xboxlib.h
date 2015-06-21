/*
typedef struct _RSA_PUBLIC_KEY
{
	// 000 Magic - always "RSA1"
	char Magic[4];
	// 004 Size of the key in bytes, starting at Unknown??? (0x108)
	SIZE_T KeySize;
	// 008 Size of the RSA modulus in bits (always 0x800)
	ULONG ModulusSize;
	// 00C Unknown (always 0xFF)
	ULONG Unknown;
	// 010 RSA public exponent (65537)
	ULONG PublicExponent;
	// 014 RSA modulus in Intel order
	UCHAR Modulus[1];
} RSA_PUBLIC_KEY, *PRSA_PUBLIC_KEY;
*/

void shax(unsigned char *result, unsigned char *data, unsigned int len);
int VerifySignaturex(void *xbe,int debugout);
int GenarateSignaturex(void *xbe);
int dump_rsaxbe(char *filename);
int read_rsafromflash(char *filename,unsigned int dumpflag); 
int VerifyCertificatex(void *xbe);
int load_rsa(unsigned int dumpflag);

int load_xbefile(void* &xbe,unsigned int &filesize,char *filename);
unsigned int xorentry(int modus);
unsigned int xorthunk(int modus);
