#ifndef   _DES_ENCRYPT_DECRYPT 
#define   _DES_ENCRYPT_DECRYPT 

#define BYTE   unsigned char 
#define LPBYTE   BYTE* 
#define LPCBYTE   const BYTE* 
#define BOOL   int 


BOOL DesEnter(LPCBYTE in, LPBYTE out, int datalen, const BYTE key[8], BOOL type); 
BOOL DesMac(LPCBYTE mac_data, LPBYTE mac_code, int datalen, const BYTE key[8]); 

#endif