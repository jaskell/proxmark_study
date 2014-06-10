 /********************************************************************
 * keystream.c
 ********************************************************************
 * Keystream extracter/ Ciphertext generator helper program
 *
 * With elements from Proxmark 3 source code.(CRC)
 *
 * Code Implementation by Kyle Penri-Williams
 * kyle.penriwilliams@gmail.com
 */

 #include "keystream.h"

 #include <stdio.h>
 #include <stdlib.h>
 #include "keystream.h"

 /*
 * Parse and regenerate the keystream.txt file
 */
 int main()
 {
 FILE *ftxt;
 char str[200];
 char *strcursor;
 int i,j;
 unsigned char temp;

 unsigned int ct_parity=0;
 unsigned int pt_parity=0;
 unsigned int ks_parity=0;
 unsigned int parity=0;

 unsigned char ct_frame[64];
 unsigned char pt_frame[64];
 unsigned char ks_frame[64];

 unsigned int ct_len=0;
 unsigned int pt_len=0;
 unsigned int ks_len=0;


 ftxt=fopen("./keystream.txt","r+");

 //get Ciphertext
 fgets(str,200,ftxt);

 strcursor=str;
 sscanf(strcursor,"%08x,%02x,",&ct_parity,&ct_len);
 strcursor+=12;

 for(i=0;i<ct_len;i++){
 sscanf(strcursor," %02x",&(ct_frame[i]));
 strcursor+=3;
 }

 //get Plaintext
 fgets(str,200,ftxt);
 strcursor=str;
 sscanf(strcursor,"%08x,%02x,",&pt_parity,&pt_len);
 strcursor+=12;

 for(i=0;i<pt_len;i++){
 sscanf(strcursor," %02x",&(pt_frame[i]));
 strcursor+=3;
 }
 if(strcursor[0]=='?'){
 ComputeCrc14443(pt_frame, pt_len, &(pt_frame[pt_len]), &(pt_frame[pt_len+1]));
 pt_len+=2;

 }


 //calculate plaintext parity
 pt_parity=0;
 for(i=0;i<pt_len;i++){
 temp=pt_frame[i];
 parity=1;

 for(j=0;j<8;j++){
 parity^= (temp & 0x01);
 temp>>=1;
 }
 pt_parity<<=1;
 pt_parity|=parity;
 }

 //calculate keystream
 ks_len = (pt_len>ct_len)?ct_len:pt_len;

 ks_parity= pt_parity ^ ct_parity;

 for(i=0;i<ks_len;i++){
 ks_frame[i] = pt_frame[i] ^ ct_frame[i];
 }

 fseek(ftxt,0,SEEK_SET);

 //write Ciphertext
 fprintf(ftxt,"%08x,%02x,",ct_parity,ct_len);

 for(i=0;i<ct_len;i++){
 fprintf(ftxt," %02x",ct_frame[i]);
 }
 fprintf(ftxt,"\n");

 //write Plaintext
 fprintf(ftxt,"%08x,%02x,",pt_parity,pt_len);

 for(i=0;i<pt_len;i++){
 fprintf(ftxt," %02x",pt_frame[i]);
 }
 fprintf(ftxt,"\n");

 //write keystream
 fprintf(ftxt,"%08x,%02x,",ks_parity,ks_len);

 for(i=0;i<ks_len;i++){
 fprintf(ftxt," %02x",ks_frame[i]);
 }
 fprintf(ftxt,"\n");
 fprintf(ftxt," \n");


 fclose(ftxt);
 return 0;
 }



 /*
 * ------------------------------------------------------------------
 *
 * CRC Helper Functions
 *
 * ------------------------------------------------------------------
 */


 static unsigned short UpdateCrc14443(unsigned char ch, unsigned short *lpwCrc)
 {
 ch = (ch ^ (unsigned char) ((*lpwCrc) & 0x00FF));
 ch = (ch ^ (ch << 4));
 *lpwCrc =
 (*lpwCrc >> 8) ^ ((unsigned short) ch << 8) ^
 ((unsigned short) ch << 3) ^ ((unsigned short) ch >> 4);
 return (*lpwCrc);
 }

 void ComputeCrc14443(BYTE *Data, int Length, BYTE *TransmitFirst, BYTE *TransmitSecond)
 {
 unsigned char chBlock;
 unsigned short wCrc;
 wCrc = 0x6363; /* ITU-V.41 */

 do {
 chBlock = *Data++;
 UpdateCrc14443(chBlock, &wCrc);
 } while (--Length);

 *TransmitFirst = (BYTE) (wCrc & 0xFF);
 *TransmitSecond = (BYTE) ((wCrc >> 8) & 0xFF);
 return;
 }