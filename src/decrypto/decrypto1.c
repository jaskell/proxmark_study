/********************************************************************
* decrypto1.c
********************************************************************
* Find a key from Philips/NXP Mifare Crypto-1 keystream
*
* Based on the paper :
* "Dismantling MIFARE Classic"
* By Flavio D. Garcia, Gerhard de Koning Gans, Ruben Muijrers,
* Peter van Rossum, Roel Verdult, Ronny Wichers Schreur, and Bart Jacobs
* Institute for Computing and Information Sciences,
* Radboud University Nijmegen, The Netherlands

* With elements from crypto1.c by Karsten Nohl, Henryk Pl?tz, Sean O¡¯Neil
*
* Code Implementation by Kyle Penri-Williams
* kyle.penriwilliams@gmail.com
*/

#include "decrypto1.h"
#include <inttypes.h>
#define VAL2POWER20 1048576


/*
* ------------------------------------------------------------------
*
* Table Entry List Functions
*
* ------------------------------------------------------------------
*/

/*
* Init a table first element(the head).
*/
void table_entry_init(table_entry_t* head)
{
    head->value=0;
    head->fbc24=0;
    head->fbc21=0;
    head->prev=NULL;
    head->next=NULL;
}

/*
* Remove a table_entry_t from list and delete it.
*/
void table_entry_delete( table_entry_t* entry)
{
    if (entry->prev !=NULL)
    {
        entry->prev->next=entry->next;
    }

    if (entry->next !=NULL)
    {
        entry->next->prev=entry->prev;
    }
    free(entry);
}

/*
* Insert a table_entry_t after the parent into the table
*/
void table_entry_insert( table_entry_t* parent,table_entry_t* newentry)
{
    newentry->prev = parent;

    newentry->next = parent->next;

    if (parent->next!=NULL)
    {
        parent->next->prev=newentry;
    }

    parent->next = newentry;
}

/*
* Insert a value/fbc24/fbc21 after the parent into the table
*/
void table_entry_insert_value(table_entry_t* parent,uint64_t value ,uint64_t fbc24,uint64_t
                              fbc21 )
{
    table_entry_t* newentry;
    newentry = (table_entry_t*) malloc(sizeof(table_entry_t));

    newentry->fbc24=(uint32_t)fbc24;
    newentry->fbc21=(uint32_t)fbc21;
    newentry->value=value;

    table_entry_insert(parent, newentry);
}

/*
* Move an entry from its current position to next item of newparent
*/
void table_entry_move( table_entry_t* newparent,table_entry_t* newentry)
{

    if ( newentry->prev!=NULL)
    {
        newentry->prev->next = newentry->next;
    }

    if ( newentry->next!=NULL)
    {
        newentry->next->prev = newentry->prev;
    }

    table_entry_insert(newparent, newentry);
}

/*
* Get a value from the table using an index
*/
uint64_t table_entry_get_value(table_entry_t* head, uint32_t index)
{
    uint32_t i;
    table_entry_t* cursor;
    uint64_t returnvalue=0;

    if (head!=NULL)
    {
        cursor=head;

        for (i=0; i<index; i++)
        {
            if (cursor->next==NULL)
            {
                break;
            }
            else
            {
                cursor=cursor->next;
            }

        }
        returnvalue=cursor->value;
    }
    return returnvalue;
}

/*
* Get the table size
*/
uint32_t table_entry_get_size(table_entry_t* head)
{
    int i;
    table_entry_t* cursor;

    cursor=head;

    for (i=-1; cursor!=NULL; i++)
    {
        cursor=cursor->next;
    }

    return i;
}

table_entry_t* table_entry_last(table_entry_t* head) 
{
	table_entry_t* prev = NULL;
	table_entry_t* cursor = head;

	while (cursor != NULL) {
		prev = cursor;
		cursor=cursor->next;
	}
	return prev;
}

/*
* Keep only one value in the list. Delete all Others. (For Testing Only)
*/
void table_entry_filter(table_entry_t* head, uint64_t v)
{
    table_entry_t* cursor,*temp;

    if (head!=NULL)
    {
        cursor=head->next;

        while (cursor!=NULL)
        {
            temp=cursor->next;
            if (((cursor->value))!=v)
            {
                table_entry_delete( cursor );
            }
            cursor=temp;
        }
    }
}
/*
* Quicksort a table using value (Descending)
*/
void quicksort_value(table_entry_t* start,table_entry_t* end)
{

    table_entry_t* cursor,* parent,*temp;
    uint64_t pivot;
    uint64_t test;

    //Errors
    if (start==NULL )
    {
        //printf("Internal Error: quicksort\n");
        return;
    }
    if (start->prev==NULL)
    {
        printf("Internal Error: quicksort\n");
        return;
    }

    //End of recursion condition
    if (start==end || start->next==end)
    {
        return;
    }

    //interesting variables
    pivot=start->value;
    parent=start->prev;
    cursor=start->next;


    while (cursor!=NULL&& cursor!=end)
    {

        temp=cursor->next;

        test=cursor->value;

        if ( pivot <= test )
        {
            table_entry_move( parent,cursor);
        }

        cursor=temp;
    }
    quicksort_value(parent->next,start);
    quicksort_value(start->next,end);
}

/*
* Quicksort a table using fbc24 as MSBs and fbc21 as LSB (Descending)
*/
void quicksort_24_21(table_entry_t* start,table_entry_t* end)
{

    table_entry_t* cursor,* parent,*temp;
    uint64_t pivot;
    uint64_t test;

    //Errors
    if (start==NULL )
    {
        //printf("Internal Error: quicksort\n");
        return;
    }
    if (start->prev==NULL)
    {
        printf("Internal Error: quicksort\n");
        return;
    }

    //End of recursion condition
    if (start==end || start->next==end)
    {
        return;
    }

    //interesting variables
    pivot=(((uint64_t)(start->fbc24))<<32) | (((uint64_t)(start->fbc21)) & 0xffffffff);
    parent=start->prev;
    cursor=start->next;

    while (cursor!=NULL)
    {

        temp=cursor->next;

        test=(((uint64_t)(cursor->fbc24))<<32) | (((uint64_t)(cursor->fbc21)) &
                0xffffffff);

        if ( pivot <= test )
        {
            //printf("swap\n");
            table_entry_move( parent,cursor);
        }

        if (temp==end)
        {
            break;
        }

        cursor=temp;
    }
    quicksort_24_21(parent->next,start);
    quicksort_24_21(start->next,end);
}


/*
* Quicksort a table using fbc21 as MSBs and fbc24 as LSB (Descending)
*/
void quicksort_21_24(table_entry_t* start,table_entry_t* end)
{

    table_entry_t* cursor,* parent,*temp;
    uint64_t pivot;
    uint64_t test;

    //Errors
    if (start==NULL )
    {
        //printf("Internal Error: quicksort\n");
        return;
    }
    if (start->prev==NULL)
    {
        printf("Internal Error: quicksort\n");
        return;
    }

    //End of recursion condition
    if (start==end || start->next==end)
    {
        return;
    }

    //interesting variables
    pivot=(((uint64_t)(start->fbc21))<<32) | ((uint64_t)(start->fbc24) & 0xffffffff);
    parent=start->prev;
    cursor=start->next;

    while (cursor!=NULL)
    {

        temp=cursor->next;
        test=(((uint64_t)(cursor->fbc21))<<32) | ((uint64_t)(cursor->fbc24) &
                0xffffffff);


        if (pivot <= test)
        {
            table_entry_move( parent,cursor);
        }

        if (temp==end)
        {
            break;
        }

        cursor=temp;
    }
    quicksort_21_24(parent->next,start);
    quicksort_21_24(start->next,end);
}

/*
* ------------------------------------------------------------------
*
* Decrypto1 Table Functions
*
* ------------------------------------------------------------------
*/

/*
* Generate a new 2^19 table of possible semi-states that output b0(keystream bit)
*/
void table_init(table_entry_t * table,uint32_t b0)
{
    int i;

    table_entry_init(table);

    for (i=0; i<VAL2POWER20; i++)
    {
        if (sf20(i)==b0)
            table_entry_insert_value(table,i,0,0);
    }
    table->value=20;
}

/*
* Update the contribution of the semi-state when in even and odd position
*/
void update_feedback_contribution(uint64_t value,uint32_t * fbc24,uint32_t * fbc21,
                                  uint8_t is_t)
{

    *fbc24=(*fbc24<<1) | ( bit(value,0)
                           ^ bit(value,5)
                           ^ bit(value,6)
                           ^ bit(value,7)
                           ^ bit(value,12)
                           ^ bit(value,21)
                           ^ bit(value,24)) ;

    if (!is_t) value=value>>1;
    *fbc21=(*fbc21<<1) | ( bit(value,2)
                           ^ bit(value,4)
                           ^ bit(value,7)
                           ^ bit(value,8)
                           ^ bit(value,9)
                           ^ bit(value,12)
                           ^ bit(value,13)
                           ^ bit(value,14)
                           ^ bit(value,17)
                           ^ bit(value,19)
                           ^ bit(value,20)
                           ^ bit(value,21)) ;
}

/*
* Loop through table once and extend its entries using b (keystream bit) and update
contributions
*/
void table_loopthrough(table_entry_t * table, uint8_t b, uint8_t is_t)
{
    table_entry_t * cursor ;
    table_entry_t * temp ;
    uint64_t value;
    uint32_t result=0;
    uint32_t blen=0;

    if (table!=NULL)
    {
        cursor = table->next;
        blen=table->value;

        //printf("b:%02d - %d\n",blen,b);
        while (cursor!=NULL)
        {

            temp=cursor->next;
            value=cursor->value;
            result=0;

            /**********************************
            * Filter Inversion
            **********************************/
            if ( sf20((value>>(blen-19)) | (1<<19))==b)
            {
                result+=0x1;
            }

            if ( sf20((value>>(blen-19)))==b)
            {
                result+=0x2;
            }

            //printf("result:%d\n",result);
            //system("pause");

            switch (result)
            {
            case 0:
                table_entry_delete( cursor );
                break;
            case 1:
                cursor->value= value | (((uint64_t)1)<<blen);
                //printf("keeeping 1\n");
                break;
            case 2:
                //cursor->value= value | 0;
                //printf("keeeping 0\n");
                break;
            case 3:
                //cursor->value= value | 0;
                table_entry_insert_value(cursor,value | (((uint64_t)1)<<blen),(cursor->fbc24),(cursor->fbc21));
                break;
            default:
                printf("Internal Error: table_loopthrough\n");
            }


            /**********************************
            * Feedback Contributions
            **********************************/
            if (blen >= 24)
            {
                if (result>0)
                {
                    update_feedback_contribution((cursor->value)>>(blen-24),&(cursor->fbc24),&(cursor->fbc21),is_t);
                }

                if (result>2)
                {
                    cursor=cursor->next;
                    update_feedback_contribution((cursor->value)>>(blen-24),&(cursor->fbc24),&(cursor->fbc21),is_t);
                }
            }
            cursor=temp;
        }
        (table->value)++;

    }

}

/*
* Loop through sorted tables once and get pairs of matching contribution semi-states.
*/
uint32_t table_getresults_fbc(table_entry_t * table1, table_entry_t *
                              table2,table_entry_t * results,uint32_t rewindbitcount)
{
    table_entry_t * cursor1 ;
    table_entry_t * cursor2 ;
	uint64_t solution;
    uint32_t count=0;

    if (table1!=NULL && table2!=NULL)
    {
        cursor1 = table1->next;
        cursor2 = table2->next;

        // printf("1Checking s:%08x t:%08x\n",(uint32_t)cursor1->value,(uint32_t)cursor2->value);
        // cursor2=cursor2->next;
        // cursor1=cursor1->next;
        //printf("2Checking s:%08x t:%08x\n",cursor1->value,cursor2->value);
        while (cursor1!=NULL && cursor2!=NULL)
        {
            //printf("Considering s:%08x t:%08x\n",(uint32_t)cursor1->value,(uint32_t)cursor2->value);

            if ( ((cursor1->fbc24) > (cursor2->fbc21)) )
            {
                cursor1=cursor1->next;
            }
            else if ( ((cursor1->fbc24) < (cursor2->fbc21)) )
            {
                cursor2=cursor2->next;
            }
            else // equal if ( ((cursor1->fbc24) == (cursor2->fbc21)) )
            {
                if ( ((cursor1->fbc21) > (cursor2->fbc24)) )
                {
                    cursor1=cursor1->next;
                }
                else if ( ((cursor1->fbc21) < (cursor2->fbc24)) )
                {
                    cursor2=cursor2->next;
                }
                else //equal if ( ((cursor1->fbc21) == (cursor2->fbc24)) )
                {
                    count++;
                    solution = lfsr_assemble(cursor1->value,cursor2->value);
                    //printf("Match found s:%08x t:%08x\n",(uint32_t)cursor1->value,(uint32_t)cursor2->value);
                    lfsr_rollback_m(&solution,9);
                    lfsr_rollback_m(&solution,rewindbitcount);
                    table_entry_insert_value(results,solution ,0,0 );

                    if (cursor2->next!=NULL && cursor2->next->fbc21==cursor2->fbc21 &&
                            cursor2->next->fbc24==cursor2->fbc24 )
                    {
                        cursor2=cursor2->next;
                    }
                    else
                    {
                        cursor1=cursor1->next;
                    }
                }
            }
        }
    }
    return count;
}


/*
* Loop through sorted tables once and get pairs of matching contribution semi-states.
*/
uint32_t table_getresults_value(table_entry_t * table1, table_entry_t *
                                table2,table_entry_t * results)
{
    table_entry_t * cursor1 ;
    table_entry_t * cursor2 ;

    uint32_t count=0;

    if (table1!=NULL && table2!=NULL)
    {
        cursor1 = table1->next;
        cursor2 = table2->next;

        while (cursor1!=NULL && cursor2!=NULL)
        {
            //printf("Considering s:%08x t:%08x\n",(uint32_t)cursor1->value,(uint32_t)cursor2->value);

            if ( ((cursor1->value) > (cursor2->value)) )
            {
                cursor1=cursor1->next;
            }
            else if ( ((cursor1->value) < (cursor2->value)) )
            {
                cursor2=cursor2->next;
            }
            else // equal if ( ((cursor1->fbc24) == (cursor2->fbc21)) )
            {
                count++;
                table_entry_insert_value(results,cursor1->value ,0,0 );

                if (cursor2->next!=NULL && cursor2->next->value==cursor2->value)
                {
                    cursor2=cursor2->next;
                }
                else
                {
                    cursor1=cursor1->next;
                }
            }
        }
    }
    return count;
}


/*
* ------------------------------------------------------------------
*
* Decrypto1 LFSR Functions
*
* ------------------------------------------------------------------
*/

/*
* Create 2 semi-states from a state (For testing only)
*/
__inline void lfsr_unassemble(uint64_t x,uint64_t* s,uint64_t* t)
{
    int i;

    for (i=0; i<24; i++)
    {
        *s |= bit(x,i*2) << i;
        *t |= bit(x,i*2+1) << i;
    }
}

/*
* Create a state from 2 semi-states
*/
__inline uint64_t lfsr_assemble(uint64_t s,uint64_t t)
{
    int i;
    uint64_t temp=0;

    for (i=0; i<24; i++)
    {
        temp |= bit(s,i)<<(i*2);
        temp |= bit(t,i)<<(i*2+1);
    }
    return temp;
}

/*
* Rollback LFSR by one bit
*/
__inline void lfsr_rollback_bit(uint64_t *state,uint8_t input,uint8_t is_feedback)
{
    uint64_t fb = 0;
    *state= *state<<1;
    if (is_feedback) fb=lf20(*state);

    *state = *state | ((bit(*state,48)
                        ^ bit(*state,5)
                        ^ bit(*state,9)
                        ^ bit(*state,10)
                        ^ bit(*state,12)
                        ^ bit(*state,14)
                        ^ bit(*state,15)
                        ^ bit(*state,17)
                        ^ bit(*state,19)
                        ^ bit(*state,24)
                        ^ bit(*state,25)
                        ^ bit(*state,27)
                        ^ bit(*state,29)
                        ^ bit(*state,35)
                        ^ bit(*state,39)
                        ^ bit(*state,41)
                        ^ bit(*state,42)
                        ^ bit(*state,43)
                        ^ input
                        ^ fb ));

    //*state = *state & 0xffffffffffffULL;
	*state = *state & 281474976710655UL;
}

/*
* Rollback LFSR by eight bits
*/
__inline void lfsr_rollback_byte(uint64_t *state,uint8_t input,uint8_t is_feedback)
{
    int i;

    for (i=0; i<8; i++)
    {
        lfsr_rollback_bit(state,bit(input,7-i),is_feedback);
    }

}

/*
* Rollback LFSR by thirty-two bits
*/
__inline void lfsr_rollback_word(uint64_t *state,uint32_t input,uint8_t is_feedback)
{
    int i;

    for (i=0; i<4; i++)
    {
        lfsr_rollback_byte(state,(uint8_t)(input>>(i*8))&0xff,is_feedback);
    }
}

/*
* Rollback LFSR by multiple bits
*/
__inline void lfsr_rollback_m(uint64_t *state,int count)
{
    int i;
    for (i=0; i<count; i++)
    {
        lfsr_rollback_bit(state,0,0);
    }
}

/*
* Rollforward LFSR by one bit
*/
__inline void lfsr_rollforward (uint64_t *state)
{
    const uint64_t x = *state;

    *state = (x >> 1) |
             ((((x >> 0) ^ (x >> 5)
                ^ (x >> 9) ^ (x >> 10) ^ (x >> 12) ^ (x >> 14)
                ^ (x >> 15) ^ (x >> 17) ^ (x >> 19) ^ (x >> 24)
                ^ (x >> 25) ^ (x >> 27) ^ (x >> 29) ^ (x >> 35)
                ^ (x >> 39) ^ (x >> 41) ^ (x >> 42) ^ (x >> 43)
               ) & 1) << 47);

}

/*
* Rollforward LFSR by multiple bits
*/
__inline void lfsr_rollforward_m(uint64_t *state,int count)
{
    int i;
    for (i=0; i<count; i++)
    {
        lfsr_rollforward(state);
    }
}

/*
* Rollforward LFSR by 8 bits and extract 8 bits of keystream
*/
uint8_t lfsr_encrypt_byte(uint64_t *state)
{
    int i;
    uint8_t ret=0;
    for (i=0; i<8; i++)
    {
        ret |= lf20 (*state)<<i;
        lfsr_rollforward(state);
    }
    return ret;
}

/*
* Rollforward LFSR by 4 bits and extract 4 bits of keystream
*/
uint8_t lfsr_encrypt_nibble(uint64_t *state)
{
    int i;
    uint8_t ret=0;
    for (i=0; i<4; i++)
    {
        ret |= lf20 (*state)<<i;
        lfsr_rollforward(state);
    }
    return ret;
}
/*
* ------------------------------------------------------------------
*
* Decrypto1 crypto1 Functions
*
* Original Code By Karsten Nohl, Henryk Pl?tz, Sean O¡¯Neil
* [Philips/NXP Mifare Crypto-1 implementation v1.0]
* ------------------------------------------------------------------
*/

/* Reverse the bit order in the 8 bit value x */
#define rev8(x) ((((x)>>7)&1) ^((((x)>>6)&1)<<1)^\
  ((((x)>>5)&1)<<2)^((((x)>>4)&1)<<3)^\
  ((((x)>>3)&1)<<4)^((((x)>>2)&1)<<5)^\
  ((((x)>>1)&1)<<6)^(((x)&1)<<7))
/* Reverse the bit order in the 16 bit value x */
#define rev16(x) (rev8 (x)^(rev8 (x>> 8)<< 8))
/* Reverse the bit order in the 32 bit value x */
#define rev32(x) (rev16(x)^(rev16(x>>16)<<16))

#define i4(x,a,b,c,d) ((uint32_t)( \
  (((x)>>(a)) & 1)<<0 \
  | (((x)>>(b)) & 1)<<1 \
  | (((x)>>(c)) & 1)<<2 \
  | (((x)>>(d)) & 1)<<3 \
  ))

/* == keystream generating filter function === */
/* This macro selects the four bits at offset a, b, c and d from the value x
* and returns the concatenated bitstring x_d || x_c || x_b || x_a as an integer
*/
const uint32_t f2_f4a = 0x9E98;
const uint32_t f2_f4b = 0xB48E;
const uint32_t f2_f5c = 0xEC57E80A;

/* Return one bit of non-linear filter function output for 48 bits of
* state input */
uint32_t sf20 (uint64_t s)
{
    // const uint32_t d = 2;
    /* number of cycles between when key stream is produced
    * and when key stream is used.
    * Irrelevant for software implementations, but important
    * to consider in side-channel attacks */

    const uint32_t i5 = ((f2_f4b >> i4 (s, 0, 1,2,3)) & 1)<<0
                        | ((f2_f4a >> i4 (s,4,5,6,7)) & 1)<<1
                        | ((f2_f4a >> i4 (s,8,9,10,11)) & 1)<<2
                        | ((f2_f4b >> i4 (s,12,13,14,15)) & 1)<<3
                        | ((f2_f4a >> i4 (s,16,17,18,19)) & 1)<<4;

    return (f2_f5c >> i5) & 1;
}

/* Return one bit of non-linear filter function output for 20 bits of
* semi-state input */
uint8_t lf20 (uint64_t x)
{
    const uint32_t d = 2; /* number of cycles between when key stream is produced
  * and when key stream is used.
  * Irrelevant for software implementations, but important
  * to consider in side-channel attacks */

    const uint32_t i5 = ((f2_f4b >> i4 (x, 7+d, 9+d,11+d,13+d)) & 1)<<0
                        | ((f2_f4a >> i4 (x,15+d,17+d,19+d,21+d)) & 1)<<1
                        | ((f2_f4a >> i4 (x,23+d,25+d,27+d,29+d)) & 1)<<2
                        | ((f2_f4b >> i4 (x,31+d,33+d,35+d,37+d)) & 1)<<3
                        | ((f2_f4a >> i4 (x,39+d,41+d,43+d,45+d)) & 1)<<4;

    return (f2_f5c >> i5) & 1;
}

/* Get the next successor of a PRNG nonce */
uint32_t nonce_get_successor(uint32_t nonce)
{
    nonce = rev32(nonce);
    nonce = (nonce<<1) | ( ((nonce>>15)^(nonce>>13)^(nonce>>12)^(nonce>>10)) & 1 );
    return rev32(nonce);
}

/* Get the n-th successor of a PRNG nonce */
uint32_t nonce_get_successor_m(uint32_t nonce,uint32_t count)
{

    int i;
    nonce = rev32(nonce);
    for (i=0; i<count; i++)
    {
        nonce = (nonce<<1) | ( ((nonce>>15)^(nonce>>13)^(nonce>>12)^(nonce>>10)) & 1 );
    }

    return rev32(nonce);
}

/*
* ------------------------------------------------------------------
*
* Recover Logic Functions
*
* ------------------------------------------------------------------
*/
uint32_t recover_states(uint64_t keystream, uint32_t len, table_entry_t *
                        results,uint32_t rewindbitcount)
{
    //Variables
    int i;
    uint32_t resultscount=0;
    table_entry_t table1;
    table_entry_t table2;
	table_entry_t * cur;


    printf("\n=== Decrypto1 ===\n");

    //Init the tables
    printf("Init Tables...................\n");
    table_init(&table1, bit(keystream,0));
    table_init(&table2, bit(keystream,1));
    printf("Done size: %d/%d\n", table_entry_get_size(&table1), table_entry_get_size(&table2));


    //Loop Throughs
    printf("Extending Tables..............\n");
    for (i=2; i<len; i+=2)
    {
        table_loopthrough(&table1, bit(keystream,i),0);
        table_loopthrough(&table2, bit(keystream,i+1),1);
		//printf("extend %d: table_cap(%d/%d), count(%d/%d)\n", i, (uint32_t)table1.value,(uint32_t)table2.value, table_entry_get_size(&table1), table_entry_get_size(&table2));
		//cur = table1.next;
		//printf("table1 first value: %#16" PRIx64 ", fbc21: %08x, fbc24: %08x\n", cur->value, cur->fbc21, cur->fbc24);
		//cur = table_entry_last(&table1);
		//printf("table1 last  value: %#16" PRIx64 ", fbc21: %08x, fbc24: %08x\n", cur->value, cur->fbc21, cur->fbc24);
		//cur = table2.next;
		//printf("table2 first value: %#16" PRIx64 ", fbc21: %08x, fbc24: %08x\n", cur->value, cur->fbc21, cur->fbc24);
		//cur = table_entry_last(&table2);
		//printf("table2 last  value: %#16" PRIx64 ", fbc21: %08x, fbc24: %08x\n", cur->value, cur->fbc21, cur->fbc24);
    }
    printf("Done (length:%d/%d)\n",(uint32_t)table1.value,(uint32_t)table2.value);


    //Sorting
    printf("Sorting Table1................\n");
	//cur = table1.next;
	//printf("table1 first value: %#16" PRIx64 ", fbc21: %08x, fbc24: %08x\n", cur->value, cur->fbc21, cur->fbc24);
	//cur = table_entry_last(&table1);
	//printf("table1 last  value: %#16" PRIx64 ", fbc21: %08x, fbc24: %08x\n", cur->value, cur->fbc21, cur->fbc24);

    quicksort_24_21(table1.next,NULL);
    printf("Done (size:%d)\n",table_entry_get_size( &table1));

	//cur = table1.next;
	//printf("table1 sorted value: %#16" PRIx64 ", fbc21: %08x, fbc24: %08x\n", cur->value, cur->fbc21, cur->fbc24);

    printf("Sorting Table2................\n");
	//cur = table2.next;
	//printf("table2 first value: %#16" PRIx64 ", fbc21: %08x, fbc24: %08x\n", cur->value, cur->fbc21, cur->fbc24);
	//cur = table_entry_last(&table2);
	//printf("table2 last  value: %#16" PRIx64 ", fbc21: %08x, fbc24: %08x\n", cur->value, cur->fbc21, cur->fbc24);

    quicksort_21_24(table2.next,NULL);
    printf("Done (size:%d)\n",table_entry_get_size( &table2));

	//cur = table2.next;
	//printf("table2 sorted value: %#16" PRIx64 ", fbc21: %08x, fbc24: %08x\n", cur->value, cur->fbc21, cur->fbc24);


    //Results
    printf("Getting Results...............\n");
    resultscount=table_getresults_fbc(&table1, &table2,results,rewindbitcount);
    printf("Done (%d results)\n",resultscount);
    return resultscount;
}

/*
* ------------------------------------------------------------------
*
* Find correct Nonce from nested authentication
*
* ------------------------------------------------------------------
*/

/*
* Get parity of 8 bits
*/
uint8_t parity8(uint8_t value)
{
    value = (value^(value >> 4))& 0xf;
    return 1^bit(0x6996, value );
}

/*
* Get the 4 parity of 32 bits of data
*/
uint32_t parity32(uint32_t value)
{
    int i;
    uint32_t parity=0;

    for (i=0; i<4; i++)
    {
        parity|=(parity8(value>>(i*8))<<i);

    }

    return parity;
}

/*
* Find the tag nonce of an encrypted nested authentication
*/
uint32_t nonce_find_tagnonce( uint32_t parity1,uint32_t nonce_t,
                              uint32_t parity2,uint32_t nonce_tsuc2,
                              uint32_t parity3,uint32_t nonce_tsuc3,
                              uint32_t nonce_tprev,
                              uint32_t timediff)
{
    uint8_t pt0,pt1,pt2,pt3,pt4,pt5,pt6,pt7,pt8,pt9;
    uint32_t candidate_t,candidate_tsuc2,candidate_tsuc3;
    uint32_t parity_t,parity_tsuc2,parity_tsuc3;
    int i;

    //Calculate conditions candidate must meet
    pt0=bit(parity1,3)^bit(nonce_t,16);
    pt1=bit(parity1,2)^bit(nonce_t,8);
    pt2=bit(parity1,1)^bit(nonce_t,0);
    pt3=bit(parity2,3)^bit(nonce_tsuc2,16);
    pt4=bit(parity2,2)^bit(nonce_tsuc2,8);
    pt5=bit(parity2,1)^bit(nonce_tsuc2,0);
    pt6=bit(parity2,0)^bit(nonce_tsuc3,24);
    pt7=bit(parity3,3)^bit(nonce_tsuc3,16);
    pt8=bit(parity3,2)^bit(nonce_tsuc3,8);
    pt9=bit(parity3,1)^bit(nonce_tsuc3,0);

    candidate_t=nonce_tprev;
    candidate_tsuc2=nonce_get_successor_m(candidate_t,64);
    candidate_tsuc3=nonce_get_successor_m(candidate_t,96);

    for (i=0; i<65535; i++)
    {
        candidate_t=nonce_get_successor(candidate_t);
        candidate_tsuc2=nonce_get_successor(candidate_tsuc2);
        candidate_tsuc3=nonce_get_successor(candidate_tsuc3);

        parity_t=parity32(candidate_t);
        parity_tsuc2=parity32(candidate_tsuc2);
        parity_tsuc3=parity32(candidate_tsuc3);

        if ( pt0==bit(parity_t,3)^bit(candidate_t,16) &&
                pt1==bit(parity_t,2)^bit(candidate_t,8) &&
                pt2==bit(parity_t,1)^bit(candidate_t,0) &&
                pt3==bit(parity_tsuc2,3)^bit(candidate_tsuc2,16) &&
                pt4==bit(parity_tsuc2,2)^bit(candidate_tsuc2,8) &&
                pt5==bit(parity_tsuc2,1)^bit(candidate_tsuc2,0) &&
                pt6==bit(parity_tsuc2,0)^bit(candidate_tsuc3,24) &&
                pt7==bit(parity_tsuc3,3)^bit(candidate_tsuc3,16) &&
                pt8==bit(parity_tsuc3,2)^bit(candidate_tsuc3,8) &&
                pt9==bit(parity_tsuc3,1)^bit(candidate_tsuc3,0))
        {
            printf("candidate_t:%08x\n",candidate_t);
        }
    }
	return candidate_t;
}