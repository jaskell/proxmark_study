/********************************************************************
* decrypto1.h
********************************************************************
* Find a key from Philips/NXP Mifare Crypto-1 keystream
*
* Based on the paper :
* "Dismantling MIFARE Classic"
* By Flavio D. Garcia, Gerhard de Koning Gans, Ruben Muijrers,
* Peter van Rossum, Roel Verdult, Ronny Wichers Schreur, and Bart Jacobs
* Institute for Computing and Information Sciences,
* Radboud University Nijmegen, The Netherlands
*
* Code Implementation by Kyle Penri-Williams
* kyle.penriwilliams@gmail.com
*
* With elements from crypto1.c by Karsten Nohl, Henryk Pl?tz, Sean O¡¯Neil
*/

#ifndef DECRYPTO1_H_INCLUDED
#define DECRYPTO1_H_INCLUDED


#include <malloc.h>
#include <stdlib.h>
#include <stdint.h>

/*
* Helpers
*/

/* Get bit n from b*/
#define bit(b,n) (((b)>>(n))&1)

/*
* table_entry_t element
*/
typedef struct table_entry_s
{
    uint64_t value; //partial lfsr state
    uint32_t fbc24; //Feedback contribution
    uint32_t fbc21; //Feedback contribution
    struct table_entry_s * next;
    struct table_entry_s * prev;
} table_entry_t;

/*
* ------------------------------------------------------------------
*
* Table Entry List Functions
*
* ------------------------------------------------------------------
*/
void quicksort_value(table_entry_t* start,table_entry_t* end);
void quicksort_21_24(table_entry_t* start,table_entry_t* end);
void quicksort_24_21(table_entry_t* start,table_entry_t* end);
void table_entry_filter(table_entry_t* head, uint64_t v);
uint32_t table_entry_get_size(table_entry_t* head);
uint64_t table_entry_get_value(table_entry_t* head, uint32_t index);
void table_entry_move( table_entry_t* newparent,table_entry_t* newentry);
void table_entry_insert_value(table_entry_t* parent,uint64_t value ,uint64_t fbc24,uint64_t
                              fbc21 );
void table_entry_insert( table_entry_t* parent,table_entry_t* newentry);
void table_entry_delete( table_entry_t* entry);
void table_entry_init(table_entry_t* head);
/*
* ------------------------------------------------------------------
*
* Decrypto1 Table Functions
*
* ------------------------------------------------------------------
*/
uint32_t table_getresults_fbc(table_entry_t * table1, table_entry_t * table2,table_entry_t *
                              results,uint32_t rewindbitcount);
uint32_t table_getresults_value(table_entry_t * table1, table_entry_t * table2,table_entry_t
                                * results);
void table_loopthrough(table_entry_t * table, uint8_t b, uint8_t is_t);
void update_feedback_contribution(uint64_t value,uint32_t * fbc24,uint32_t * fbc21, uint8_t
                                  is_t);
void table_init(table_entry_t * table,uint32_t b0);
/*
* ------------------------------------------------------------------
*
* Decrypto1 LFSR Functions
*
* ------------------------------------------------------------------
*/
__inline void lfsr_unassemble(uint64_t x,uint64_t* s,uint64_t* t);
__inline uint64_t lfsr_assemble(uint64_t s,uint64_t t);
__inline void lfsr_rollforward (uint64_t *state);
__inline void lfsr_rollforward_m(uint64_t *state,int count);
__inline void lfsr_rollback_bit(uint64_t *state,uint8_t input,uint8_t is_feedback);
__inline void lfsr_rollback_byte(uint64_t *state,uint8_t input,uint8_t is_feedback);
__inline void lfsr_rollback_word(uint64_t *state,uint32_t input,uint8_t is_feedback);
__inline void lfsr_rollback_m(uint64_t *state,int count);
uint8_t lfsr_encrypt_byte(uint64_t *state);
uint8_t lfsr_encrypt_nibble(uint64_t *state);

/*
* ------------------------------------------------------------------
*
* Decrypto1 crypto1 Functions
*
* Original Code By Karsten Nohl, Henryk Pl?tz, Sean O¡¯Neil
* [Philips/NXP Mifare Crypto-1 implementation v1.0]
* ------------------------------------------------------------------
*/
uint32_t sf20 (uint64_t s);
uint8_t lf20 (uint64_t x);
uint32_t nonce_get_successor(uint32_t nonce);
uint32_t nonce_get_successor_m(uint32_t nonce,uint32_t count);



/*
* ------------------------------------------------------------------
*
* Recover Logic Functions
*
* ------------------------------------------------------------------
*/
uint32_t recover_states(uint64_t keystream, uint32_t len, table_entry_t*
                        results,uint32_t rewindbitcount);
uint8_t parity8(uint8_t x);
uint32_t parity32(uint32_t value);
uint32_t nonce_find_tagnonce( uint32_t parity1,uint32_t nonce_t,
                              uint32_t parity2,uint32_t nonce_tsuc2,
                              uint32_t parity3,uint32_t nonce_tsuc3,
                              uint32_t nonce_tprev,
                              uint32_t timediff);

#endif // DECRYPTO1_H_INCLUDED