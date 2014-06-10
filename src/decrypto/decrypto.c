#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include "decrypto1.h"

void print_fbc(uint64_t n) {
	while (n) {
		if (n & 1)
			printf("1");
		else
			printf("0");
		n >>= 1;
	}
}

int main3(int argc, char* argv[])
{
	//uint64_t value = 0x00079597c8302914;
	//uint64_t value = 0xffd2f;
	uint64_t value = 0x2ffd6b;
	uint32_t fbc24 = 0, fbc21 = 0;
	int i;

	for (i = 0; i < 2; i ++) {
		update_feedback_contribution(value, &fbc24, &fbc21, 0);
		value = value >> 1;
	}
	printf("fbc21: %08x, ", fbc21);
	print_fbc(fbc21);
	printf("\n");
	printf("fbc24: %08x, ", fbc24);
	print_fbc(fbc24);
	printf("\n");
	getch();
	return 0;
}

int main(int argc, char* argv[])
{
	clock_t t;
	double time_taken;
	uint32_t i, count = 0;
	table_entry_t results = {0};
	table_entry_t* root = &results;
	uint32_t rewindbitcount = 0;
	uint32_t len = 64;
	 //uint64_t keystream = 0x198fefc6ab328fe3;
	// ks2: e38f32ab
	// ks3: c6ef8f19
	   uint64_t keystream = 0xde32c3a5f4c842fc;
	// ks2: fc42c8f4
	// ks3: a5c332de
    t = clock();
	count = recover_states(keystream, len, root, rewindbitcount);
	printf("count: %d", count);
	root = root->next;
	for (i = 0; i < count; i ++) {
		printf("key %d: %#" PRIx64 "\n", i, root->value);
		root = root->next;
	}
    t = clock() - t;
    time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds
	printf("elapsed time : %f seconds to execute\n", time_taken);
	printf("game over!\n");
	getch();
	return 0;
}
