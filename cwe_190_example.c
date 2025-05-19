#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// CWE-190: Integer Overflow or Wraparound
// Based on real-world vulnerability in memory allocation
// This example simulates a function that allocates memory based on
// user input, vulnerable to integer overflow

#define MAX_ALLOC_SIZE 1024*1024  // 1MB limit

struct data_block {
    uint32_t size;
    char* data;
};

// Vulnerable function that allocates memory based on user input
struct data_block* allocate_block(uint32_t size, const char* input) {
    struct data_block* block = (struct data_block*)malloc(sizeof(struct data_block));
    if (!block) return NULL;
    
    // Vulnerable: Integer overflow in size calculation
    // If size is close to UINT32_MAX, size + 1 will wrap around to 0
    uint32_t total_size = size + 1;  // Add 1 for null terminator
    
    // This check can be bypassed due to integer overflow
    if (total_size > MAX_ALLOC_SIZE) {
        free(block);
        return NULL;
    }
    
    // Allocate memory based on potentially overflowed size
    block->data = (char*)malloc(total_size);
    if (!block->data) {
        free(block);
        return NULL;
    }
    
    block->size = size;
    // Vulnerable: Could write beyond allocated memory if size overflowed
    memcpy(block->data, input, size);
    block->data[size] = '\0';
    
    return block;
}

int main() {
    // Normal usage
    struct data_block* normal_block = allocate_block(100, "Normal data");
    if (normal_block) {
        printf("Normal block allocated: %s\n", normal_block->data);
        free(normal_block->data);
        free(normal_block);
    }
    
    // Integer overflow attack
    // This will cause size + 1 to wrap around to 0
    uint32_t overflow_size = UINT32_MAX;
    struct data_block* overflow_block = allocate_block(overflow_size, "Overflow data");
    if (overflow_block) {
        printf("Overflow block allocated with size: %u\n", overflow_block->size);
        // This could lead to heap overflow
        printf("Data: %s\n", overflow_block->data);
        free(overflow_block->data);
        free(overflow_block);
    }
    
    // Another attack vector: size close to MAX_ALLOC_SIZE
    uint32_t large_size = MAX_ALLOC_SIZE - 1;
    struct data_block* large_block = allocate_block(large_size, "Large data");
    if (large_block) {
        printf("Large block allocated with size: %u\n", large_block->size);
        free(large_block->data);
        free(large_block);
    }
    
    return 0;
} 