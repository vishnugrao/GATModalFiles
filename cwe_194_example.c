#include <stdio.h>
#include <stdint.h>

// CWE-194: Unexpected Sign Extension
// This function is vulnerable because it doesn't properly handle
// the sign extension of a char when converting to a larger type
void process_byte(uint8_t input_byte) {
    // Vulnerable: The char is signed by default and will be sign-extended
    // when converted to int
    int processed_value = input_byte;  // Sign extension happens here
    
    // This can lead to unexpected behavior when the byte is interpreted
    // as a signed value
    if (processed_value > 127) {
        printf("Value is greater than 127: %d\n", processed_value);
    } else {
        printf("Value is less than or equal to 127: %d\n", processed_value);
    }
}

int main() {
    // Normal usage with small positive number
    process_byte(42);
    
    // This will demonstrate the sign extension issue
    // The byte 0xFF will be interpreted as -1 after sign extension
    process_byte(0xFF);
    
    return 0;
} 