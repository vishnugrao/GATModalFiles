#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// CWE-134: Use of Externally-Controlled Format String
// Based on real-world vulnerability in logging systems
// This example simulates a logging function that is vulnerable
// to format string attacks

#define MAX_LOG_LENGTH 1024

struct log_entry {
    char timestamp[32];
    char level[16];
    char message[MAX_LOG_LENGTH];
};

void log_event(const char* level, const char* message) {
    struct log_entry entry;
    time_t now = time(NULL);
    
    // Format timestamp
    strftime(entry.timestamp, sizeof(entry.timestamp), 
             "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // Copy level
    strncpy(entry.level, level, sizeof(entry.level) - 1);
    entry.level[sizeof(entry.level) - 1] = '\0';
    
    // Vulnerable: Using user input directly in format string
    // This allows an attacker to read memory or crash the program
    printf("[%s] [%s] ", entry.timestamp, entry.level);
    printf(message);  // Should be printf("%s", message)
    printf("\n");
    
    // Also vulnerable: Using user input in snprintf format string
    char log_buffer[MAX_LOG_LENGTH];
    snprintf(log_buffer, sizeof(log_buffer), 
             message,  // Should be "%s", message
             entry.timestamp, entry.level);
}

int main() {
    // Normal usage
    log_event("INFO", "User logged in successfully");
    
    // Format string attack examples
    // 1. Read memory from stack
    log_event("ERROR", "%x %x %x %x %x");
    
    // 2. Read from specific memory address
    log_event("DEBUG", "%s");
    
    // 3. Write to memory (could crash the program)
    log_event("CRITICAL", "%n");
    
    // 4. Complex format string attack
    log_event("WARNING", "%1000x%n");
    
    return 0;
} 