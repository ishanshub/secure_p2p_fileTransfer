// gcc peer.c -o peer -lssl -lcrypto -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define MAX_PEERS 10
#define BUFFER_SIZE 4096
#define BROADCAST_PORT 9090
#define BROADCAST_INTERVAL 5

typedef struct {
    char name[50];
    char ip[INET_ADDRSTRLEN];
    int port;
    time_t last_seen;
} Peer;

Peer peers[MAX_PEERS];
int peer_count = 0;
char my_name[50];
char my_ip[INET_ADDRSTRLEN];
int my_port;

pthread_mutex_t peer_list_mutex = PTHREAD_MUTEX_INITIALIZER;

void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
             unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len);

    int len;
    EVP_EncryptFinal_ex(ctx, ciphertext + *ciphertext_len, &len);
    *ciphertext_len += len;

    memmove(ciphertext + sizeof(iv), ciphertext, *ciphertext_len);
    memcpy(ciphertext, iv, sizeof(iv));
    *ciphertext_len += sizeof(iv);

    EVP_CIPHER_CTX_free(ctx);
}

void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
             unsigned char *plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    memcpy(iv, ciphertext, sizeof(iv));

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, plaintext_len,
                      ciphertext + sizeof(iv), ciphertext_len - sizeof(iv));

    int len;
    EVP_DecryptFinal_ex(ctx, plaintext + *plaintext_len, &len);
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

void generate_hmac(unsigned char *data, int data_len, unsigned char *key,
                   unsigned char *hmac_output) {
    unsigned int len;
    HMAC(EVP_sha256(), key, 16, data, data_len, hmac_output, &len);
}

void do_diffie_hellman(int sock, unsigned char* derived_key) {
    DH* dh = DH_get_2048_256();
    if (!dh || !DH_generate_key(dh)) {
        perror("DH key generation failed");
        exit(EXIT_FAILURE);
    }

    const BIGNUM *pub_key;
    DH_get0_key(dh, &pub_key, NULL);

    int pub_key_len = BN_num_bytes(pub_key);
    unsigned char* pub_key_bin = malloc(pub_key_len);
    BN_bn2bin(pub_key, pub_key_bin);

    if (send(sock, &pub_key_len, sizeof(int), 0) != sizeof(int) ||
        send(sock, pub_key_bin, pub_key_len, 0) != pub_key_len) {
        perror("DH key send failed");
        exit(EXIT_FAILURE);
    }

    int peer_pub_key_len;
    if (recv(sock, &peer_pub_key_len, sizeof(int), 0) != sizeof(int)) {
        perror("DH key receive failed");
        exit(EXIT_FAILURE);
    }

    unsigned char* peer_pub_key_bin = malloc(peer_pub_key_len);
    if (recv(sock, peer_pub_key_bin, peer_pub_key_len, 0) != peer_pub_key_len) {
        perror("DH key receive failed");
        exit(EXIT_FAILURE);
    }

    BIGNUM* peer_pub_key = BN_bin2bn(peer_pub_key_bin, peer_pub_key_len, NULL);
    unsigned char shared_secret[256];
    int secret_size = DH_compute_key(shared_secret, peer_pub_key, dh);

    memcpy(derived_key, shared_secret, 16);

    free(pub_key_bin);
    free(peer_pub_key_bin);
    BN_free(peer_pub_key);
    DH_free(dh);
}

void* server_thread(void* arg) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Server socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(my_port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0 ||
        listen(server_sock, 5) < 0) {
        perror("Server setup failed");
        exit(EXIT_FAILURE);
    }

    printf("[+] Listening for incoming files on port %d...\n", my_port);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock < 0) continue;

        unsigned char derived_key[16];
        do_diffie_hellman(client_sock, derived_key);

        int fname_len;
        if (recv(client_sock, &fname_len, sizeof(int), 0) != sizeof(int)) {
            close(client_sock);
            continue;
        }

        char filename[256];
        if (recv(client_sock, filename, fname_len, 0) != fname_len) {
            close(client_sock);
            continue;
        }
        filename[fname_len] = '\0';

        int ciphertext_len;
        if (recv(client_sock, &ciphertext_len, sizeof(int), 0) != sizeof(int)) {
            close(client_sock);
            continue;
        }

        unsigned char* ciphertext = malloc(ciphertext_len);
        if (recv(client_sock, ciphertext, ciphertext_len, 0) != ciphertext_len) {
            free(ciphertext);
            close(client_sock);
            continue;
        }

        unsigned char received_hmac[32];
        if (recv(client_sock, received_hmac, 32, 0) != 32) {
            free(ciphertext);
            close(client_sock);
            continue;
        }

        unsigned char computed_hmac[32];
        generate_hmac(ciphertext, ciphertext_len, derived_key, computed_hmac);

        if (memcmp(received_hmac, computed_hmac, 32) != 0) {
            printf("[!] HMAC verification failed for %s\n", filename);
            free(ciphertext);
            close(client_sock);
            continue;
        }

        unsigned char* plaintext = malloc(ciphertext_len);
        int plaintext_len;
        decrypt(ciphertext, ciphertext_len, derived_key, plaintext, &plaintext_len);

        FILE *fp = fopen(filename, "wb");
        if (fp) {
            fwrite(plaintext, 1, plaintext_len, fp);
            fclose(fp);
            printf("[+] File received: %s\n", filename);
        }

        free(ciphertext);
        free(plaintext);
        close(client_sock);
    }
    return NULL;
}

void* broadcast_thread(void* arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Broadcast socket creation failed");
        exit(EXIT_FAILURE);
    }

    int broadcastEnable = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));

    struct sockaddr_in broadcast_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(BROADCAST_PORT),
        .sin_addr.s_addr = inet_addr("255.255.255.255")
    };

    char message[100];
    while (1) {
        snprintf(message, sizeof(message), "%s %s %d", my_name, my_ip, my_port);
        sendto(sock, message, strlen(message), 0, 
              (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
        sleep(BROADCAST_INTERVAL);
    }
}

void* listen_broadcast_thread(void* arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Broadcast listener socket creation failed");
        exit(EXIT_FAILURE);
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in recv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(BROADCAST_PORT),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(sock, (struct sockaddr*)&recv_addr, sizeof(recv_addr)) < 0) {
        perror("Broadcast listener bind failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        char buffer[100];
        struct sockaddr_in sender_addr;
        socklen_t addr_len = sizeof(sender_addr);
        
        int len = recvfrom(sock, buffer, sizeof(buffer)-1, 0, 
                          (struct sockaddr*)&sender_addr, &addr_len);
        if (len <= 0) continue;
        
        buffer[len] = '\0';
        
        char peer_name[50], peer_ip[INET_ADDRSTRLEN];
        int peer_port;
        if (sscanf(buffer, "%49s %15s %d", peer_name, peer_ip, &peer_port) != 3) continue;

        if (strcmp(peer_name, my_name) == 0) continue;

        pthread_mutex_lock(&peer_list_mutex);
        int found = 0;
        for (int i = 0; i < peer_count; i++) {
            if (strcmp(peers[i].name, peer_name) == 0) {
                peers[i].last_seen = time(NULL);
                found = 1;
                break;
            }
        }

        if (!found && peer_count < MAX_PEERS) {
            strncpy(peers[peer_count].name, peer_name, sizeof(peers[0].name));
            strncpy(peers[peer_count].ip, peer_ip, sizeof(peers[0].ip));
            peers[peer_count].port = peer_port;
            peers[peer_count].last_seen = time(NULL);
            peer_count++;
            printf("[+] New peer discovered: %s (%s:%d)\n", peer_name, peer_ip, peer_port);
        }
        pthread_mutex_unlock(&peer_list_mutex);
    }
}

void refresh_peers() {
    pthread_mutex_lock(&peer_list_mutex);
    printf("\n--- Available Peers ---\n");
    for (int i = 0; i < peer_count; i++) {
        printf("%d. %s (%s:%d)\n", i+1, peers[i].name, peers[i].ip, peers[i].port);
    }
    printf("------------------------\n");
    pthread_mutex_unlock(&peer_list_mutex);
}

void* cleanup_peers_thread(void* arg) {
    while (1) {
        sleep(5);
        time_t now = time(NULL);

        pthread_mutex_lock(&peer_list_mutex);
        for (int i = 0; i < peer_count; ) {
            if (difftime(now, peers[i].last_seen) > 15) {
                printf("[-] Removing inactive peer: %s (%s:%d)\n", peers[i].name, peers[i].ip, peers[i].port);
                // Shift remaining peers up
                for (int j = i; j < peer_count - 1; j++) {
                    peers[j] = peers[j + 1];
                }
                peer_count--;
            } else {
                i++;
            }
        }
        pthread_mutex_unlock(&peer_list_mutex);
    }
    return NULL;
}


void send_file() {
    refresh_peers();
    if (peer_count == 0) {
        printf("[!] No peers available\n");
        return;
    }

    printf("Enter peer number to send file to: ");
    int choice;
    if (scanf("%d", &choice) != 1 || choice < 1 || choice > peer_count) {
        printf("[!] Invalid choice\n");
        while (getchar() != '\n'); // Clear input buffer
        return;
    }

    Peer p;
    pthread_mutex_lock(&peer_list_mutex);
    p = peers[choice-1];
    pthread_mutex_unlock(&peer_list_mutex);

    char filepath[256];
    printf("Enter file path: ");
    if (scanf("%255s", filepath) != 1) {
        printf("[!] Invalid file path\n");
        return;
    }

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        printf("[!] Cannot open file\n");
        return;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        printf("[!] Invalid file size\n");
        fclose(fp);
        return;
    }

    unsigned char *file_data = malloc(file_size);
    if (!file_data) {
        printf("[!] Memory allocation failed\n");
        fclose(fp);
        return;
    }

    if (fread(file_data, 1, file_size, fp) != (size_t)file_size) {
        printf("[!] File read error\n");
        free(file_data);
        fclose(fp);
        return;
    }
    fclose(fp);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        free(file_data);
        return;
    }

    struct sockaddr_in peer_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(p.port),
        .sin_addr.s_addr = inet_addr(p.ip)
    };

    if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        perror("Connection failed");
        free(file_data);
        close(sock);
        return;
    }

    unsigned char derived_key[16];
    do_diffie_hellman(sock, derived_key);

    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len;
    encrypt(file_data, file_size, derived_key, ciphertext, &ciphertext_len);

    unsigned char hmac[32];
    generate_hmac(ciphertext, ciphertext_len, derived_key, hmac);

    const char *filename = strrchr(filepath, '/');
    filename = filename ? filename + 1 : filepath;
    int fname_len = strlen(filename);

    if (send(sock, &fname_len, sizeof(int), 0) != sizeof(int) ||
        send(sock, filename, fname_len, 0) != fname_len ||
        send(sock, &ciphertext_len, sizeof(int), 0) != sizeof(int) ||
        send(sock, ciphertext, ciphertext_len, 0) != ciphertext_len ||
        send(sock, hmac, 32, 0) != 32) {
        printf("[!] File send failed\n");
    } else {
        printf("[+] File sent successfully: %s\n", filename);
    }

    free(file_data);
    close(sock);
}

int main() {
    printf("Enter your name: ");
    if (scanf("%49s", my_name) != 1) {
        fprintf(stderr, "Invalid name input\n");
        return EXIT_FAILURE;
    }

    printf("Enter your port number: ");
    if (scanf("%d", &my_port) != 1 || my_port < 1024 || my_port > 65535) {
        fprintf(stderr, "Invalid port number (1024-65535)\n");
        return EXIT_FAILURE;
    }

    FILE *fp = popen("hostname -I | awk '{print $1}'", "r");
    if (!fp || fscanf(fp, "%15s", my_ip) != 1) {
        fprintf(stderr, "Failed to get local IP\n");
        return EXIT_FAILURE;
    }
    pclose(fp);

    pthread_t threads[4];
    pthread_create(&threads[0], NULL, server_thread, NULL);
    pthread_create(&threads[1], NULL, broadcast_thread, NULL);
    pthread_create(&threads[2], NULL, listen_broadcast_thread, NULL);
    pthread_create(&threads[3], NULL, cleanup_peers_thread, NULL);

    while (1) {
        printf("\nOptions:\n1. Refresh peer list\n2. Send file\n3. Exit\nChoice: ");
        int choice;
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }

        switch (choice) {
            case 1:
                refresh_peers();
                break;
            case 2:
                send_file();
                break;
            case 3:
                printf("[*] Exiting...\n");
                exit(EXIT_SUCCESS);
            default:
                printf("[!] Invalid choice\n");
        }
    }
}
