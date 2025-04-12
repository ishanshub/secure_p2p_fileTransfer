// gcc peer.c -o peer -lssl -lcrypto -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define MAX_PEERS 10
#define BUFFER_SIZE 4096
#define BROADCAST_PORT 9090
#define BROADCAST_INTERVAL 5 // seconds
#define SECRET_KEY "secretkey1234567" // 16 bytes

typedef struct {
    char name[50];
    char ip[INET_ADDRSTRLEN];
    int port;
} Peer;

Peer peers[MAX_PEERS];
int peer_count = 0;
char my_name[50];
char my_ip[INET_ADDRSTRLEN];
int my_port;

void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
             unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0}; // Initialization Vector

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len);

    int len;
    EVP_EncryptFinal_ex(ctx, ciphertext + *ciphertext_len, &len);
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
             unsigned char *plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0}; // Initialization Vector

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, plaintext_len, ciphertext, ciphertext_len);

    int len;
    EVP_DecryptFinal_ex(ctx, plaintext + *plaintext_len, &len);
    *plaintext_len += len;

    EVP_DecryptFinal_ex(ctx, plaintext + *plaintext_len, &len);
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

void generate_hmac(unsigned char *data, int data_len, unsigned char *key, unsigned char *hmac_output) {
    unsigned int len;
    HMAC(EVP_sha256(), key, 16, data, data_len, hmac_output, &len);
}


void do_diffie_hellman(int sock, unsigned char* derived_key) {
    DH* dh = DH_get_2048_256();  // Built-in safe prime group

    // Print DH parameters
    const BIGNUM *p, *q, *g;
    DH_get0_pqg(dh, &p, &q, &g);

    printf("\n[DEBUG] DH Parameters:\n");
    printf("p: ");
    BN_print_fp(stdout, p);
    printf("\n");

    if (q) {
        printf("q: ");
        BN_print_fp(stdout, q);
        printf("\n");
    } else {
        printf("q: (none)\n");
    }

    printf("g: ");
    BN_print_fp(stdout, g);
    printf("\n");

    DH_generate_key(dh);
    const BIGNUM* pub_key = NULL;
    DH_get0_key(dh, &pub_key, NULL);

    int pub_key_len = BN_num_bytes(pub_key);
    unsigned char* pub_key_bin = malloc(pub_key_len);
    BN_bn2bin(pub_key, pub_key_bin);

    // Send my public key
    send(sock, &pub_key_len, sizeof(int), 0);
    send(sock, pub_key_bin, pub_key_len, 0);

    // Receive peer's public key
    int peer_pub_key_len;
    recv(sock, &peer_pub_key_len, sizeof(int), 0);
    unsigned char* peer_pub_key_bin = malloc(peer_pub_key_len);
    recv(sock, peer_pub_key_bin, peer_pub_key_len, 0);

    BIGNUM* peer_pub_key = BN_bin2bn(peer_pub_key_bin, peer_pub_key_len, NULL);

    unsigned char shared_secret[256];
    int secret_size = DH_compute_key(shared_secret, peer_pub_key, dh);

    // 🔥 Print the derived shared secret
    printf("[DEBUG] Derived Shared Secret: ");
    for (int i = 0; i < secret_size; i++) printf("%02x", shared_secret[i]);
    printf("\n\n");

    memcpy(derived_key, shared_secret, 16);  // AES-128

    free(pub_key_bin);
    free(peer_pub_key_bin);
    BN_free(peer_pub_key);
    DH_free(dh);

    // ✨ Log security property
    printf("[SECURITY] Perfect Forward Secrecy (PFS) achieved: Fresh DH key for this connection.\n\n");
}

void* server_thread(void* arg) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(my_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_sock, 5);
    printf("[+] Listening for incoming files on port %d...\n", my_port);

    while (1) {
        int client_sock = accept(server_sock, NULL, NULL);

        unsigned char derived_key[16];
        do_diffie_hellman(client_sock, derived_key);

        int fname_len;
        recv(client_sock, &fname_len, sizeof(int), 0);
        char filename[100];
        recv(client_sock, filename, fname_len, 0);
        filename[fname_len] = '\0';

        int ciphertext_len;
        recv(client_sock, &ciphertext_len, sizeof(int), 0);

        unsigned char* ciphertext = malloc(ciphertext_len);
        recv(client_sock, ciphertext, ciphertext_len, 0);

        unsigned char received_hmac[32];
        recv(client_sock, received_hmac, 32, 0);

        unsigned char computed_hmac[32];
        generate_hmac(ciphertext, ciphertext_len, derived_key, computed_hmac);

        if (memcmp(received_hmac, computed_hmac, 32) != 0) {
            printf("[!] HMAC verification failed!\n");
            free(ciphertext);
            close(client_sock);
            continue;
        }

        unsigned char* plaintext = malloc(ciphertext_len);
        int plaintext_len;
        decrypt(ciphertext, ciphertext_len, derived_key, plaintext, &plaintext_len);

        FILE *fp = fopen(filename, "wb");
        fwrite(plaintext, 1, plaintext_len, fp);
        fclose(fp);

        printf("[+] File received: %s\n", filename);

        free(ciphertext);
        free(plaintext);
        close(client_sock);
    }
    return NULL;
}

void* broadcast_thread(void* arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    int broadcastEnable = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));

    struct sockaddr_in broadcast_addr;
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(BROADCAST_PORT);
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");

    char message[100];

    while (1) {
        sprintf(message, "%s %s %d", my_name, my_ip, my_port);
        sendto(sock, message, strlen(message), 0, (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
        sleep(BROADCAST_INTERVAL);
    }
}

void* listen_broadcast_thread(void* arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in recv_addr;
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(BROADCAST_PORT);
    recv_addr.sin_addr.s_addr = INADDR_ANY;

    bind(sock, (struct sockaddr*)&recv_addr, sizeof(recv_addr));

    while (1) {
        char buffer[100];
        struct sockaddr_in sender_addr;
        socklen_t addr_len = sizeof(sender_addr);
        int len = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&sender_addr, &addr_len);
        buffer[len] = '\0';

        char peer_name[50], peer_ip[INET_ADDRSTRLEN];
        int peer_port;
        sscanf(buffer, "%s %s %d", peer_name, peer_ip, &peer_port);

        if (strcmp(peer_name, my_name) == 0) continue; // Ignore own broadcast

        int found = 0;
        for (int i = 0; i < peer_count; i++) {
            if (strcmp(peers[i].name, peer_name) == 0) {
                found = 1;
                break;
            }
        }
        if (!found && peer_count < MAX_PEERS) {
            strcpy(peers[peer_count].name, peer_name);
            strcpy(peers[peer_count].ip, peer_ip);
            peers[peer_count].port = peer_port;
            peer_count++;
            printf("[+] New peer discovered: %s (%s:%d)\n", peer_name, peer_ip, peer_port);
        }
    }
}


void refresh_peers() {
    printf("\n--- Available Peers ---\n");
    int idx = 1;
    for (int i = 0; i < peer_count; i++) {
        printf("%d. %s (%s:%d)\n", idx++, peers[i].name, peers[i].ip, peers[i].port);
    }
    printf("------------------------\n");
}

void send_file() {
    refresh_peers();
    printf("Enter peer number to send file to: ");
    int choice;
    scanf("%d", &choice);

    if (choice < 1 || choice > peer_count) {
        printf("[!] Invalid choice.\n");
        return;
    }

    Peer p = peers[choice - 1];

    char filepath[100];
    printf("Enter file path: ");
    scanf("%s", filepath);

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        printf("[!] Cannot open file.\n");
        return;
    }

    fseek(fp, 0, SEEK_END);
    int file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *file_data = malloc(file_size);
    fread(file_data, 1, file_size, fp);
    fclose(fp);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in peer_addr;
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(p.port);
    inet_pton(AF_INET, p.ip, &peer_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        printf("[!] Connection failed.\n");
        free(file_data);
        return;
    }

    // Diffie-Hellman key exchange
    unsigned char derived_key[16];
    do_diffie_hellman(sock, derived_key);

    // Encrypt file with derived key
    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len;
    encrypt(file_data, file_size, derived_key, ciphertext, &ciphertext_len);

    // Generate HMAC with derived key
    unsigned char hmac[32];
    generate_hmac(ciphertext, ciphertext_len, derived_key, hmac);

    // Send encrypted file and hmac
    int fname_len = strlen(filepath);
    send(sock, &fname_len, sizeof(int), 0);
    send(sock, filepath, fname_len, 0);
    send(sock, &ciphertext_len, sizeof(int), 0);
    send(sock, ciphertext, ciphertext_len, 0);
    send(sock, hmac, 32, 0);

    printf("[+] File sent successfully!\n");

    free(file_data);
    close(sock);
}

int main() {
    printf("Enter your name: ");
    scanf("%s", my_name);

    printf("Enter your port number: ");
    scanf("%d", &my_port);

    // Get local IP
    system("hostname -I | awk '{print $1}' > myip.txt");
    FILE *fp = fopen("myip.txt", "r");
    fscanf(fp, "%s", my_ip);
    fclose(fp);
    remove("myip.txt");

    pthread_t tid1, tid2, tid3;
    pthread_create(&tid1, NULL, server_thread, NULL);
    pthread_create(&tid2, NULL, broadcast_thread, NULL);
    pthread_create(&tid3, NULL, listen_broadcast_thread, NULL);

    while (1) {
        printf("\nOptions:\n");
        printf("1. Refresh peer list\n");
        printf("2. Send file\n");
        printf("3. Exit\n");
        printf("Choice: ");
        int ch;
        scanf("%d", &ch);

        if (ch == 1) {
            refresh_peers();
        } else if (ch == 2) {
            send_file();
        } else {
            printf("[*] Exiting...\n");
            exit(0);
        }
    }
}
