#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <crypt.h>
#include <pthread.h>
#include <sys/stat.h>

#define PORT 8080
#define BUF_SIZE 1024
#define DISCORIT_DIR "/home/ax3lrod/sisop/fp/DiscorIT"


typedef struct {
    char channel[BUF_SIZE];
    char room[BUF_SIZE];
    int sock;
} ChatMonitorArgs;

void handle_commands(int sock, const char *username);

void display_chat(const char *channel, const char *room) {

    printf("\033[2J");  // Clear entire screen
    printf("\033[H");   // Move cursor to the top left

    char file_path[BUF_SIZE];
    snprintf(file_path, sizeof(file_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, channel, room);

    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        printf("Tidak dapat membuka file chat.\n");
        return;
    }

    printf("\n------------------- Chat %s/%s -------------------\n", channel, room);
    char line[BUF_SIZE];
    char response[BUF_SIZE * 10] = "";
    while (fgets(line, sizeof(line), file)) {
        // Ignore empty lines
        if (strlen(line) <= 1) continue;

        char id_chat[BUF_SIZE], timestamp[BUF_SIZE], username[BUF_SIZE], message[BUF_SIZE];
        
        // Use a pointer to keep track of our position in the line
        char *ptr = line;
        
        // Parse id_chat
        sscanf(ptr, "%[^,]", id_chat);
        ptr = strchr(ptr, ',') + 1;
        
        // Parse timestamp
        sscanf(ptr, "%[^,]", timestamp);
        ptr = strchr(ptr, ',') + 1;
        
        // Parse username
        sscanf(ptr, "%[^,]", username);
        ptr = strchr(ptr, ',') + 1;
        
        // The rest of the line is the message (including spaces)
        strcpy(message, ptr);
        
        // Remove newline from message if present
        char *newline = strchr(message, '\n');
        if (newline) *newline = '\0';

        char chat_info[BUF_SIZE];
        snprintf(chat_info, sizeof(chat_info), "[%s][%s][%s] \"%s\"\n", timestamp, id_chat, username, message);
        
        // Check if appending chat_info would overflow response
        if (strlen(response) + strlen(chat_info) < sizeof(response) - 1) {
            strcat(response, chat_info);
        } else {
            // If we're about to overflow, stop adding messages
            strcat(response, "...\n(more messages not shown due to buffer limit)\n");
            break;
        }
    }

    printf("%s", response);
    printf("-----------------------------------------------------------\n");

    fclose(file);
}

void *monitor_chat(void *arg) {
    ChatMonitorArgs *args = (ChatMonitorArgs *)arg;
    char file_path[BUF_SIZE];
    snprintf(file_path, sizeof(file_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, args->channel, args->room);

    struct stat last_stat;
    if (stat(file_path, &last_stat) == -1) {
        perror("Error getting file stats");
        return NULL;
    }

    while (1) {
        struct stat current_stat;
        if (stat(file_path, &current_stat) == -1) {
            perror("Error getting file stats");
            sleep(1);
            continue;
        }

        if (current_stat.st_mtime != last_stat.st_mtime) {
            display_chat(args->channel, args->room);
            last_stat = current_stat;
        }

        sleep(1);  // Check every second
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s LOGIN username -p password\n", argv[0]);
        return -1;
    }

    struct sockaddr_in address;
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUF_SIZE] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Connection Failed");
        return -1;
    }

    const char *username = argv[2];
    const char *password = argv[4];

    if (strcmp(argv[1], "LOGIN") == 0) {
        snprintf(buffer, sizeof(buffer), "LOGIN_MONITOR %s -p %s", username, password);
        send(sock, buffer, strlen(buffer), 0);
        read(sock, buffer, BUF_SIZE);
        if (strstr(buffer, "berhasil login")) {
            printf("%s\n", buffer);
            handle_commands(sock, username);
        } else {
            printf("Login gagal\n");
        }
    } else {
        fprintf(stderr, "Invalid command. Use LOGIN.\n");
    }

    close(sock);
    return 0;
}

void handle_commands(int sock, const char *username) {
    char buffer[BUF_SIZE];
    char channel[BUF_SIZE] = "";
    char room[BUF_SIZE] = "";
    pthread_t chat_monitor_thread;
    ChatMonitorArgs chat_monitor_args;
    int chat_monitor_active = 0;

    while (1) {
        //printf("[%s] ", username);

        //fgets(buffer, BUF_SIZE, stdin);
        //buffer[strcspn(buffer, "\n")] = 0; // Remove newline character
        //send(sock, buffer, strlen(buffer), 0);

        memset(buffer, 0, sizeof(buffer));
        int bytes_read = read(sock, buffer, BUF_SIZE);
        buffer[bytes_read] = '\0';

        if (sscanf(buffer, "-channel %s -room %s", channel, room) == 2) {

            //printf("Channel: %s\n", channel);
            //printf("Room: %s\n", room);
            //printf("%s\n", buffer);

            // New channel and room received
            if (chat_monitor_active) {
                pthread_cancel(chat_monitor_thread);
                chat_monitor_active = 0;
            }

            // Start new chat monitor thread
            chat_monitor_args.sock = sock;
            strncpy(chat_monitor_args.channel, channel, BUF_SIZE);
            strncpy(chat_monitor_args.room, room, BUF_SIZE);

            if (pthread_create(&chat_monitor_thread, NULL, monitor_chat, (void *)&chat_monitor_args) == 0) {
                chat_monitor_active = 1;
            } else {
                perror("Error creating chat monitor thread");
            }

            display_chat(channel, room);
        } else if(strcmp(buffer, "EXIT") == 0){
            break;
        } else {
            printf("%s\n", buffer);
        }
    }

    if (chat_monitor_active) {
        pthread_cancel(chat_monitor_thread);
    }
}
