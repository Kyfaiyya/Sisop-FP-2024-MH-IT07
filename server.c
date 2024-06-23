#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <crypt.h>
#include <stdbool.h>
#include <errno.h>

#define PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 10240
#define SALT_SIZE 64
#define USERS_FILE "/home/kyfaiyya/SISOP/FP/DiscorIT/users.csv"
#define CHANNELS_FILE "/home/kyfaiyya/SISOP/FP/DiscorIT/channels.csv"

typedef struct {
    int socket;
    struct sockaddr_in address;
    char logged_in_user[50];
    char logged_in_role[10];
} client_info;

client_info *clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

void *handle_client(void *arg);
void daemonize();

void register_user(const char *username, const char *password, client_info *client);
void login_user(const char *username, const char *password, client_info *client);
void create_channel(const char *username, const char *channel, const char *key, client_info *client);

int main() {
    daemonize();

    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);
    pthread_t tid;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Gagal membuat socket");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Gagal bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Gagal listen");
        exit(EXIT_FAILURE);
    }

    printf("Server berjalan sebagai daemon pada port %d\n", PORT);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addr_len)) < 0) {
            perror("Gagal melakukan accept");
            exit(EXIT_FAILURE);
        }

        pthread_t tid;
        client_info *client = (client_info *)malloc(sizeof(client_info));
        client->socket = new_socket;
        client->address = address;
        memset(client->logged_in_user, 0, sizeof(client->logged_in_user));
        memset(client->logged_in_role, 0, sizeof(client->logged_in_role));

        pthread_create(&tid, NULL, handle_client, (void *)client);
    }

    return 0;
}

void daemonize() {
    pid_t pid, sid;

    pid = fork();

    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int log_fd = open("/tmp/server.log", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (log_fd < 0) {
        exit(EXIT_FAILURE);
    }
    dup2(log_fd, STDOUT_FILENO);
    dup2(log_fd, STDERR_FILENO);
}

void *handle_client(void *arg) {
    client_info *cli = (client_info *)arg;
    char buffer[BUFFER_SIZE];
    int n;

    while ((n = read(cli->socket, buffer, sizeof(buffer))) > 0) {
        buffer[n] = '\0';
        printf("Pesan dari client: %s\n", buffer);

        char *token = strtok(buffer, " ");
        if (token == NULL) {
            char response[] = "Perintah tidak dikenali";
            if (write(cli->socket, response, strlen(response)) < 0) {
                perror("Gagal mengirim respons ke client");
            }
            continue;
        }

        if (strcmp(token, "REGISTER") == 0) {
            char *username = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            register_user(username, password, cli);
        } else if (strcmp(token, "LOGIN") == 0) {
            char *username = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            if (username == NULL || password == NULL) {
                char response[] = "Format perintah LOGIN tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Gagal mengirim respons ke client");
                }
                continue;
            }
            login_user(username, password, cli);
        } else if (strcmp(token, "CREATE") == 0) {
            char *subcommand = strtok(NULL, " ");
            if (subcommand == NULL) {
                char response[] = "Format perintah CREATE tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Gagal mengirim respons ke client");
                }
                continue;
            }
            if (strcmp(subcommand, "CHANNEL") == 0) {
                char *channel = strtok(NULL, " ");
                char *key = strtok(NULL, " ");
                if (channel == NULL || key == NULL) {
                    char response[] = "Format perintah CREATE CHANNEL tidak valid";
                    if (write(cli->socket, response, strlen(response)) < 0) {
                        perror("Gagal mengirim respons ke client");
                    }
                    continue;
                }
                create_channel(cli->logged_in_user, channel, key, cli);
            } else {
                char response[] = "Perintah CREATE tidak valid";
                if (write(cli->socket, response, strlen(response)) < 0) {
                    perror("Gagal mengirim respons ke client");
                }
            }
        } else {
            char response[] = "Perintah tidak dikenali";
            if (write(cli->socket, response, strlen(response)) < 0) {
                perror("Gagal mengirim respons ke client");
            }
        }
    }

    close(cli->socket);
    free(cli);
    pthread_exit(NULL);
}

void register_user(const char *username, const char *password, client_info *client) {
    if (username == NULL || password == NULL) {
        char response[] = "Username atau password tidak boleh kosong";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
        return;
    }

    FILE *file = fopen(USERS_FILE, "r+");
    if (!file) {
        file = fopen(USERS_FILE, "w+");
        if (!file) {
            perror("Tidak dapat membuka atau membuat file");
            char response[] = "Tidak dapat membuka atau membuat file users.csv";
            if (write(client->socket, response, strlen(response)) < 0) {
                perror("Gagal mengirim respons ke client");
            }
            return;
        }
    }

    char line[256];
    bool user_exists = false;
    int user_count = 0;

    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        if (token == NULL) continue;
        token = strtok(NULL, ",");
        if (token && strcmp(token, username) == 0) {
            user_exists = true;
            break;
        }
        user_count++;
    }

    if (user_exists) {
        char response[100];
        snprintf(response, sizeof(response), "%s sudah terdaftar", username);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
        fclose(file);
        return;
    }

    fseek(file, 0, SEEK_END);

    char salt[SALT_SIZE];
    snprintf(salt, sizeof(salt), "$6$%.22s", "inistringsaltuntukcrypt");
    char *hash = crypt(password, salt);

    if (hash == NULL) {
        char response[] = "Gagal membuat hash password";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
        fclose(file);
        return;
    }

    fprintf(file, "%d,%s,%s,%s\n", user_count + 1, username, hash, user_count == 0 ? "ROOT" : "USER");
    fclose(file);

    char response[100];
    snprintf(response, sizeof(response), "%s berhasil register", username);
    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Gagal mengirim respons ke client");
    }
}

void login_user(const char *username, const char *password, client_info *client) {
    FILE *file = fopen(USERS_FILE, "r");
    if (!file) {
        char response[] = "Tidak dapat membuka file users.csv atau user belum terdaftar";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
        return;
    }

    char line[256];
    bool user_found = false;

    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ",");
        if (token && strcmp(token, username) == 0) {
            user_found = true;
            token = strtok(NULL, ","); // Hash password
            char *stored_hash = token;

            if (strcmp(crypt(password, stored_hash), stored_hash) == 0) {
                snprintf(client->logged_in_user, sizeof(client->logged_in_user), "%s", username);
                token = strtok(NULL, ","); // Role
                snprintf(client->logged_in_role, sizeof(client->logged_in_role), "%s", token);

                char response[BUFFER_SIZE];
                snprintf(response, sizeof(response), "%s berhasil login", username);
                if (write(client->socket, response, strlen(response)) < 0) {
                    perror("Gagal mengirim respons ke client");
                }
            } else {
                char response[] = "Password salah";
                if (write(client->socket, response, strlen(response)) < 0) {
                    perror("Gagal mengirim respons ke client");
                }
            }
            break;
        }
    }

    if (!user_found) {
        char response[] = "Username tidak ditemukan";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
    }

    fclose(file);
}

void create_channel(const char *username, const char *channel, const char *key, client_info *client) {
    FILE *channels_file = fopen(CHANNELS_FILE, "a+");
    if (!channels_file) {
        char response[] = "Gagal membuka file channels.csv";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
        return;
    }

    char salt[SALT_SIZE];
    snprintf(salt, sizeof(salt), "$6$%.22s", "inistringsaltuntukcrypt");
    char *hash = crypt(key, salt);

    if (hash == NULL) {
        char response[] = "Gagal membuat hash key";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
        fclose(channels_file);
        return;
    }

    fprintf(channels_file, "%d,%s,%s\n", rand(), channel, hash);
    fclose(channels_file);

    size_t channel_path_len = snprintf(NULL, 0, "/home/kyfaiyya/SISOP/FP/DiscorIT/%s", channel) + 1;
    char *channel_path = (char *)malloc(channel_path_len);
    snprintf(channel_path, channel_path_len, "/home/kyfaiyya/SISOP/FP/DiscorIT/%s", channel);

    if (mkdir(channel_path, 0700) < 0) {
        perror("Gagal membuat direktori channel");
        char response[] = "Gagal membuat direktori channel";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
        free(channel_path);
        return;
    }

    size_t admin_path_len = snprintf(NULL, 0, "%s/admin", channel_path) + 1;
    char *admin_path = (char *)malloc(admin_path_len);
    snprintf(admin_path, admin_path_len, "%s/admin", channel_path);

    if (mkdir(admin_path, 0700) < 0) {
        perror("Gagal membuat direktori admin");
        char response[] = "Gagal membuat direktori admin";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
        free(channel_path);
        free(admin_path);
        return;
    }

    size_t auth_path_len = snprintf(NULL, 0, "%s/auth.csv", admin_path) + 1;
    char *auth_path = (char *)malloc(auth_path_len);
    snprintf(auth_path, auth_path_len, "%s/auth.csv", admin_path);
    FILE *auth_file = fopen(auth_path, "w+");
    if (!auth_file) {
        perror("Gagal membuat file auth.csv");
        char response[] = "Gagal membuat file auth.csv";
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
        free(channel_path);
        free(admin_path);
        free(auth_path);
        return;
    }

    fprintf(auth_file, "%d,%s,ROOT\n", rand(), username);
    fclose(auth_file);

    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Channel %s berhasil dibuat", channel);
    if (write(client->socket, response, strlen(response)) < 0) {
        perror("Gagal mengirim respons ke client");
    }

    free(channel_path);
    free(admin_path);
    free(auth_path);
}

