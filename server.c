#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <crypt.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>
#include <stdbool.h>
#include <dirent.h>
#include <signal.h>

#define PORT 8080
#define BUF_SIZE 1024
#define MAX_CLIENTS 100
#define USER_FILE "/home/kyfaiyya/SISOP/FP/DiscorIT/users.csv"
#define DISCORIT_DIR "/home/kyfaiyya/SISOP/FP/DiscorIT"
#define CHANNEL_FILE "/home/kyfaiyya/SISOP/FP/DiscorIT/channels.csv"

#define MAX_USERS 100
//int logged_in_users[MAX_USERS] = {0};

typedef struct {
    int regular;
    int monitor;
} UserLoginStatus;

UserLoginStatus logged_in_users[MAX_USERS] = {0};

typedef struct {
    int logged_in;
    int user_id;
    char username[BUF_SIZE];
    char role[BUF_SIZE];
    int in_channel;
    char current_channel[BUF_SIZE];
    int in_room;
    char current_room[BUF_SIZE];
    int is_monitor;
} Session;

typedef struct {
    int logged_in;
} monitorSession;

typedef struct {
    int socket;
    bool is_monitor;
    bool logged_in;
    char username[BUF_SIZE];
} Client;

Client clients[MAX_CLIENTS] = {0};
int client_count = 0;

void *handle_client(void *arg);
char *bcrypt(const char *password);
void list_channels(int socket);
void create_channel(int socket, const char *username, int id, const char *channel_name, const char *key);
void edit_channel(int socket, const char *username, const char *channel_name, const char *new_channel_name);
void delete_channel(int socket, const char *channel_name);
void kick_user(int socket, const char *channel_name, const char *username);
void join_channel(int socket, const char *username, const char *channel, int id,const char *key);
void create_room(int socket, const char *username, const char *channel, const char *room);
void join_room(int socket, const char *username, const char *channel, const char *room);
void edit_room(int socket, const char *username, const char *channel, const char *room, const char *new_room);
void delete_room(int socket, const char *channel, const char *room, const char *username);
void delete_all_rooms(int socket, const char *channel, const char *username);
void list_rooms(int socket, const char *channel);
void list_users(int socket);
void list_channel_users(int socket, const char *channel);
void edit_user_name(int socket, const char *username, const char *new_username);
void edit_user_name_other(int socket, const char *username, const char *new_username);
void edit_user_password(int socket, const char *username, const char *new_password);
void remove_user(int socket, const char *username);
void ban_user(int socket, const char *channel, const char *username);
void unban_user(int socket, const char *channel, const char *username);
void chat(int socket, const char *channel, const char *room, const char *username, const char *message);
void edit_chat(int socket, const char *channel, const char *room, const char *username, int id_chat, const char *new_message);
void delete_chat(int socket, const char *channel, const char *room, int id_chat);
void see_chat(int socket, const char *channel, const char *room);
//void channel_room_info_for_monitor(int socket, const char *channel, const char *room);

/*void broadcast_message(const char *message) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != 0) {
            send(clients[i].socket, message, strlen(message), 0);
        }
    }
}*/

// Function to recursively delete a directory and its contents
int remove_directory(const char *path) {
    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;

    if (d) {
        struct dirent *p;
        r = 0;
        while (!r && (p = readdir(d))) {
            int r2 = -1;
            char *buf;
            size_t len;

            // Skip the names "." and ".." as we don't want to recurse on them
            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
                continue;

            len = path_len + strlen(p->d_name) + 2;
            buf = malloc(len);

            if (buf) {
                struct stat statbuf;
                snprintf(buf, len, "%s/%s", path, p->d_name);

                if (!stat(buf, &statbuf)) {
                    if (S_ISDIR(statbuf.st_mode))
                        r2 = remove_directory(buf);
                    else
                        r2 = unlink(buf);
                }
                free(buf);
            }
            r = r2;
        }
        closedir(d);
    }

    if (!r)
        r = rmdir(path);

    return r;
}


// Function to get the current timestamp in the required format
void get_timestamp(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, buffer_size, "[%d/%m/%Y %H:%M:%S]", t);
}

// Function to log a message to the user.log file in the admin folder
void log_action(const char *channel_name, const char *event) {
    char log_file_path[BUF_SIZE];
    snprintf(log_file_path, sizeof(log_file_path), "%s/%s/admin/user.log", DISCORIT_DIR, channel_name);
    FILE *log_file = fopen(log_file_path, "a");
    if (!log_file) {
        perror("fopen");
        return;
    }

    char timestamp[BUF_SIZE];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(log_file, "%s %s\n", timestamp, event);
    fclose(log_file);
}

void daemonize() {
    pid_t pid;

    // Fork the parent process
    //printf("Forking the process...\n");
    pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    // Terminate the parent process
    if (pid > 0) {
        //printf("Exiting parent process...\n");
        exit(EXIT_SUCCESS);
    }

    // On success: the child process becomes the session leader
    //printf("Setting session leader...\n");
    if (setsid() < 0) {
        perror("setsid failed");
        exit(EXIT_FAILURE);
    }

    // Ignore signal sent from child to parent process
    signal(SIGCHLD, SIG_IGN);

    // Fork off for the second time
    //printf("Forking again...\n");
    pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    // Terminate the parent process
    if (pid > 0) {
        //printf("Exiting parent process...\n");
        exit(EXIT_SUCCESS);
    }

    // Set new file permissions
    //printf("Setting file permissions...\n");
    umask(0);

    // Change the working directory to the root directory
    //printf("Changing working directory...\n");
    if (chdir("/") < 0) {
        perror("chdir failed");
        exit(EXIT_FAILURE);
    }

    // Close all open file descriptors
    //printf("Closing file descriptors...\n"); 
    // Close all open file descriptors
    //for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        //if (close(x) == -1) {
            //perror("Error closing file descriptor");
            //fprintf(stderr, "Failed to close file descriptor %d\n", x);
            // Add more specific handling if needed
        //}
    //}
    
    // Reopen standard file descriptors to /dev/null
    //printf("Redirecting standard file descriptors...\n");
    open("/dev/null", O_RDWR); // stdin
    dup(0); // stdout
    dup(0); // stderr

    //printf("Daemon setup complete.\n");
}

int main() {

    daemonize();

    //printf("Server is starting...\n");

    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    //printf("Socket created successfully\n"); // Debugging

    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEPORT) failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Attaching socket to the port 8080
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    //printf("Server is running on port %d\n", PORT);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, (void *)&new_socket);
    }

    return 0;
}

void send_to_monitor(const char *message) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != 0 && clients[i].is_monitor) {
            send(clients[i].socket, message, strlen(message), 0);
        }
    }
}

int find_monitor_client(const char *username) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != 0 && clients[i].is_monitor && strcmp(clients[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

void send_message_to_monitor(Session *session, const char *message) {
    int monitor_index = find_monitor_client(session->username);
    if (monitor_index != -1) {
        send(clients[monitor_index].socket, message, strlen(message), 0);
    }
}

void close_monitor_sessions() {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != 0 && clients[i].is_monitor) {
            close(clients[i].socket);
            clients[i].socket = 0;
            clients[i].is_monitor = false;
            client_count--;
        }
    }
}

bool is_logged_in(const char *username) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].logged_in && strcmp(clients[i].username, username) == 0) {
            return 1;
        }
    }

    return 0;
}

void *handle_client(void *arg) {
    int socket = *(int *)arg;
    char buffer[BUF_SIZE];
    int bytes_read;
    Session session = {0}; // Initialize session
    monitorSession monitor_session = {0}; // Initialize monitor session 
    int client_index = -1;

    // Add client to the list
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == 0) {
            clients[i].socket = socket;
            client_index = i;
            client_count++;
            break;
        }
    }

    //printf("Client connected\n"); // Debugging

    while ((bytes_read = read(socket, buffer, BUF_SIZE)) > 0) {
        buffer[bytes_read] = '\0';
        //printf("Received: %s\n", buffer);

        char command[BUF_SIZE], username[BUF_SIZE], password[BUF_SIZE];
        sscanf(buffer, "%s %s -p %s", command, username, password);

        if (strcmp(command, "REGISTER") == 0) {
            if (register_user(username, password)) {
                snprintf(buffer, sizeof(buffer), "%s berhasil register", username);
            } else {
                snprintf(buffer, sizeof(buffer), "%s sudah terdaftar", username);
            }
        } else if (strcmp(command, "LOGIN") == 0) {
            int login_result = login_user(username, password, &session, 0);
            if (login_result == -1) {
                snprintf(buffer, sizeof(buffer), "User sudah login sebagai regular user");
            } else if (login_result == 1) {
                snprintf(buffer, sizeof(buffer), "%s berhasil login", username);
                clients[client_index].logged_in = true;
                clients[client_index].is_monitor = false;
                strcpy(clients[client_index].username, username);
            } else {
                snprintf(buffer, sizeof(buffer), "Login gagal");
            }
        } else if (strcmp(command, "LOGIN_MONITOR") == 0) {
            int login_result = login_user(username, password, &session, 1);
            if (login_result == -1) {
                snprintf(buffer, sizeof(buffer), "User sudah login sebagai monitor");
            } else if (login_result == 1) {
                snprintf(buffer, sizeof(buffer), "%s berhasil login sebagai monitor", username);
                clients[client_index].is_monitor = true;
                clients[client_index].logged_in = true;  // Set this to true for monitors as well
                strcpy(clients[client_index].username, username);
                monitor_session.logged_in = 1;
            } else {
                snprintf(buffer, sizeof(buffer), "Login gagal");
            }
        } else if (session.logged_in) {
            // Process other commands only if logged in
            process_command(socket, &session, buffer, &monitor_session);
            memset(buffer, 0, sizeof(buffer));
        } else {
            snprintf(buffer, sizeof(buffer), "Anda harus login terlebih dahulu");
        }

        write(socket, buffer, strlen(buffer));
        memset(buffer, 0, sizeof(buffer));
    }

    //printf("Client disconnected\n"); // Debugging
    close(socket);

    // Remove client from the list
    if (clients[client_index].logged_in) {
        logout_user(&session);
    }
    clients[client_index].socket = 0;
    clients[client_index].is_monitor = false;
    clients[client_index].logged_in = false;
    strcpy(clients[client_index].username, "");
    client_count--;

    return NULL;
}

int register_user(const char *username, const char *password) {
    FILE *file = fopen(USER_FILE, "r");
    int max_id = 0;

    if (file) {
        char line[BUF_SIZE];
        while (fgets(line, sizeof(line), file)) {
            int id;
            char stored_username[BUF_SIZE];
            if (sscanf(line, "%d,%[^,]", &id, stored_username) == 2) {
                if (strcmp(stored_username, username) == 0) {
                    fclose(file);
                    return 0; // Username already exists
                }
                if (id > max_id) {
                    max_id = id;
                }
            }
        }
        fclose(file);
    }

    file = fopen(USER_FILE, "a");
    if (!file) {
        perror("fopen");
        return 0;
    }

    int new_id = max_id + 1;
    char *encrypted_password = bcrypt(password);
    fprintf(file, "%d,%s,%s,%s\n", new_id, username, encrypted_password, new_id == 1 ? "ROOT" : "USER");
    free(encrypted_password);
    fclose(file);
    return 1;
}

int login_user(const char *username, const char *password, Session *session, int is_monitor) {
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        perror("fopen");
        return 0;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_username[BUF_SIZE], stored_password[BUF_SIZE], role[BUF_SIZE];
        int num_fields = sscanf(line, "%d,%[^,],%[^,],%s", &id, stored_username, stored_password, role);

        if (num_fields < 4) {
            printf("Malformed line: %s\n", line);
            continue;
        }

        if (strcmp(stored_username, username) == 0) {
            if ((is_monitor && logged_in_users[id].monitor) || (!is_monitor && logged_in_users[id].regular)) {
                fclose(file);
                return -1; // User already logged in for this type of session
            }
            if (strcmp(crypt(password, stored_password), stored_password) == 0) {
                session->logged_in = 1;
                strncpy(session->username, username, BUF_SIZE);
                strncpy(session->role, role, BUF_SIZE);
                session->user_id = id;
                session->is_monitor = is_monitor;
                if (is_monitor) {
                    logged_in_users[id].monitor = 1;
                } else {
                    logged_in_users[id].regular = 1;
                }
                fclose(file);
                printf("User %s logged in %s\n", username, is_monitor ? "as monitor" : ""); // Debugging
                return 1;
            }
            break;
        }
    }

    fclose(file);
    return 0;
}

void logout_user(Session *session) {
    if (session->logged_in) {
        if (session->is_monitor) {
            logged_in_users[session->user_id].monitor = 0;
        } else {
            logged_in_users[session->user_id].regular = 0;
        }
        session->logged_in = 0;
        memset(session->username, 0, BUF_SIZE);
        memset(session->role, 0, BUF_SIZE);
        session->user_id = 0;
        session->is_monitor = 0;
    }
}

void logout_monitor(monitorSession *monitor_session) {
    if (monitor_session->logged_in) {
        monitor_session->logged_in = 0;
    }
}

int login_monitor(const char *username, const char *password, monitorSession *session) {
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        perror("fopen");
        return 0;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_username[BUF_SIZE], stored_password[BUF_SIZE], role[BUF_SIZE];
        int num_fields = sscanf(line, "%d,%[^,],%[^,],%s", &id, stored_username, stored_password, role);

        if (num_fields < 4) {
            printf("Malformed line: %s\n", line);
            continue;
        }

        if (strcmp(stored_username, username) == 0) {
            if (strcmp(crypt(password, stored_password), stored_password) == 0) {
                session->logged_in = 1;
                fclose(file);
                printf("User %s logged in as monitor\n", username); // Debugging
                return 1;
            }
            break;
        }
    }

    fclose(file);
    return 0;
}

bool is_admin(int socket, const char *channel_name, const char *username) {
    char admin_dir_path[BUF_SIZE];
    snprintf(admin_dir_path, sizeof(admin_dir_path), "%s/%s/admin", DISCORIT_DIR, channel_name);

    char auth_dir_path[BUF_SIZE];
    snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/auth.csv", admin_dir_path);

    FILE *auth_file = fopen(auth_dir_path, "r");
    if (!auth_file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), auth_file)) {
        int id;
        char stored_username[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, stored_username, role);
        if (strcmp(stored_username, username) == 0 && strcmp(role, "ADMIN") == 0) {
            fclose(auth_file);
            return 1;
        }
    }

    fclose(auth_file);
    return 0;
}

bool is_root(int socket, const char *username) {
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        perror("fopen");
        return false;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_username[BUF_SIZE], role[BUF_SIZE], password[BUF_SIZE];
        if (sscanf(line, "%d,%[^,],%[^,],%s", &id, stored_username, password, role) == 4) {
            if (strcmp(stored_username, username) == 0 && strcmp(role, "ROOT") == 0) {
                fclose(file);
                return true;
            }
        }
    }

    fclose(file);
    return false;
}

bool is_member(int socket, const char *channel_name, const char *username) {
    char auth_dir_path[BUF_SIZE];
    snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, channel_name);

    FILE *auth_file = fopen(auth_dir_path, "r");
    if (!auth_file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), auth_file)) {
        int id;
        char stored_username[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, stored_username, role);
        if (strcmp(stored_username, username) == 0) {
            fclose(auth_file);
            return 1;
        }
    }

    fclose(auth_file);
    return 0;
}

bool validate_key(int socket, const char *channel_name, const char *key) {
    FILE *file = fopen(CHANNEL_FILE, "r");
    if (!file) {
        perror("fopen");
        return false;  // Changed from 'return;' to 'return false;'
    }

    // Trim newline from key if present
    char trimmed_key[BUF_SIZE];
    strncpy(trimmed_key, key, BUF_SIZE - 1);
    trimmed_key[BUF_SIZE - 1] = '\0';  // Ensure null-termination
    char *newline = strchr(trimmed_key, '\n');
    if (newline) *newline = '\0';

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char stored_channel[BUF_SIZE], stored_key[BUF_SIZE];
        sscanf(line, "%*d,%[^,],%s", stored_channel, stored_key);
        if (strcmp(stored_channel, channel_name) == 0 && strcmp(crypt(trimmed_key, stored_key), stored_key) == 0) {
            fclose(file);
            return true;
        }
    }

    fclose(file);
    return false;
}

bool channel_exists(int socket, const char *channel_name) {
    FILE *file = fopen(CHANNEL_FILE, "r");
    if (!file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char stored_channel[BUF_SIZE];
        sscanf(line, "%*d,%[^,],%*s", stored_channel);
        if (strcmp(stored_channel, channel_name) == 0) {
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

bool room_exists(int socket, const char *channel_name, const char *room_name) {
    char room_dir_path[BUF_SIZE];
    snprintf(room_dir_path, sizeof(room_dir_path), "%s/%s/%s", DISCORIT_DIR, channel_name, room_name);

    struct stat st;
    if (stat(room_dir_path, &st) == 0) {
        return 1;
    }

    return 0;
}

bool is_banned(int socket, const char *channel_name, const char *username) {
    char auth_dir_path[BUF_SIZE];
    snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, channel_name);

    FILE *auth_file = fopen(auth_dir_path, "r");
    if (!auth_file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), auth_file)) {
        int id;
        char stored_username[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, stored_username, role);
        if (strcmp(stored_username, username) == 0 && strcmp(role, "BANNED") == 0) {
            fclose(auth_file);
            return 1;
        }
    }

    fclose(auth_file);
    return 0;
}

bool username_taken(int socket, const char *username) {
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char stored_username[BUF_SIZE];
        sscanf(line, "%*d,%[^,]", stored_username);
        if (strcmp(stored_username, username) == 0) {
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

bool my_message(int socket, const char *channel_name, const char *room_name, const char *username, int id_chat) {
    char chat_dir_path[BUF_SIZE];
    snprintf(chat_dir_path, sizeof(chat_dir_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, channel_name, room_name);

    FILE *chat_file = fopen(chat_dir_path, "r");
    if (!chat_file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), chat_file)) {
        int id;
        char sender[BUF_SIZE], message[BUF_SIZE], timestamp[BUF_SIZE];
        sscanf(line, "%d,%[^,],%[^,],%[^\n]", &id, timestamp, sender, message);
        if (id == id_chat && strcmp(sender, username) == 0) {
            fclose(chat_file);
            return 1;
        }
    }

    fclose(chat_file);
    return 0;
}

void process_command(int socket, Session *session, char *buffer, monitorSession *monitor_session) {
    char command[BUF_SIZE], arg1[BUF_SIZE], arg2[BUF_SIZE], arg3[BUF_SIZE], key[BUF_SIZE], 
    channel_name[BUF_SIZE], new_channel_name[BUF_SIZE], room_name[BUF_SIZE], new_room_name[BUF_SIZE], 
    message[BUF_SIZE], new_username[BUF_SIZE], new_password[BUF_SIZE], target_username[BUF_SIZE], username[BUF_SIZE];
    int id_chat;

    if (strstr(buffer, "LIST CHANNEL") != NULL) {
        list_channels(socket);
    } else if (sscanf(buffer, "CREATE CHANNEL %s -k %s", channel_name, key) == 2) {
        create_channel(socket, session->username, session->user_id, channel_name, key);
    } else if (sscanf(buffer, "EDIT CHANNEL %s TO %s", channel_name, new_channel_name) == 2) {
        if(is_admin(socket, channel_name, session->username) || is_root(socket, session->username)) {
            edit_channel(socket, session->username, channel_name, new_channel_name);
            strcpy(session->current_channel, new_channel_name);
        } else {
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
    } else if (sscanf(buffer, "DEL CHANNEL %s", channel_name) == 1) {
        if(is_admin(socket, channel_name, session->username) || is_root(socket, session->username)) {
            if(session->in_channel && strcmp(session->current_channel, channel_name) == 0) {
                write(socket, "Anda sedang berada di channel ini", strlen("Anda sedang berada di channel ini"));
            } else {
                delete_channel(socket, channel_name);
            }
        } else {
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
    } else if (sscanf(buffer, "JOIN %s", channel_name) == 1) {
        if(session->in_channel){
            strcpy(room_name, channel_name);
            if(room_exists(socket, session->current_channel, room_name) && (strcmp(room_name, "admin") != 0)){
                if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username) || is_member(socket, session->current_channel, session->username)){
                    join_room(socket, session->username, session->current_channel, room_name);
                    session->in_room = 1;
                    strcpy(session->current_room, room_name);
                }else{
                    write(socket, "Akses ditolak", strlen("Akses ditolak"));
                }
            } else {
                write(socket, "Room tidak ditemukan", strlen("Room tidak ditemukan"));
            }
        }else{
            if(channel_exists(socket, channel_name)){
                if(is_banned(socket, channel_name, session->username)){
                    write(socket, "Anda dibanned dari channel ini", strlen("Anda dibanned dari channel ini"));
                }else{
                    if(is_member(socket, channel_name, session->username) || is_root(socket, session->username) || is_admin(socket, channel_name, session->username)){
                        join_channel(socket, session->username, channel_name, session->user_id,NULL);
                        session->in_channel = 1;
                        strcpy(session->current_channel, channel_name);
                    } else {
                        char key[BUF_SIZE];
                        write(socket, "Key: ", strlen("Key: "));
                        ssize_t bytes_read = read(socket, key, BUF_SIZE - 1);
                        if (bytes_read > 0) {
                            key[bytes_read] = '\0';  // Null-terminate the string
                            // Remove newline if present
                            char *newline = strchr(key, '\n');
                            if (newline) *newline = '\0';

                            if (validate_key(socket, channel_name, key)) {
                                join_channel(socket, session->username, channel_name, session->user_id, key);
                                session->in_channel = 1;
                                strcpy(session->current_channel, channel_name);
                            } else {
                                write(socket, "Key salah\n", strlen("Key salah\n"));
                            }
                        } else {
                            write(socket, "Error reading key\n", strlen("Error reading key\n"));
                        }
                    }
                }
            } else {
                write(socket, "Channel tidak ditemukan", strlen("Channel tidak ditemukan"));
            }
        }
    } else if (sscanf(buffer, "CREATE ROOM %s", room_name) == 1){
        if(session->in_channel){
            if (is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                create_room(socket, session->username, session->current_channel, room_name);
            }else{
                write(socket, "Akses ditolak", strlen("Akses ditolak"));
            }
        }else{
            write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
        }
    } else if (strcmp(buffer, "LIST ROOM") == 0) {
        if(session->in_channel){
            list_rooms(socket, session->current_channel);
        }else{
            write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
        }
    } else if (sscanf(buffer, "EDIT ROOM %s TO %s", room_name, new_room_name) == 2) {
        if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
            if(session->in_channel){
                if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                    edit_room(socket, session->username, session->current_channel, room_name, new_room_name);
                    strcpy(session->current_room, new_room_name);
                }else{
                    write(socket, "Akses ditolak", strlen("Akses ditolak"));
                }
            }else{
                write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
            }
        }else{
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
    } else if (sscanf(buffer, "DEL ROOM %s", room_name) == 1) {
        if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
            if(session->in_channel){
                if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                    if(strcmp(room_name, "ALL") == 0){
                        delete_all_rooms(socket, session->current_channel, session->username);
                    }else{
                        if(session->in_room && strcmp(session->current_room, room_name) == 0){
                            write(socket, "Anda sedang berada di room ini", strlen("Anda sedang berada di room ini"));
                        }else{
                            delete_room(socket, session->current_channel, room_name, session->username);
                        }
                    }
                }else{
                    write(socket, "Akses ditolak", strlen("Akses ditolak"));
                }
            }else{
                write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
            }
        }else{
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
    } else if (strcmp(buffer, "LIST USER") == 0){
        if(session->in_channel){
            if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                list_channel_users(socket, session->current_channel);
            }else{
                write(socket, "Akses ditolak", strlen("Akses ditolak"));
            }
        }else{
            if(is_root(socket, session->username)){
                list_users(socket);
            }else{
                write(socket, "Akses ditolak", strlen("Akses ditolak"));
            }
        }
    } else if (sscanf(buffer, "EDIT PROFILE SELF -u %s", new_username) == 1) {
        if(username_taken(socket, new_username)){
            write(socket, "Username sudah terdaftar", strlen("Username sudah terdaftar"));
        }else{
            edit_user_name(socket, session->username, new_username);
            strcpy(session->username, new_username);
        }
    } else if (sscanf(buffer, "EDIT PROFILE SELF -p %s", new_password) == 1) {
        edit_user_password(socket, session->username, new_password);
    } else if (sscanf(buffer, "EDIT WHERE %s -u %s", username, new_username) == 2) {
        if(is_root(socket, session->username)){
            if(username_taken(socket, new_username)){
                write(socket, "Username sudah terdaftar", strlen("Username sudah terdaftar"));
            }else{
                if(strcmp(username, session->username) == 0){
                    edit_user_name(socket, username, new_username);
                    strcpy(session->username, new_username);
                }else{
                    edit_user_name_other(socket, username, new_username);
                }
            }
        }else{
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
    } else if (sscanf(buffer, "EDIT WHERE %s -p %s", username, new_password) == 2) {
        if(is_root(socket, session->username)){
            edit_user_password(socket, username, new_password);
        }else{
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
    } else if (sscanf(buffer, "REMOVE USER %s", username) == 1) {
        if (session->in_channel) {
            if (is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)) {
                if (is_member(socket, session->current_channel, username)) {
                    kick_user(socket, session->current_channel, username);
                } else {
                    write(socket, "User tidak ditemukan", strlen("User tidak ditemukan"));
                }
            } else {
                write(socket, "Akses ditolak", strlen("Akses ditolak"));
            }
        } else {
            write(socket, "Anda tidak berada dalam channel", strlen("Anda tidak berada dalam channel"));
        }
    } else if (sscanf(buffer, "REMOVE %s", username) == 1) {
        if (is_root(socket, session->username)) {
            if (is_root(socket, username)) {
                write(socket, "Tidak bisa hapus root", strlen("Tidak bisa hapus root"));
            } else {
                remove_user(socket, username);
            }
        } else {
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
    } else if (sscanf(buffer, "BAN %s", target_username) == 1){
        if(session->in_channel){
            if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                if(is_member(socket, session->current_channel, target_username)){
                    if(is_banned(socket, session->current_channel, target_username)){
                        write(socket, "User sudah dibanned", strlen("User sudah dibanned"));
                    }else if(is_admin(socket, session->current_channel, target_username)){
                        write(socket, "Tidak bisa ban admin", strlen("Tidak bisa ban admin"));
                    }else if(is_root(socket, target_username)){
                        write(socket, "Tidak bisa ban root", strlen("Tidak bisa ban root"));
                    }else if(strcmp(target_username, session->username) == 0){
                        write(socket, "Tidak bisa ban diri sendiri", strlen("Tidak bisa ban diri sendiri"));
                    }else{
                        ban_user(socket, session->current_channel, target_username);
                    }
                }else{
                    write(socket, "User tidak ditemukan", strlen("User tidak ditemukan"));
                }
            }else{
                write(socket, "Akses ditolak", strlen("Akses ditolak"));
            }
        }else{
            write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
        }
    } else if (sscanf(buffer, "UNBAN %s", target_username) == 1){
        if(session->in_channel){
            if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                if(is_member(socket, session->current_channel, target_username)){
                    if(is_banned(socket, session->current_channel, target_username)){
                        unban_user(socket, session->current_channel, target_username);
                    }else{
                        write(socket, "User tidak dibanned", strlen("User tidak dibanned"));
                    }
                }else{
                    write(socket, "User tidak ditemukan", strlen("User tidak ditemukan"));
                }
            }else{
                write(socket, "Akses ditolak", strlen("Akses ditolak"));
            }
        }else{
            write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
        }
    } else if (strncmp(buffer, "CHAT ", 5) == 0) {
        char *message_start = buffer + 5;  // Skip "CHAT " (5 characters)
        size_t message_length = strlen(message_start);
        
        if (message_length >= 2 && message_start[0] == '"' && message_start[message_length - 1] == '"') {
            // Extract message within quotes
            message_start++;  // Skip opening quote
            message_length -= 2;  // Remove both quotes from length
            
            size_t max_length = sizeof(message) - 1;  // Assume 'message' is an array
            strncpy(message, message_start, message_length < max_length ? message_length : max_length);
            message[message_length < max_length ? message_length : max_length] = '\0';  // Ensure null-termination
            
            if(session->in_channel){
                if(session->in_room){
                    chat(socket, session->current_channel, session->current_room, session->username, message);
                }else{
                    write(socket, "Anda belum bergabung ke room", strlen("Anda belum bergabung ke room"));
                }
            }else{
                write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
            }
        } else {
            write(socket, "Format pesan tidak valid. Pesan harus diawali dan diakhiri dengan tanda kutip ganda (\").", 
                strlen("Format pesan tidak valid. Pesan harus diawali dan diakhiri dengan tanda kutip ganda (\")."));
        }
    } else if (sscanf(buffer, "EDIT CHAT %d \"%[^\"]\"", &id_chat, message) == 2) {
        if(session->in_channel){
            if(session->in_room){
                if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                    edit_chat(socket, session->current_channel, session->current_room, session->username, id_chat, message);
                }else{
                    if(my_message(socket, session->current_channel, session->current_room, session->username, id_chat)){
                        edit_chat(socket, session->current_channel, session->current_room, session->username, id_chat, message);
                    }else{
                        write(socket, "Anda tidak bisa edit chat orang lain", strlen("Anda tidak bisa edit chat orang lain"));
                    }
                }
            }else{
                write(socket, "Anda belum bergabung ke room", strlen("Anda belum bergabung ke room"));
            }
        }else{
            write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
        }
    } else if (sscanf(buffer, "DEL CHAT %d", &id_chat) == 1) {
        if(session->in_channel){
            if(session->in_room){
                if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                    delete_chat(socket, session->current_channel, session->current_room, id_chat);
                }else{
                    if(my_message(socket, session->current_channel, session->current_room, session->username, id_chat)){
                        delete_chat(socket, session->current_channel, session->current_room, id_chat);
                    }else{
                        write(socket, "Anda tidak bisa hapus chat orang lain", strlen("Anda tidak bisa hapus chat orang lain"));
                    }
                }
            }else{
                write(socket, "Anda belum bergabung ke room", strlen("Anda belum bergabung ke room"));
            }
        }else{
            write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
        }
    } else if (strcmp(buffer, "SEE CHAT") == 0) {
        if(session->in_channel){
            if(session->in_room){
                see_chat(socket, session->current_channel, session->current_room);
            }else{
                write(socket, "Anda belum bergabung ke room", strlen("Anda belum bergabung ke room"));
            }
        }else{
            write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
        }
    } else if (sscanf(buffer, "-channel %s -room %s", channel_name, room_name) == 2) {
        //write(socket, "%d", monitor_session->logged_in);
        if(!monitor_session->logged_in){
            if (channel_exists(socket, channel_name)) {
                if (room_exists(socket, channel_name, room_name)) {
                    if(is_member(socket, channel_name, session->username) || is_root(socket, session->username) || is_admin(socket, channel_name, session->username)){
                        send_message_to_monitor(session, buffer);
                    } else {
                        write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
                    }
                    write(socket, "Pesan terkirim", strlen("Pesan terkirim"));
                } else {
                    write(socket, "Room tidak ditemukan", strlen("Room tidak ditemukan"));
                }
            } else {
                write(socket, "Channel tidak ditemukan", strlen("Channel tidak ditemukan"));
            }
        } else {
            write(socket, "Monitor harus login terlebih dahulu", strlen("Monitor harus login terlebih dahulu"));
        }
    } else if (strcmp(buffer, "EXIT") == 0) {
        if (session->in_room) {
            char line[BUF_SIZE];
            sprintf(line, "%s keluar dari room %s", session->username, session->current_room);
            log_action(session->current_channel, line);
            write(socket, "Keluar Room", strlen("Keluar Room"));
            session->in_room = 0;
            memset(session->current_room, 0, sizeof(session->current_room));
        } else if (session->in_channel) {
            char line[BUF_SIZE];
            sprintf(line, "%s keluar dari channel %s", session->username, session->current_channel);
            log_action(session->current_channel, line);
            write(socket, "Keluar Channel", strlen("Keluar Channel"));
            session->in_channel = 0;
            memset(session->current_channel, 0, sizeof(session->current_channel));
        } else {
            send_message_to_monitor(session, buffer);
            logout_user(session);
            close(socket);
            pthread_exit(0);
        }
    } else {
        write(socket, "Perintah tidak valid", strlen("Perintah tidak valid"));
    }
}

char *bcrypt(const char *password) {
    char salt[] = "$2b$12$XXXXXXXXXXXXXXXXXXXXXX"; // Generate a random salt
    char *encrypted_password = crypt(password, salt);
    return strdup(encrypted_password);
}

void list_users(int socket) {
    FILE *file = fopen(USER_FILE, "r");
    char line[BUF_SIZE];
    char response[BUF_SIZE] = "Users: ";
    if (!file) {
        perror("fopen");
        return;
    }
    while (fgets(line, sizeof(line), file)) {
        int id;
        char username[BUF_SIZE];
        sscanf(line, "%d,%[^,]", &id, username);
        char user_info[BUF_SIZE];
        snprintf(user_info, sizeof(user_info), "[%d]%s ", id, username);
        strcat(response, user_info);
    }
    fclose(file);
    write(socket, response, strlen(response));
}

void list_channel_users(int socket, const char *channel_name) {
    char auth_file_path[BUF_SIZE];
    snprintf(auth_file_path, sizeof(auth_file_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, channel_name);

    FILE *auth_file = fopen(auth_file_path, "r");
    if (!auth_file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    char response[BUF_SIZE] = "Users: ";
    while (fgets(line, sizeof(line), auth_file)) {
        int id;
        char username[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, username, role);
        char user_info[BUF_SIZE];
        snprintf(user_info, sizeof(user_info), "%s ", username);
        strcat(response, user_info);
    }
    fclose(auth_file);
    write(socket, response, strlen(response));
}

void update_channel_auth_files(const char *old_username, const char *new_username) {
    DIR *dir = opendir(DISCORIT_DIR);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char auth_file_path[BUF_SIZE];
            snprintf(auth_file_path, sizeof(auth_file_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, entry->d_name);

            FILE *auth_file = fopen(auth_file_path, "r");
            FILE *temp_file = fopen("temp_auth.csv", "w");

            if (!auth_file || !temp_file) {
                perror("Unable to open auth file or create temp file");
                if (auth_file) fclose(auth_file);
                if (temp_file) fclose(temp_file);
                continue;
            }

            char line[BUF_SIZE];
            while (fgets(line, sizeof(line), auth_file)) {
                int id;
                char username[BUF_SIZE], role[BUF_SIZE];
                sscanf(line, "%d,%[^,],%s", &id, username, role);
                if (strcmp(username, old_username) == 0) {
                    fprintf(temp_file, "%d,%s,%s\n", id, new_username, role);
                } else {
                    fputs(line, temp_file);
                }
            }

            fclose(auth_file);
            fclose(temp_file);

            remove(auth_file_path);
            rename("temp_auth.csv", auth_file_path);

            char log_message[BUF_SIZE];
            snprintf(log_message, sizeof(log_message), "Nama user %s berubah menjadi %s", old_username, new_username);
            log_action(entry->d_name, log_message);
        }
    }
}

void edit_user_name(int socket, const char *username, const char *new_username) {
    FILE *file = fopen(USER_FILE, "r");
    FILE *temp = fopen("temp.csv", "w");
    if (!file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_username[BUF_SIZE], password[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%[^,],%s", &id, stored_username, password, role);
        if (strcmp(stored_username, username) == 0) {
            fprintf(temp, "%d,%s,%s,%s\n", id, new_username, password, role);
            found = 1;
        } else {
            fputs(line, temp);
        }
    }

    fclose(file);
    fclose(temp);

    char new_name[BUF_SIZE];

    if (found) {
        remove(USER_FILE);
        rename("temp.csv", USER_FILE);
        snprintf(line, sizeof(line), "%s berhasil diubah menjadi %s", username, new_username);
        //snprintf(new_name, sizeof(new_name), "%s", new_username);

        update_channel_auth_files(username, new_username);
    } else {
        remove("temp.csv");
        snprintf(line, sizeof(line), "User %s not found", username);
    }

    write(socket, line, strlen(line));
}

void edit_user_name_other(int socket, const char *username, const const char *new_username) {
    FILE *file = fopen(USER_FILE, "r");
    FILE *temp = fopen("temp.csv", "w");
    if (!file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_username[BUF_SIZE], stored_password[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%[^,],%s", &id, stored_username, stored_password, role);
        if (strcmp(stored_username, username) == 0) {
            fprintf(temp, "%d,%s,%s,%s\n", id, new_username, stored_password, role);
            found = 1;
        } else {
            fputs(line, temp);
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove(USER_FILE);
        rename("temp.csv", USER_FILE);
        snprintf(line, sizeof(line), "Root merubah nama user %s menjadi %s", username, new_username);
        update_channel_auth_files(username, new_username);
    } else {
        remove("temp.csv");
        snprintf(line, sizeof(line), "User %s not found", username);
    }

    write(socket, line, strlen(line));
}

void edit_user_password(int socket, const char *username, const char *new_password) {
    FILE *file = fopen(USER_FILE, "r");
    FILE *temp = fopen("temp.csv", "w");
    if (!file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_username[BUF_SIZE], stored_password[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%[^,],%s", &id, stored_username, stored_password, role);
        if (strcmp(stored_username, username) == 0) {
            char *encrypted_password = bcrypt(new_password);
            fprintf(temp, "%d,%s,%s,%s\n", id, stored_username, encrypted_password, role);
            free(encrypted_password);
            found = 1;
        } else {
            fputs(line, temp);
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove(USER_FILE);
        rename("temp.csv", USER_FILE);
        snprintf(line, sizeof(line), "password user %s berhasil diubah", username);
    } else {
        remove("temp.csv");
        snprintf(line, sizeof(line), "User %s not found", username);
    }

    write(socket, line, strlen(line));
}

void remove_user_from_channel_auth(const char *username) {
    DIR *dir = opendir(DISCORIT_DIR);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char auth_file_path[BUF_SIZE];
            snprintf(auth_file_path, sizeof(auth_file_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, entry->d_name);

            FILE *auth_file = fopen(auth_file_path, "r");
            FILE *temp_file = fopen("temp_auth.csv", "w");

            if (!auth_file || !temp_file) {
                perror("Unable to open auth file or create temp file");
                if (auth_file) fclose(auth_file);
                if (temp_file) fclose(temp_file);
                continue;
            }

            char line[BUF_SIZE];
            while (fgets(line, sizeof(line), auth_file)) {
                int id;
                char stored_username[BUF_SIZE], role[BUF_SIZE];
                sscanf(line, "%d,%[^,],%s", &id, stored_username, role);
                if (strcmp(stored_username, username) != 0) {
                    fputs(line, temp_file);
                }
            }

            fclose(auth_file);
            fclose(temp_file);

            remove(auth_file_path);
            rename("temp_auth.csv", auth_file_path);

            char log_message[BUF_SIZE];
            snprintf(log_message, sizeof(log_message), "Root menghapus user %s dari channel", username);
            log_action(entry->d_name, log_message);
        }
    }
}
void remove_user(int socket, const char *username) {
    FILE *file = fopen(USER_FILE, "r");
    FILE *temp = fopen("temp.csv", "w");
    if (!file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_username[BUF_SIZE], stored_password[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%[^,],%s", &id, stored_username, stored_password, role);
        if (strcmp(stored_username, username) == 0) {
            found = 1;
        } else {
            fputs(line, temp);
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove(USER_FILE);
        rename("temp.csv", USER_FILE);
        snprintf(line, sizeof(line), "User %s berhasil dihapus", username);
        remove_user_from_channel_auth(username);
    } else {
        remove("temp.csv");
        snprintf(line, sizeof(line), "User %s not found", username);
    }

    write(socket, line, strlen(line));
}

void ban_user(int socket, const char *channel, const char *username) {
    char auth_dir_path[BUF_SIZE];
    snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, channel);

    FILE *auth_file = fopen(auth_dir_path, "r");
    FILE *temp = fopen("temp.csv", "w");

    if (!auth_file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), auth_file)) {
        int id;
        char stored_username[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, stored_username, role);
        if (strcmp(stored_username, username) == 0) {
            fprintf(temp, "%d,%s,BANNED\n", id, stored_username);
            found = 1;
        } else {
            fputs(line, temp);
        }
    }

    fclose(auth_file);
    fclose(temp);

    if (found) {
        remove(auth_dir_path);
        rename("temp.csv", auth_dir_path);
        snprintf(line, sizeof(line), "User %s dibanned dari channel %s", username, channel);
    } else {
        remove("temp.csv");
        snprintf(line, sizeof(line), "User %s not found", username);
    }

    write(socket, line, strlen(line));

    char log_message[BUF_SIZE];
    snprintf(log_message, sizeof(log_message), "User %s dibanned", username);
    log_action(channel, log_message);
}

void unban_user(int socket, const char *channel, const char *username) {
    char auth_dir_path[BUF_SIZE];
    snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, channel);

    FILE *auth_file = fopen(auth_dir_path, "r");
    FILE *temp = fopen("temp.csv", "w");

    if (!auth_file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), auth_file)) {
        int id;
        char stored_username[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, stored_username, role);
        if (strcmp(stored_username, username) == 0) {
            fprintf(temp, "%d,%s,USER\n", id, stored_username);
            found = 1;
        } else {
            fputs(line, temp);
        }
    }

    fclose(auth_file);
    fclose(temp);

    if (found) {
        remove(auth_dir_path);
        rename("temp.csv", auth_dir_path);
        snprintf(line, sizeof(line), "User %s unbanned", username);
    } else {
        remove("temp.csv");
        snprintf(line, sizeof(line), "User %s not found", username);
    }

    write(socket, line, strlen(line));

    char log_message[BUF_SIZE];
    snprintf(log_message, sizeof(log_message), "User %s diunbanned", username);
    log_action(channel, log_message);
}

void create_channel(int socket, const char *username, int user_id, const char *channel_name, const char *key) {
    FILE *file = fopen(CHANNEL_FILE, "r");
    int max_id = 0;

    if (file) {
        char line[BUF_SIZE];
        while (fgets(line, sizeof(line), file)) {
            int id;
            char stored_channel[BUF_SIZE];
            if (sscanf(line, "%d,%[^,]", &id, stored_channel) == 2) {
                if (strcmp(stored_channel, channel_name) == 0) {
                    fclose(file);
                    write(socket, "Channel already exists", strlen("Channel already exists"));
                    return;
                }
                if (id > max_id) {
                    max_id = id;
                }
            }
        }
        fclose(file);
    }

    file = fopen(CHANNEL_FILE, "a");
    if (!file) {
        perror("fopen");
        return;
    }

    int new_id = max_id + 1;
    char *encrypted_key = bcrypt(key);
    fprintf(file, "%d,%s,%s\n", new_id, channel_name, encrypted_key);
    free(encrypted_key);
    fclose(file);

    char channel_dir_path[BUF_SIZE];
    snprintf(channel_dir_path, sizeof(channel_dir_path), "%s/%s", DISCORIT_DIR, channel_name);

    if (mkdir(channel_dir_path, 0777) == -1) {
        perror("mkdir");
        write(socket, "Failed to create channel directory", strlen("Failed to create channel directory"));
        return;
    }

    char admin_dir_path[BUF_SIZE];
    snprintf(admin_dir_path, sizeof(admin_dir_path), "%s/%s/admin", DISCORIT_DIR, channel_name);

    if (mkdir(admin_dir_path, 0777) == -1) {
        perror("mkdir");
        write(socket, "Failed to create admin directory", strlen("Failed to create admin directory"));
        return;
    }

    char auth_dir_path[BUF_SIZE];
    snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/auth.csv", admin_dir_path);
    FILE *auth_file = fopen(auth_dir_path, "w");
    if (!auth_file) {
        perror("fopen");
        return;
    }

    if(is_root(socket, username)){
        fprintf(auth_file, "%d,%s,ROOT\n", user_id, username);
    } else {
        fprintf(auth_file, "%d,%s,ADMIN\n", user_id, username);
    }

    fclose(auth_file);

    // Log the channel creation
    char log_action_msg[BUF_SIZE];
    snprintf(log_action_msg, sizeof(log_action_msg), "%s buat %s", username, channel_name);
    log_action(channel_name, log_action_msg);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "Channel %s dibuat", channel_name);
    write(socket, response, strlen(response));
}

void edit_channel(int socket, const char *username, const char *channel_name, const char *new_channel_name) {
    FILE *file = fopen(CHANNEL_FILE, "r");
    FILE *temp = fopen("temp.csv", "w");
    if (!file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_channel[BUF_SIZE], key[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, stored_channel, key);
        if (strcmp(stored_channel, channel_name) == 0) {
            fprintf(temp, "%d,%s,%s\n", id, new_channel_name, key);
            found = 1;
        } else {
            fputs(line, temp);
        }
    }

    fclose(file);
    fclose(temp);

    char log_action_msg[BUF_SIZE];

    if (found) {
        remove(CHANNEL_FILE);
        rename("temp.csv", CHANNEL_FILE);

        // Rename the channel folder
        char old_channel_dir[BUF_SIZE], new_channel_dir[BUF_SIZE];
        snprintf(old_channel_dir, sizeof(old_channel_dir), "%s/%s", DISCORIT_DIR, channel_name);
        snprintf(new_channel_dir, sizeof(new_channel_dir), "%s/%s", DISCORIT_DIR, new_channel_name);

        if (rename(old_channel_dir, new_channel_dir) == -1) {
            perror("rename");
            snprintf(line, sizeof(line), "Failed to rename channel directory from %s to %s", channel_name, new_channel_name);
        } else {
            snprintf(line, sizeof(line), "%s nama channel berubah menjadi %s", channel_name, new_channel_name);
            snprintf(log_action_msg, sizeof(log_action_msg), "%s merubah %s menjadi %s", username, channel_name, new_channel_name);
            log_action(new_channel_name, log_action_msg);
        }
    } else {
        remove("temp.csv");
        snprintf(line, sizeof(line), "Channel %s not found", channel_name);
    }

    write(socket, line, strlen(line));
}

void delete_channel(int socket, const char *channel_name) {
    FILE *file = fopen(CHANNEL_FILE, "r");
    FILE *temp = fopen("temp.csv", "w");
    if (!file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        char stored_channel[BUF_SIZE];
        sscanf(line, "%*d,%[^,],%*s", stored_channel);  // Correctly parse channel name
        if (strcmp(stored_channel, channel_name) != 0) {
            fputs(line, temp);
        } else {
            found = 1;
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove(CHANNEL_FILE);
        rename("temp.csv", CHANNEL_FILE);

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "%s berhasil dihapus", channel_name);
        write(socket, response, strlen(response));

        // Delete the channel directory
        char channel_dir_path[BUF_SIZE];
        snprintf(channel_dir_path, sizeof(channel_dir_path), "%s/%s", DISCORIT_DIR, channel_name);

        int delete_result = remove_directory(channel_dir_path);
        if (delete_result == -1) {
            perror("remove_directory");
        }

    } else {
        remove("temp.csv");

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "Channel %s tidak ditemukan", channel_name);
        write(socket, response, strlen(response));
    }
}

void join_channel(int socket, const char *username, const char *channel, int id,const char *key) {
    
    if (is_member(socket, channel, username)){
        char line[BUF_SIZE];
        sprintf(line, "%s masuk ke channel %s", username, channel);
        log_action(channel, line);

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "%s bergabung dengan channel %s", username, channel);
        write(socket, response, strlen(response));

        //const char* channel_msg = "CHANNEL_NAME";
        //write(socket, channel_msg, strlen(channel_msg));
        //write(socket, channel, strlen(channel));
    }else{

        char auth_dir_path[BUF_SIZE];
        snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, channel);

        FILE *auth_file = fopen(auth_dir_path, "a");
        if (!auth_file) {
            perror("fopen");
            return;
        }

        if(is_root(socket, username)){
            fprintf(auth_file, "%d,%s,ROOT\n", id, username);
        } else {
            fprintf(auth_file, "%d,%s,USER\n", id, username);
        }

        fclose(auth_file);

        char line[BUF_SIZE];

        sprintf(line, "%s masuk ke channel %s", username, channel);
        log_action(channel, line);

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "%s bergabung dengan channel %s", username, channel);
        write(socket, response, strlen(response));

        const char* channel_msg = "CHANNEL_NAME";
        //write(socket, channel_msg, strlen(channel_msg));
        //write(socket, channel, strlen(channel));
    }
}

void kick_user(int socket, const char *channel, const char *username) {
    char auth_dir_path[BUF_SIZE];
    snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, channel);

    FILE *auth_file = fopen(auth_dir_path, "r");
    FILE *temp = fopen("temp.csv", "w");

    if (!auth_file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), auth_file)) {
        int id;
        char stored_username[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, stored_username, role);
        if (strcmp(stored_username, username) == 0) {
            found = 1;
        } else {
            fputs(line, temp);
        }
    }

    fclose(auth_file);
    fclose(temp);

    if (found) {
        remove(auth_dir_path);
        rename("temp.csv", auth_dir_path);
        snprintf(line, sizeof(line), "User %s berhasil dikeluarkan dari channel %s", username, channel);
    } else {
        remove("temp.csv");
        snprintf(line, sizeof(line), "User %s not found", username);
    }

    write(socket, line, strlen(line));

    char log_message[BUF_SIZE];
    snprintf(log_message, sizeof(log_message), "User %s dikeluarkan dari channel", username);
    log_action(channel, log_message);
}

void list_channels(int socket) {
   DIR *dir = opendir(DISCORIT_DIR);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    char response[BUF_SIZE] = "Channels: ";
    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            strcat(response, entry->d_name);
            strcat(response, " ");
        }
    }

    closedir(dir);
    write(socket, response, strlen(response));
}

void create_room(int socket, const char *username, const char *channel, const char *room){
    char room_dir_path[BUF_SIZE];
    snprintf(room_dir_path, sizeof(room_dir_path), "%s/%s/%s", DISCORIT_DIR, channel, room);

    if (mkdir(room_dir_path, 0777) == -1) {
        perror("mkdir");
        write(socket, "Failed to create room directory", strlen("Failed to create room directory"));
        return;
    }

    char chat_file_path[BUF_SIZE];
    snprintf(chat_file_path, sizeof(chat_file_path), "%s/chat.csv", room_dir_path);

    FILE *chat_file = fopen(chat_file_path, "w");
    if (!chat_file) {
        perror("fopen");
        return;
    }

    fclose(chat_file);

    char line[BUF_SIZE];
    sprintf(line, "%s membuat room %s", username, room);
    log_action(channel, line);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "Room %s created", room);
    write(socket, response, strlen(response));
}

void join_room(int socket, const char *username, const char *channel, const char *room) {
    char line[BUF_SIZE];
    sprintf(line, "%s masuk ke room %s", username, room);
    log_action(channel, line);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "%s bergabung dengan room %s", username, room);
    write(socket, response, strlen(response));
}

void list_rooms(int socket, const char *channel) {
    char channel_dir_path[BUF_SIZE];
    snprintf(channel_dir_path, sizeof(channel_dir_path), "%s/%s", DISCORIT_DIR, channel);

    DIR *dir = opendir(channel_dir_path);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    char response[BUF_SIZE] = "Rooms: ";
    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            if(strcmp(entry->d_name, "admin") == 0) {
                continue;
            }
            strcat(response, entry->d_name);
            strcat(response, " ");
        }
    }

    closedir(dir);
    write(socket, response, strlen(response));
}

void edit_room(int socket, const char *username, const char *channel, const char *room, const char *new_room) {
    char old_room_dir_path[BUF_SIZE];
    snprintf(old_room_dir_path, sizeof(old_room_dir_path), "%s/%s/%s", DISCORIT_DIR, channel, room);

    char new_room_dir_path[BUF_SIZE];
    snprintf(new_room_dir_path, sizeof(new_room_dir_path), "%s/%s/%s", DISCORIT_DIR, channel, new_room);

    if (rename(old_room_dir_path, new_room_dir_path) == -1) {
        perror("rename");
        write(socket, "Failed to rename room directory", strlen("Failed to rename room directory"));
        return;
    }

    char line[BUF_SIZE];
    sprintf(line, "%s merubah room %s menjadi %s", username, room, new_room);
    log_action(channel, line);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "%s nama room berubah menjadi %s", room, new_room);
    write(socket, response, strlen(response));
}

void delete_room(int socket, const char *channel, const char *room, const char *username) {
    char room_dir_path[BUF_SIZE];
    snprintf(room_dir_path, sizeof(room_dir_path), "%s/%s/%s", DISCORIT_DIR, channel, room);

    int delete_result = remove_directory(room_dir_path);
    if (delete_result == -1) {
        perror("remove_directory");
        write(socket, "Failed to delete room directory", strlen("Failed to delete room directory"));
        return;
    }

    char line[BUF_SIZE];
    sprintf(line, "%s menghapus room %s", username, room);
    log_action(channel, line);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "Room %s deleted", room);
    write(socket, response, strlen(response));
}

void delete_all_rooms(int socket, const char *channel, const char *username) {
    char channel_dir_path[BUF_SIZE];
    snprintf(channel_dir_path, sizeof(channel_dir_path), "%s/%s", DISCORIT_DIR, channel);

    DIR *dir = opendir(channel_dir_path);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            if(strcmp(entry->d_name, "admin") == 0) {
                continue;
            }
            char room_dir_path[BUF_SIZE];
            snprintf(room_dir_path, sizeof(room_dir_path), "%s/%s", channel_dir_path, entry->d_name);

            int delete_result = remove_directory(room_dir_path);
            if (delete_result == -1) {
                perror("remove_directory");
                write(socket, "Failed to delete room directory", strlen("Failed to delete room directory"));
                return;
            }
        }
    }

    closedir(dir);

    char line[BUF_SIZE];
    sprintf(line, "%s menghapus semua room", username);
    log_action(channel, line);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "All rooms deleted");
    write(socket, response, strlen(response));
}

// Helper function to sanitize strings
void sanitize_string(const char *input, char *output, size_t output_size) {
    size_t i, j;
    for (i = 0, j = 0; input[i] != '\0' && j < output_size - 1; i++) {
        if (input[i] != ',' && input[i] != '\n') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

void chat(int socket, const char *channel, const char *room, const char *username, const char *message) {
    char chat_file_path[BUF_SIZE];
    if (snprintf(chat_file_path, sizeof(chat_file_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, channel, room) >= sizeof(chat_file_path)) {
        // Path too long
        const char *error_msg = "Error: Path too long";
        send(socket, error_msg, strlen(error_msg), 0);
        return;
    }

    FILE *chat_file = fopen(chat_file_path, "a+");
    if (!chat_file) {
        perror("fopen");
        const char *error_msg = "Error: Could not open chat file";
        send(socket, error_msg, strlen(error_msg), 0);
        return;
    }

    int id_chat = 1;
    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), chat_file)) {
        if (strlen(line) <= 1) continue;
        char *token = strtok(line, ",");
        if (token) {
            int current_id_chat = atoi(token);
            if (current_id_chat >= id_chat) {
                id_chat = current_id_chat + 1;
            }
        }
    }

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[BUF_SIZE];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

    // Sanitize username and message to remove newlines and commas
    char safe_username[BUF_SIZE], safe_message[BUF_SIZE];
    sanitize_string(username, safe_username, sizeof(safe_username));
    sanitize_string(message, safe_message, sizeof(safe_message));

    fprintf(chat_file, "%d,%s,%s,%s\n", id_chat, timestamp, safe_username, safe_message);
    fclose(chat_file);

    char send_message[BUF_SIZE];
    snprintf(send_message, sizeof(send_message), "Chat Baru: %s", safe_message);
    send(socket, send_message, strlen(send_message), 0);

    char log_message[BUF_SIZE];
    snprintf(log_message, sizeof(log_message), "%s: %s", safe_username, safe_message);
    log_action(room, log_message);
}

void edit_chat(int socket, const char *channel, const char *room, const char *username, int id_chat, const char *new_message) {
    char chat_file_path[BUF_SIZE];
    snprintf(chat_file_path, sizeof(chat_file_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, channel, room);

    FILE *chat_file = fopen(chat_file_path, "r");
    FILE *temp_file = fopen("temp.csv", "w");

    if (!chat_file || !temp_file) {
        perror("fopen");
        const char *error_msg = "Error: Could not open files";
        send(socket, error_msg, strlen(error_msg), 0);
        return;
    }

    char line[BUF_SIZE];
    int edited = 0;
    while (fgets(line, sizeof(line), chat_file)) {
        char original_line[BUF_SIZE];
        strncpy(original_line, line, sizeof(original_line));

        char *token = strtok(line, ",");
        if (token) {
            int current_id_chat = atoi(token);
            if (current_id_chat == id_chat) {
                // Extract original timestamp and username
                char *original_timestamp = strtok(NULL, ",");
                char *original_username = strtok(NULL, ",");

                // Sanitize new_message to remove newlines and commas
                char safe_new_message[BUF_SIZE];
                sanitize_string(new_message, safe_new_message, sizeof(safe_new_message));

                fprintf(temp_file, "%d,%s,%s,%s\n", id_chat, original_timestamp, original_username, safe_new_message);
                edited = 1;
            } else {
                // Write the original line to the temporary file
                fputs(original_line, temp_file);
            }
        } else {
            // If line parsing fails, write the original line
            fputs(original_line, temp_file);
        }
    }

    fclose(chat_file);
    fclose(temp_file);

    if (edited) {
        // Replace the original file with the temporary file
        if (remove(chat_file_path) == 0 && rename("temp.csv", chat_file_path) == 0) {
            const char *success_msg = "Chat berhasil diubah";
            send(socket, success_msg, strlen(success_msg), 0);

            char log_message[BUF_SIZE];
            snprintf(log_message, sizeof(log_message), "%s mengubah chat %d", username, id_chat);

            log_action(channel, log_message);
        } else {
            perror("File operation failed");
            const char *error_msg = "Error: Failed to update chat file";
            send(socket, error_msg, strlen(error_msg), 0);
        }
    } else {
        // Remove the temporary file if no edit was made
        remove("temp.csv");
        const char *not_found_msg = "Error: Chat message not found";
        send(socket, not_found_msg, strlen(not_found_msg), 0);
    }
}

void delete_chat(int socket, const char *channel, const char *room, int id_chat) {
    char chat_file_path[BUF_SIZE];
    char temp_file_path[BUF_SIZE];
    snprintf(chat_file_path, sizeof(chat_file_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, channel, room);
    snprintf(temp_file_path, sizeof(temp_file_path), "%s/%s/%s/temp_chat.csv", DISCORIT_DIR, channel, room);

    FILE *chat_file = fopen(chat_file_path, "r");
    FILE *temp_file = fopen(temp_file_path, "w");

    if (!chat_file || !temp_file) {
        perror("Error opening files");
        if (chat_file) fclose(chat_file);
        if (temp_file) fclose(temp_file);
        send(socket, "Error: Could not delete chat", 28, 0);
        return;
    }

    char line[BUF_SIZE];
    int deleted = 0;
    int line_count = 0;

    while (fgets(line, sizeof(line), chat_file)) {
        line_count++;
        
        // Skip the header line if it exists
        if (line_count == 1 && strstr(line, "date") && strstr(line, "id_chat")) {
            fputs(line, temp_file);
            continue;
        }

        int current_id_chat;
        char sender[BUF_SIZE], chat_content[BUF_SIZE], date[BUF_SIZE];

        // Parse the line according to the format
        if (sscanf(line, "%d,%[^,],%[^,],%[^\n]", &current_id_chat, date, sender, chat_content) == 4) {
            if (current_id_chat != id_chat) {
                fputs(line, temp_file);
            } else {
                deleted = 1;
            }
        } else {
            // If parsing fails, write the line as is
            fputs(line, temp_file);
        }
    }

    fclose(chat_file);
    fclose(temp_file);

    if (deleted) {
        // Replace the original file with the temporary file
        if (remove(chat_file_path) != 0 || rename(temp_file_path, chat_file_path) != 0) {
            perror("Error replacing file");
            send(socket, "Error: Could not delete chat", 28, 0);
            return;
        }
        send(socket, "Chat Dihapus", 12, 0);

        char log_message[BUF_SIZE];
        snprintf(log_message, sizeof(log_message), "Chat %d dihapus", id_chat);
        log_action(channel, log_message);
    } else {
        // Remove the temporary file if no edit was made
        remove(temp_file_path);
        send(socket, "Chat not found", 14, 0);
    }
}

void see_chat(int socket, const char *channel, const char *room) {
    char chat_file_path[BUF_SIZE];
    snprintf(chat_file_path, sizeof(chat_file_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, channel, room);

    FILE *chat_file = fopen(chat_file_path, "r");
    if (!chat_file) {
        perror("fopen");
        return;
    }

    char response[BUF_SIZE * 10] = "Chat:\n";  // Increased buffer size for response
    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), chat_file)) {
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

    fclose(chat_file);
    write(socket, response, strlen(response));
}
