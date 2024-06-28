Sisop-FP-2024-MH-IT07

------------ Anggota Kelompok -------------

Dzaky Faiq Fayyadhi 5027231047 Kelas B

Randist Prawandha Putera 5027231059 Kelas B

Radella Chesa Syaharani 5027231064 Kelas A

## server.c
### 1. Header dan Deklarasi
````
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
#define USER_FILE "/home/ax3lrod/sisop/fp/DiscorIT/users.csv"
#define DISCORIT_DIR "/home/ax3lrod/sisop/fp/DiscorIT"
#define CHANNEL_FILE "/home/ax3lrod/sisop/fp/DiscorIT/channels.csv"

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

````
- #include mencakup berbagai header file yang diperlukan untuk operasi jaringan, threading, enkripsi, logging, dan operasi sistem file.
- #define digunakan untuk mendefinisikan konstanta seperti port server, ukuran buffer, jumlah maksimal klien, dan lokasi file yang menyimpan data pengguna dan saluran.
- UserLoginStatus: Menyimpan status login pengguna biasa dan monitor.
- Session: Menyimpan informasi sesi untuk setiap pengguna yang login, termasuk status login, ID pengguna, username, role, saluran dan ruangan saat ini, serta status monitor.
- monitorSession: Struktur untuk menyimpan status login monitor.
- Client: Menyimpan informasi untuk setiap klien yang terhubung, termasuk socket, status monitor, status login, dan username.
- logged_in_users: Array yang menyimpan status login pengguna berdasarkan ID.
- clients: Array yang menyimpan informasi klien yang terhubung.
- client_count: Menyimpan jumlah klien yang terhubung saat ini.
- Prototipe untuk berbagai fungsi yang digunakan dalam server untuk menangani klien, mengelola saluran dan ruangan, mengedit informasi pengguna, dan mengirim pesan.
- handle_client(void *arg): Fungsi untuk menangani komunikasi dengan klien.
- bcrypt(const char *password): Fungsi untuk mengenkripsi kata sandi menggunakan bcrypt.
- Fungsi lain untuk mengelola saluran, ruangan, dan pengguna, serta untuk mengirim dan mengedit pesan.

### 2. Deskripsi Fungsi
````
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
````
Channel Management:
- list_channels: Menampilkan daftar saluran yang tersedia.
- create_channel: Membuat saluran baru.
- edit_channel: Mengubah nama saluran yang ada.
- delete_channel: Menghapus saluran.
- kick_user: Mengeluarkan pengguna dari saluran.
- join_channel: Bergabung dengan saluran yang ada.

Room Management:
- create_room: Membuat ruangan dalam saluran tertentu.
- join_room: Bergabung dengan ruangan dalam saluran tertentu.
- edit_room: Mengubah nama ruangan yang ada.
- delete_room: Menghapus ruangan.
- delete_all_rooms: Menghapus semua ruangan dalam saluran tertentu.
- list_rooms: Menampilkan daftar ruangan dalam saluran tertentu.

User Management:
- list_users: Menampilkan daftar pengguna.
- list_channel_users: Menampilkan daftar pengguna dalam saluran tertentu.
- edit_user_name: Mengubah nama pengguna sendiri.
- edit_user_name_other: Mengubah nama pengguna lain (oleh monitor).
- edit_user_password: Mengubah kata sandi pengguna.
- remove_user: Menghapus pengguna.
- ban_user: Melarang pengguna dari saluran tertentu.
- unban_user: Mengizinkan kembali pengguna yang dilarang dari saluran.

Chat Management:
- chat: Mengirim pesan dalam ruangan tertentu.
- edit_chat: Mengedit pesan yang sudah dikirim.
- delete_chat: Menghapus pesan yang sudah dikirim.
- see_chat: Melihat pesan dalam ruangan tertentu.

### 3. Fungsi `remove_directory`
````
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
````
fungsi remove_directory yang bertujuan untuk menghapus direktori beserta isinya, termasuk subdirektori dan file yang ada di dalamnya. Fungsi ini secara rekursif menghapus semua file dan subdirektori sebelum akhirnya menghapus direktori itu sendiri. 

#### Deklarasi dan inisialisasi
````
int remove_directory(const char *path) {
    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;
````
- DIR *d = opendir(path);: Membuka direktori yang path-nya diberikan sebagai argumen dan mengembalikan pointer ke struktur direktori.
- size_t path_len = strlen(path);: Menghitung panjang string dari path direktori.
- int r = -1;: Inisialisasi variabel r dengan nilai -1, yang menunjukkan kegagalan operasi jika tidak berubah.

#### Pemeriksaan Direktori
````
if (d) {
    struct dirent *p;
    r = 0;

````
Jika direktori berhasil dibuka (d tidak NULL), inisialisasi variabel p dari tipe struct dirent dan set r ke 0, yang menandakan keberhasilan.

#### Pembacaan Direktori
````
    while (!r && (p = readdir(d))) {
        int r2 = -1;
        char *buf;
        size_t len;

````
- while (!r && (p = readdir(d))): Iterasi melalui setiap entri dalam direktori selama r tetap 0 dan masih ada entri yang bisa dibaca.
- int r2 = -1;: Inisialisasi variabel r2 dengan -1 untuk memeriksa hasil penghapusan entri.
- char *buf;: Pointer untuk menyimpan path lengkap dari entri yang sedang diproses.
- size_t len;: Menyimpan panjang dari path lengkap.

#### Melewati Entri Khusus
````
        if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
            continue;

````
Memeriksa dan melewati entri khusus "." dan ".." yang merepresentasikan direktori saat ini dan direktori induk.

#### Penggabungan Path dan Penghapusan
````
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
````
- len = path_len + strlen(p->d_name) + 2;: Menghitung panjang buffer yang diperlukan untuk path lengkap.
- buf = malloc(len);: Mengalokasikan memori untuk buffer.
- snprintf(buf, len, "%s/%s", path, p->d_name);: Menggabungkan path direktori dengan nama entri untuk membentuk path lengkap.
- stat(buf, &statbuf): Mendapatkan informasi status dari entri.
- if (S_ISDIR(statbuf.st_mode)): Jika entri adalah direktori, panggil remove_directory secara rekursif.
- else unlink(buf);: Jika entri adalah file, hapus file tersebut.
- free(buf);: Membebaskan memori yang dialokasikan untuk buffer.
- r = r2;: Set nilai r ke hasil dari operasi penghapusan entri.

#### Menutup Direktori dan Menghapus Direktori
````
    closedir(d);
}

if (!r)
    r = rmdir(path);

return r;
````
- closedir(d);: Menutup direktori setelah selesai diproses.
- if (!r) r = rmdir(path);: Jika semua entri berhasil dihapus (r adalah 0), hapus direktori itu sendiri.
- return r;: Mengembalikan nilai r yang menunjukkan keberhasilan (0) atau kegagalan (nilai negatif) operasi penghapusan direktori.

### 4. Fungsi `get_timestamp`
````
void get_timestamp(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, buffer_size, "[%d/%m/%Y %H:%M:%S]", t);
}
````
Fungsi ini menghasilkan timestamp dalam format [dd/mm/yyyy hh:mm:ss] dan menyimpannya di buffer yang diberikan.

time_t now = time(NULL);: Mendapatkan waktu saat ini.
struct tm *t = localtime(&now);: Mengonversi waktu ke format lokal.
strftime(buffer, buffer_size, "[%d/%m/%Y %H:%M:%S]", t);: Memformat waktu dan menyimpannya dalam buffer.

### 5. Fungsi `log_action`
````
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
````
Fungsi ini mencatat sebuah aksi ke file log (user.log) yang terletak di dalam folder admin pada direktori saluran tertentu.

- char log_file_path[BUF_SIZE];: Buffer untuk path file log.
- snprintf(log_file_path, sizeof(log_file_path), "%s/%s/admin/user.log", DISCORIT_DIR, channel_name);: Menggabungkan direktori dan nama saluran untuk membuat path lengkap ke file log.
- FILE *log_file = fopen(log_file_path, "a");: Membuka file log dalam mode append. Jika gagal, menampilkan pesan error dan keluar dari fungsi.
- char timestamp[BUF_SIZE];: Buffer untuk menyimpan timestamp.
- get_timestamp(timestamp, sizeof(timestamp));: Mendapatkan timestamp saat ini.
- fprintf(log_file, "%s %s\n", timestamp, event);: Menulis timestamp dan event ke file log.
- fclose(log_file);: Menutup file log.

### 6. Fungsi `daemonize`
````
void daemonize() {
    pid_t pid;

    pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        perror("setsid failed");
        exit(EXIT_FAILURE);
    }

    signal(SIGCHLD, SIG_IGN);

    pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    if (chdir("/") < 0) {
        perror("chdir failed");
        exit(EXIT_FAILURE);
    }

    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);
}
````
Fungsi ini mengubah proses yang sedang berjalan menjadi daemon, yaitu sebuah proses yang berjalan di latar belakang tanpa kontrol terminal.

Fork the Parent Process:
- pid = fork();: Membuat proses anak.
- Jika fork gagal (pid < 0), menampilkan pesan error dan keluar.
- Jika pid > 0, ini adalah proses induk yang keluar dengan status sukses.

Set Session Leader:
- if (setsid() < 0): Proses anak menjadi pemimpin sesi baru.
- Jika setsid gagal, menampilkan pesan error dan keluar.

Ignore SIGCHLD:
- signal(SIGCHLD, SIG_IGN);: Mengabaikan sinyal dari proses anak yang berakhir.

Fork Again:
- pid = fork();: Membuat proses anak kedua.
- Jika fork gagal, menampilkan pesan error dan keluar.
- Jika pid > 0, proses induk kedua keluar dengan status sukses.

Set File Permissions:
- umask(0);: Mengatur mode file mask untuk memastikan file yang dibuat memiliki izin yang tepat.

Change Working Directory:
- if (chdir("/") < 0): Mengubah direktori kerja ke root untuk memastikan proses daemon tidak mengunci direktori yang sedang berjalan.
- Jika chdir gagal, menampilkan pesan error dan keluar.

Close File Descriptors:
- open("/dev/null", O_RDWR);: Membuka /dev/null untuk input/output standar.
- dup(0);: Menyalin file descriptor stdin ke stdout.
- dup(0);: Menyalin file descriptor stdin ke stderr.

Fungsi ini memastikan bahwa daemon tidak terkait dengan terminal dan dapat berjalan di latar belakang tanpa interaksi langsung dari pengguna.

### 7. Fungsi `main`
````
int main() {
    daemonize();

    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

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
````
#### Daemonisasi:
````
daemonize();
````
Memanggil fungsi daemonize untuk membuat proses menjadi daemon.

#### Membuat Socket:
````
if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
}
````
Membuat socket file descriptor untuk komunikasi TCP.

#### Mengatur Opsi Socket:
````
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
````
Mengatur opsi socket untuk memungkinkan penggunaan kembali alamat dan port.

#### Binding:
````
address.sin_family = AF_INET;
address.sin_addr.s_addr = INADDR_ANY;
address.sin_port = htons(PORT);

if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    close(server_fd);
    exit(EXIT_FAILURE);
}
````
Mengaitkan socket ke alamat dan port tertentu.

#### Mendengarkan Koneksi:
````
if (listen(server_fd, 3) < 0) {
    perror("listen");
    close(server_fd);
    exit(EXIT_FAILURE);
}
````
Menempatkan socket dalam mode mendengarkan untuk menerima koneksi masuk.

#### Menerima dan Menangani Koneksi Klien:
````
while (1) {
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        continue;
    }
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, handle_client, (void *)&new_socket);
}
````
Menerima koneksi masuk dan membuat thread baru untuk menangani setiap klien menggunakan fungsi handle_client.

### 8. Fungsi `send_to_monitor`
````
void send_to_monitor(const char *message) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != 0 && clients[i].is_monitor) {
            send(clients[i].socket, message, strlen(message), 0);
        }
    }
}
````
Penjelasan:
Fungsi ini mengirim pesan ke semua klien yang bertindak sebagai monitor.
Iterasi melalui semua klien dan mengirim pesan jika klien adalah monitor.

### 9. Fungsi `find_monitor_client`
````
int find_monitor_client(const char *username) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != 0 && clients[i].is_monitor && strcmp(clients[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}
````
Penjelasan:
Fungsi ini mencari klien monitor berdasarkan nama pengguna.
Mengembalikan indeks klien jika ditemukan, atau -1 jika tidak ditemukan.

### 10. Fungsi `send_message_to_monitor`
````
void send_message_to_monitor(Session *session, const char *message) {
    int monitor_index = find_monitor_client(session->username);
    if (monitor_index != -1) {
        send(clients[monitor_index].socket, message, strlen(message), 0);
    }
}
````
Penjelasan:
Fungsi ini mengirim pesan ke klien monitor yang sesuai dengan nama pengguna dalam sesi.
Menggunakan find_monitor_client untuk menemukan klien dan mengirim pesan jika ditemukan.

### 11. Fungsi `close_monitor_sessions`
````
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
````
Penjelasan:
Fungsi ini menutup semua sesi klien yang bertindak sebagai monitor.
Iterasi melalui semua klien, menutup socket klien yang adalah monitor, dan mengatur ulang status klien.

### 12. Fungsi `is_logged_in`
````
bool is_logged_in(const char *username) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].logged_in && strcmp(clients[i].username, username) == 0) {
            return 1;
        }
    }
    return 0;
}\
````
Penjelasan:
Fungsi ini memeriksa apakah pengguna dengan username tertentu sudah login.
Melakukan iterasi melalui daftar klien (clients), jika ditemukan klien yang sudah login dengan username yang cocok, mengembalikan true (1). Jika tidak ditemukan, mengembalikan false (0).

### 13. Fungsi `handle_client`
````
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
````
Penjelasan:

Inisialisasi:
- Socket klien diterima sebagai argumen.
- Buffer untuk membaca data dari klien dan variabel lainnya diinisialisasi.
- Session dan monitorSession diinisialisasi untuk menyimpan informasi sesi dan monitor.
- Mencari indeks klien yang kosong untuk menambahkan klien baru ke dalam daftar clients.

Menerima dan Memproses Perintah Klien:
- Loop membaca data dari socket klien.
- Data yang diterima diparsing untuk mendapatkan perintah, username, dan password.
- Memproses perintah REGISTER, LOGIN, dan LOGIN_MONITOR.
- Jika perintah adalah REGISTER, memanggil register_user dan mengirimkan pesan berhasil atau gagal.
- Jika perintah adalah LOGIN, memanggil login_user dan mengirimkan pesan berhasil atau gagal, serta mengatur status login klien dalam daftar clients.
- Jika perintah adalah LOGIN_MONITOR, memanggil login_user untuk login sebagai monitor dan mengatur status monitor dan login klien dalam daftar clients.
- Jika pengguna sudah login, memproses perintah lainnya dengan memanggil process_command.
- Jika pengguna belum login, mengirimkan pesan bahwa pengguna harus login terlebih dahulu.

Menutup Koneksi Klien:
- Jika koneksi klien terputus, socket ditutup dan status klien dalam daftar clients direset.
- Jika klien sudah login, memanggil logout_user untuk keluar dari sesi.
- Mengurangi jumlah klien yang terhubung (client_count).

### 14. Fungsi `register_user`
````
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
````
Penjelasan:
Membaca File Pengguna:

Membuka file USER_FILE untuk membaca.
Memeriksa apakah username sudah ada di file.
Menentukan max_id untuk ID pengguna baru.
Menambahkan Pengguna Baru:

Jika username belum ada, membuka file USER_FILE dalam mode append.
Mengenkripsi password menggunakan bcrypt.
Menulis informasi pengguna baru ke dalam file.
Menutup file dan mengembalikan nilai 1 yang menunjukkan registrasi berhasil.

![Screenshot 2024-06-27 201346](https://github.com/Ax3lrod/Sisop-FP-2024-MH-IT17/assets/151889425/e32c45eb-3681-4ce9-bac3-ab0fddb64bb0)


### 15. Fungsi `login_user`
````
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
````
Penjelasan:
Membaca File Pengguna:

Membuka file USER_FILE untuk membaca.
Memeriksa apakah username ada di file.
Memeriksa Status Login dan Password:

Memeriksa apakah pengguna sudah login.
Membandingkan password yang dienkripsi.
Jika cocok, memperbarui sesi pengguna dengan informasi login.
Menutup file dan mengembalikan nilai 1 untuk menunjukkan login berhasil.

### 16. Fungsi `logout_user`
````
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
````
Penjelasan:
Logout Pengguna:
Memeriksa apakah sesi pengguna sedang login.
Mengubah status login dalam daftar logged_in_users berdasarkan tipe sesi (monitor atau regular).
Mengatur ulang informasi sesi pengguna menjadi nol atau kosong.

### 17. Fungsi `logout_monitor`
````
void logout_monitor(monitorSession *monitor_session) {
    if (monitor_session->logged_in) {
        monitor_session->logged_in = 0;
    }
}
````
Penjelasan:
Logout Monitor:
Memeriksa apakah sesi monitor sedang login.
Mengubah status login monitor menjadi tidak login (0).


### 18. Fungsi `login_monitor`
````
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
````
Fungsi ini bertujuan untuk memeriksa kredensial login pengguna dan mengatur sesi login jika pengguna berhasil masuk sebagai monitor.

Parameter:
- username: Nama pengguna yang mencoba login.
- password: Kata sandi yang diberikan oleh pengguna.
- session: Pointer ke struktur sesi yang digunakan untuk mencatat status login.

Proses:
- Membuka file pengguna (USER_FILE) dalam mode baca. Jika gagal, mencetak pesan kesalahan dan mengembalikan 0. -
- Membaca setiap baris dari file dan memparsingnya menjadi variabel yang sesuai (id, stored_username, stored_password, role).
- Jika baris tidak terformat dengan benar (kurang dari 4 bidang), mencetak pesan kesalahan dan melanjutkan ke baris berikutnya.
- Membandingkan stored_username dengan username yang diberikan.
- Jika cocok, membandingkan kata sandi yang di-hash menggunakan fungsi crypt dengan stored_password.
- Jika kata sandi cocok, mengatur status login dalam session dan menutup file, lalu mengembalikan 1.
- Jika tidak cocok, menutup file dan mengembalikan 0.

### 19. Fungsi `bool is_admin`
````
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
````
Fungsi ini memeriksa apakah seorang pengguna adalah admin pada suatu channel tertentu.

Parameter:
socket: Soket yang digunakan untuk komunikasi (tidak digunakan dalam implementasi ini).
channel_name: Nama channel yang diperiksa.
username: Nama pengguna yang diperiksa.

Proses:
Mengatur jalur direktori admin berdasarkan DISCORIT_DIR dan channel_name.
Membuka file autentikasi (auth.csv) dalam direktori tersebut.
Membaca setiap baris dari file dan memparsingnya menjadi variabel yang sesuai (id, stored_username, role).
Jika stored_username cocok dengan username dan role adalah "ADMIN", menutup file dan mengembalikan true.
Jika tidak ditemukan, menutup file dan mengembalikan false.

### 20. Fungsi `bool is_root`    
````
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
````
Fungsi ini memeriksa apakah seorang pengguna adalah root (superuser) dalam sistem.

Parameter:
socket: Soket yang digunakan untuk komunikasi (tidak digunakan dalam implementasi ini).
username: Nama pengguna yang diperiksa.

Proses:
Membuka file pengguna (USER_FILE) dalam mode baca.
Membaca setiap baris dari file dan memparsingnya menjadi variabel yang sesuai (id, stored_username, password, role).
Jika stored_username cocok dengan username dan role adalah "ROOT", menutup file dan mengembalikan true.
Jika tidak ditemukan, menutup file dan mengembalikan false.

### 21. Fungsi `bool is_member`
````
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
````
Fungsi ini memeriksa apakah seorang pengguna adalah anggota dari suatu channel tertentu.

Parameter:
socket: Soket yang digunakan untuk komunikasi (tidak digunakan dalam implementasi ini).
channel_name: Nama channel yang diperiksa.
username: Nama pengguna yang diperiksa.

Proses:
Mengatur jalur direktori autentikasi berdasarkan DISCORIT_DIR dan channel_name.
Membuka file autentikasi (auth.csv) dalam direktori tersebut.
Membaca setiap baris dari file dan memparsingnya menjadi variabel yang sesuai (id, stored_username, role).
Jika stored_username cocok dengan username, menutup file dan mengembalikan true.
Jika tidak ditemukan, menutup file dan mengembalikan false.

### 22. Fungsi `bool validate_key`
````
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
````
Fungsi ini memeriksa apakah kunci yang diberikan valid untuk suatu channel.

Parameter:
socket: Soket yang digunakan untuk komunikasi (tidak digunakan dalam implementasi ini).
channel_name: Nama channel yang diperiksa.
key: Kunci yang diberikan untuk divalidasi.

Proses:
Membuka file channel (CHANNEL_FILE) dalam mode baca. Jika gagal, mencetak pesan kesalahan dan mengembalikan false.
Memangkas newline dari kunci jika ada.
Membaca setiap baris dari file dan memparsingnya menjadi variabel yang sesuai (stored_channel, stored_key).
Jika stored_channel cocok dengan channel_name dan kunci yang di-hash cocok dengan stored_key, menutup file dan mengembalikan true.
Jika tidak ditemukan, menutup file dan mengembalikan false.

### 23. Fungsi `bool channel_exists`
````
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
````
Fungsi ini memeriksa apakah suatu channel ada.

Parameter:
socket: Soket yang digunakan untuk komunikasi (tidak digunakan dalam implementasi ini).
channel_name: Nama channel yang diperiksa.

Proses:
Membuka file channel (CHANNEL_FILE) dalam mode baca. Jika gagal, mencetak pesan kesalahan dan mengembalikan false.
Membaca setiap baris dari file dan memparsingnya menjadi variabel yang sesuai (stored_channel).
Jika stored_channel cocok dengan channel_name, menutup file dan mengembalikan true.
Jika tidak ditemukan, menutup file dan mengembalikan false.

### 24. Fungsi `bool room_exists`
````
bool room_exists(int socket, const char *channel_name, const char *room_name) {
    char room_dir_path[BUF_SIZE];
    snprintf(room_dir_path, sizeof(room_dir_path), "%s/%s/%s", DISCORIT_DIR, channel_name, room_name);

    struct stat st;
    if (stat(room_dir_path, &st) == 0) {
        return 1;
    }

    return 0;
}
````
Fungsi ini memeriksa apakah suatu room ada dalam channel tertentu.

Parameter:
socket: Soket yang digunakan untuk komunikasi (tidak digunakan dalam implementasi ini).
channel_name: Nama channel yang diperiksa.
room_name: Nama room yang diperiksa.

Proses:
Menyusun jalur direktori room berdasarkan DISCORIT_DIR, channel_name, dan room_name.
Memeriksa apakah jalur tersebut ada menggunakan fungsi stat.
Jika jalur ada, mengembalikan true, jika tidak, mengembalikan false.

### 25. Fungsi `bool is_banned`
````
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
````
Fungsi ini memeriksa apakah seorang pengguna dilarang (banned) dalam channel tertentu.

Parameter:
socket: Soket yang digunakan untuk komunikasi (tidak digunakan dalam implementasi ini).
channel_name: Nama channel yang diperiksa.
username: Nama pengguna yang diperiksa.

Proses:
Menyusun jalur direktori autentikasi berdasarkan DISCORIT_DIR dan channel_name.
Membuka file autentikasi (auth.csv) dalam direktori tersebut.
Membaca setiap baris dari file dan memparsingnya menjadi variabel yang sesuai (id, stored_username, role).
Jika stored_username cocok dengan username dan role adalah "BANNED", menutup file dan mengembalikan true.
Jika tidak ditemukan, menutup file dan mengembalikan false.

### 26. Fungsi `bool username_taken`
````
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
````
Fungsi ini memeriksa apakah username yang diberikan sudah digunakan oleh pengguna lain.

Parameter:
socket: Soket yang digunakan untuk komunikasi (tidak digunakan dalam implementasi ini).
username: Nama pengguna yang ingin diperiksa apakah sudah ada atau belum.

Proses:
Membuka file pengguna (USER_FILE) dalam mode baca. Jika gagal, mencetak pesan kesalahan dan mengembalikan false (seharusnya, tetapi saat ini fungsi tidak mengembalikan nilai apapun jika terjadi kesalahan).
Membaca setiap baris dari file dan memparsingnya menjadi variabel yang sesuai (stored_username).
Jika stored_username cocok dengan username yang diberikan, menutup file dan mengembalikan true.
Jika tidak ditemukan, menutup file dan mengembalikan false.

### 27. Fungsi `bool my_message`
````
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
````
Fungsi ini memeriksa apakah pesan dengan ID tertentu dikirim oleh pengguna yang diberikan dalam channel dan room tertentu.

Parameter:
socket: Soket yang digunakan untuk komunikasi (tidak digunakan dalam implementasi ini).
channel_name: Nama channel tempat pesan dikirim.
room_name: Nama room tempat pesan dikirim.
username: Nama pengguna yang mengirim pesan.
id_chat: ID dari pesan yang ingin diperiksa.

Proses:
Menyusun jalur direktori chat berdasarkan DISCORIT_DIR, channel_name, dan room_name.
Membuka file chat (chat.csv) dalam mode baca. Jika gagal, mencetak pesan kesalahan dan mengembalikan false (seharusnya, tetapi saat ini fungsi tidak mengembalikan nilai apapun jika terjadi kesalahan).
Membaca setiap baris dari file dan memparsingnya menjadi variabel yang sesuai (id, timestamp, sender, message).
Jika id cocok dengan id_chat dan sender cocok dengan username, menutup file dan mengembalikan true.
Jika tidak ditemukan, menutup file dan mengembalikan false.

### 28. Fungsi `process_command`
````
void process_command(int socket, Session *session, char *buffer, monitorSession *monitor_session) {
    char command[BUF_SIZE], arg1[BUF_SIZE], arg2[BUF_SIZE], arg3[BUF_SIZE], key[BUF_SIZE], 
    channel_name[BUF_SIZE], new_channel_name[BUF_SIZE], room_name[BUF_SIZE], new_room_name[BUF_SIZE], 
    message[BUF_SIZE], new_username[BUF_SIZE], new_password[BUF_SIZE], target_username[BUF_SIZE], username[BUF_SIZE];
    int id_chat;
````
#### LIST CHANNEL menampilkan daftar channel yang ada.
````
    if (strstr(buffer, "LIST CHANNEL") != NULL) {
        list_channels(socket);
````
![Screenshot 2024-06-27 201540](https://github.com/Ax3lrod/Sisop-FP-2024-MH-IT17/assets/151889425/ae1e0f44-0ab1-45ab-a5f6-693d27696c6e)


#### CREATE CHANNEL membuat channel baru dengan nama dan key yang diberikan.
````
    } else if (sscanf(buffer, "CREATE CHANNEL %s -k %s", channel_name, key) == 2) {
        create_channel(socket, session->username, session->user_id, channel_name, key);
````
![Screenshot 2024-06-27 201613](https://github.com/Ax3lrod/Sisop-FP-2024-MH-IT17/assets/151889425/5d06ba7a-ce6d-4a0b-b6bd-938bbb2b8afa)


#### EDIT CHANNEL mengganti nama channel, jika user adalah admin atau root.
````
    } else if (sscanf(buffer, "EDIT CHANNEL %s TO %s", channel_name, new_channel_name) == 2) {
        if(is_admin(socket, channel_name, session->username) || is_root(socket, session->username)) {
            edit_channel(socket, session->username, channel_name, new_channel_name);
            strcpy(session->current_channel, new_channel_name);
        } else {
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
````
#### DELETE CHANNEL menghapus channel, jika user adalah admin atau root dan tidak berada dalam channel tersebut.
````
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
````
#### JOIN CHANNEL/ROOM bergabung ke channel atau room. Jika channel memerlukan key, user harus memasukkan key yang benar.
````
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
````
![Screenshot 2024-06-27 201642](https://github.com/Ax3lrod/Sisop-FP-2024-MH-IT17/assets/151889425/d5f1fd16-b6bc-4155-a379-a340f0c4786d)


#### CREATE ROOM membuat room baru dalam channel saat ini, jika user adalah admin atau root.
````
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
````
#### LIST ROOM menampilkan daftar room dalam channel saat ini, jika user telah bergabung ke channel.
````
    } else if (strcmp(buffer, "LIST ROOM") == 0) {
        if(session->in_channel){
            list_rooms(socket, session->current_channel);
        }else{
            write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
        }
````
#### EDIT ROOOM mengganti nama room dalam channel saat ini, jika user adalah admin atau root.
````
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
````
![Screenshot 2024-06-28 000313](https://github.com/Ax3lrod/Sisop-FP-2024-MH-IT17/assets/151889425/1c85ddc4-6167-4570-9df3-285487ac407a)



#### DELETE ROOM menghapus room, jika user adalah admin atau root dan tidak berada dalam room tersebut.
````
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
````
#### LIST USER menampilkan daftar user, tergantung apakah user berada dalam channel atau merupakan root.
````
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
````
![Screenshot 2024-06-27 201540](https://github.com/Ax3lrod/Sisop-FP-2024-MH-IT17/assets/151889425/f368f5a1-784d-4e22-b620-470ffb09727a)


#### EDIT PROFILE SELF mengubah password user saat ini.
````
    } else if (sscanf(buffer, "EDIT PROFILE SELF -u %s", new_username) == 1) {
        if(username_taken(socket, new_username)){
            write(socket, "Username sudah terdaftar", strlen("Username sudah terdaftar"));
        }else{
            edit_user_name(socket, session->username, new_username);
            strcpy(session->username, new_username);
        }
    } else if (sscanf(buffer, "EDIT PROFILE SELF -p %s", new_password) == 1) {
        edit_user_password(socket, session->username, new_password);
````
![Screenshot 2024-06-28 000313](https://github.com/Ax3lrod/Sisop-FP-2024-MH-IT17/assets/151889425/06275ae8-f243-4f1a-9a90-f4d60d793595)


#### EDIT USER -u mengubah username user lain, jika user saat ini adalah root dan username baru belum terdaftar.
````
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
````
#### EDIT USER -p mengubah password user lain, jika user saat ini adalah root.
````
    } else if (sscanf(buffer, "EDIT WHERE %s -p %s", username, new_password) == 2) {
        if(is_root(socket, session->username)){
            edit_user_password(socket, username, new_password);
        }else{
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
````
#### REMOVE USER mengeluarkan user dari channel saat ini, jika user saat ini adalah admin atau root dan user target adalah anggota channel.
````
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
````
![Screenshot 2024-06-28 000626](https://github.com/Ax3lrod/Sisop-FP-2024-MH-IT17/assets/151889425/c083d9c7-323c-4f17-95a4-12f72a6f63e3)


#### REMOVE menghapus user dari sistem, jika user saat ini adalah root dan user target bukan root.
````
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
````
![Screenshot 2024-06-28 000514](https://github.com/Ax3lrod/Sisop-FP-2024-MH-IT17/assets/151889425/6428fe58-ff27-46b5-9467-ad3d48a2475d)


#### BAN USER membanned user dari channel saat ini, jika user saat ini adalah admin atau root dan user target bukan anggota, admin, atau root.
````
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
````
#### UNBAM USER menghapus banned user dari channel saat ini, jika user saat ini adalah admin atau root dan user target telah dibanned.
````
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
````
#### CHAT mengirim pesan dalam room saat ini, jika user berada dalam channel dan room. Pesan harus di dalam tanda kutip ganda.
````
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
````
#### EDIT CHAT mengubah pesan dalam room saat ini, jika user berada dalam channel dan room serta user adalah admin, root, atau pemilik pesan.
````
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
````
#### DELETE CHAT menghapus pesan dalam room saat ini, jika user berada dalam channel dan room serta user adalah admin, root, atau pemilik pesan.
````
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
````
#### SEE CHAT menampilkan pesan dalam room saat ini, jika user berada dalam channel dan room.
````
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
````
CHAT, EDIT, DELETE, SEE
![Screenshot 2024-06-27 202027](https://github.com/Ax3lrod/Sisop-FP-2024-MH-IT17/assets/151889425/c06133cc-2878-4828-9a33-3b2ca3a74281)


#### EXIT, user akan keluar dari room dan channel saat ini, log exit akan dicatat, dan user akan keluar dari sistem.
````
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
````
#### Jika perintah tidak dikenali, pesan "Perintah tidak valid" akan dikirim ke user.
````    
    } else {
        write(socket, "Perintah tidak valid", strlen("Perintah tidak valid"));
    }
}
````

### 29. Fungsi `bcrypt`
```
har *bcrypt(const char *password) {
    char salt[] = "$2b$12$XXXXXXXXXXXXXXXXXXXXXX"; // Generate a random salt
    char *encrypted_password = crypt(password, salt);
    return strdup(encrypted_password);
}
```
Fungsi tersebut mengenkripsi _password_ menggunakan algoritma "bcrypt". Pertama-tama, fungsi akan membuat "salt" yang statis kemudian menggunakan `crypt()` untuk mengenkripsi _password_. Terakhir, fungsi mengembalikan salinan dari password yang telah dienkripsi.

### 30. Fungsi `list users`
```
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
```
Membaca file .csv dari pengguna setiap barisnya dan mengekstrak ID beserta namanya, lalu informasi tersebut dikumpulkan _string_ `response` yang pada akhirnya akan dikembalikan melalui socket.

### 31. Fungsi `list_channel_users`
```
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
```
Fungsi ini membaca file otentikasi _channel_ dan mengirimkan daftar pengguna _channel_ ke klien. Fungsi membuka file otentikasi channel, membaca setiap baris, dan mengekstrak nama pengguna. Lalu nama pengguna dikumpulkan dalam _string_ `response`. Akhirnya, respons dikirim kembali ke klien melalui _socket_.

### 32. Fungsi `update_channel_auth_files`
```
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
```
Fungsi ini memperbarui file otentikasi di semua _channel_ ketika nama pengguna diubah. Fungsi menelusuri semua direktori _channel_, membuka file otentikasi, dan memperbarui nama pengguna yang sesuai. Perubahan disimpan ke file sementara, kemudian file asli diganti dengan file sementara. Fungsi juga mencatat perubahan dalam file log _channel_.

### 33. Fungsi `edit_user_name`
```
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
```
Mengubah nama pengguna dalam file pengguna. Fungsi membaca file pengguna > Mencari pengguna yang sesuai > memperbarui namanya. Perubahan disimpan ke file sementara, kemudian file asli diganti dengan file sementara. Fungsi juga memperbarui file otentikasi _channel_ dan mengirim konfirmasi ke klien.

### 34. Fungsi `edit_user_name_other`
```
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
```
Mirip dengan edit_user_name, tetapi digunakan oleh pengguna _root_ untuk mengubah nama pengguna lain. Fungsi membaca file pengguna, mencari pengguna yang sesuai, dan memperbarui namanya. Perubahan disimpan dan file otentikasi channel diperbarui. Fungsi mengirim konfirmasi ke klien.

### 35. Fungsi `edit_user_password`
```
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
```
_Logic_ mirip `edit_user_name` namun untuk mengubah _password_ pengguna.

### 36. Fungsi `remove_user_from_channel_auth`
```
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
```
Akan menghapus pengguna dari file otentikasi semua _channel_. Fungsi menelusuri semua direktori channel, membuka file otentikasi, dan menghapus entri pengguna yang sesuai. Perubahan disimpan dan dicatat dalam file log channel.

### 37. Fungsi `remove_user`
```
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
```
Fungsi ini menghapus pengguna dari file pengguna dan semua file otentikasi channel. Fungsi membaca file pengguna, menghapus entri pengguna yang sesuai, dan menyimpan perubahan. Fungsi juga memanggil `remove_user_from_channel_auth` untuk menghapus pengguna dari semua _channel_. Konfirmasi dikirim ke klien.

### 38. Fungsi `ban_user`
```
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
```
Fungsi ini mem-_ban_ pengguna dari _channel_ tertentu. Fungsi membaca file otentikasi channel, mencari pengguna yang sesuai, dan mengubah perannya menjadi "BANNED". Perubahan disimpan dan dicatat dalam file log channel. Konfirmasi dikirim ke klien.

### 39. Fungsi `unban_user`
```
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
```
Fungsi ini membatalkan _ban_ pengguna dari channel tertentu. Fungsi membaca file otentikasi _channel_, mencari pengguna yang sesuai, dan mengubah perannya kembali menjadi "USER". Perubahan disimpan dan dicatat dalam file log channel. Konfirmasi dikirim ke klien.

### 40. Fungsi `create_channel`
```
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
```
Fungsi ini membuat _channel_ baru. Fungsi memeriksa apakah _channel_ sudah ada, membuat entri baru dalam file _channel_, membuat direktori channel dan admin, serta membuat file otentikasi _channel_. Fungsi juga menambahkan pengguna yang membuat _channel sebagai admin atau root. Konfirmasi dikirim ke klien.

### 41. Fungsi `edit_channel`
```
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
```
Fungsi ini akan mengubah nama _channel_ yang ada. Fungsi membaca file channel, mencari channel yang sesuai, dan memperbarui namanya. Setelah memperbarui file _channel_, fungsi juga mengubah nama direktori _channel_. Fungsi mencatat perubahan dalam log dan mengirim konfirmasi ke klien.

### 42. Fungsi `delete_channel`
```
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
```
Fungsi ini menghapus _channel_ yang ada. Fungsi membaca file _channel_, menghapus entri _channel_ yang sesuai, dan menyimpan perubahan. Setelah memperbarui file _channel_, fungsi juga menghapus direktori channel beserta seluruh isinya. Fungsi mengirim konfirmasi ke klien.

### 43. Fungsi `join_channel`
```
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
```
Fungsi ini menambahkan pengguna ke _channel_. Jika pengguna sudah menjadi anggota, fungsi hanya mencatat aksi join. Jika pengguna baru, fungsi menambahkan pengguna ke file otentikasi _channel_ dengan peran yang sesuai. Fungsi mencatat aksi join dalam log dan mengirim konfirmasi ke klien.

### 44. Fungsi `kick_user`
```
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
```
Fungsi ini mengeluarkan pengguna dari _channel_. Fungsi membaca file otentikasi _channel_, menghapus entri pengguna yang sesuai, dan menyimpan perubahan. Fungsi mencatat aksi kick dalam log dan mengirim konfirmasi ke klien.

### 45. Fungsi `list_channels`
```
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
```
Fungsi ini menunjukkan daftar semua _channel_ yang ada. Fungsi membaca direktori DiscorIT dan mengumpulkan nama semua subdirektori (kecuali "." dan "..") sebagai nama _channel_.

### 46. Fungsi `create_room`
```
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
```
Fungsi ini membuat _room_ baru dalam channel. Fungsi membuat direktori _room_ baru dan file chat kosong di dalamnya.

### 47. Fungsi `join_room`
```
void join_room(int socket, const char *username, const char *channel, const char *room) {
    char line[BUF_SIZE];
    sprintf(line, "%s masuk ke room %s", username, room);
    log_action(channel, line);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "%s bergabung dengan room %s", username, room);
    write(socket, response, strlen(response));
}
```
Mencatat aksi pengguna bergabung ke _room_. Fungsi mencatat aksi join dalam log channel dan mengirim konfirmasi ke klien.

### 48. Fungsi `list_rooms`
```
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
```
Fungsi dan _logic_nya mirip `list_channels` namun untuk _room_.

### 49. Fungsi `edit_room`
```
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
```
Fungsi ini mengubah nama _room_ yang ada lalu mencatat perubahan dalam log _channel_ dan mengirim konfirmasi ke klien.

### 50. Fungsi `delete_room`
```
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
```
Fungsi ini menghapus _room_ yang ada. Fungsi menghapus direktori _room_ beserta seluruh isinya. Fungsi mencatat penghapusan _room_ dalam log _channel_ dan mengirim konfirmasi ke klien.

### 51. Fungsi `delete_all_rooms`
```
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
```
Fungsi ini memulai proses penghapusan semua _room_ dalam channel. Fungsi membuka direktori _channel_ untuk iterasi lebih lanjut.

### 52. Fungsi `sanitize_string`
```
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
```
_Function_ ini membersihkan string input dari karakter koma dan newline. Ia menyalin karakter-karakter yang valid ke dalam buffer output, memastikan tidak melebihi ukuran buffer yang ditentukan. Function ini penting untuk mencegah injeksi data yang tidak diinginkan ke dalam file CSV. Hasil akhirnya adalah string yang aman untuk disimpan dalam format CSV.

### 53. Fungsi `chat`
```
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
```
_Function_ ini menangani pengiriman pesan chat baru. Ia membuka file chat yang sesuai, menentukan ID chat berikutnya, dan menambahkan entri baru dengan _timestamp_. _Function_ ini menggunakan `sanitize_string` untuk membersihkan _username_ dan pesan sebelum menyimpannya. Setelah menyimpan pesan, ia mengirimkan konfirmasi ke client dan mencatat aksi tersebut dalam log.

### 54. Fungsi `edit_chat`
```
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
```
_Function_ ini memungkinkan pengeditan pesan chat yang ada. Ia membaca file chat yang ada, mencari pesan dengan ID yang sesuai, dan menggantinya dengan pesan baru yang telah disanitasi. _Function_ ini menggunakan file sementara untuk menyimpan perubahan sebelum menggantikan file asli. Jika berhasil, ia mengirimkan konfirmasi ke client dan mencatat perubahan dalam log.

### 55. Fungsi `delete_chat`
```
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
```
_Function_ ini menghapus pesan chat tertentu berdasarkan ID-nya. Ia membaca file chat, menyalin semua pesan kecuali yang akan dihapus ke file sementara. _Function_ ini menangani kemungkinan adanya baris _header_ dalam file CSV. Setelah penghapusan selesai, file asli diganti dengan file sementara dan konfirmasi dikirim ke client.

### 56. Fungsi `see_chat`
```
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
```
_Function_ ini menampilkan isi chat dari file chat yang ditentukan. Ia membaca file baris per baris, memparse setiap baris menjadi komponen-komponennya (ID, timestamp, username, pesan), dan memformatnya ke dalam string `response`. _Function_ ini menangani kemungkinan overflow buffer dengan membatasi jumlah pesan yang ditampilkan. Hasil akhirnya dikirim ke client melalui socket.

## discorit.c
### 1. _Header_ dan Deklarasi
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <crypt.h>

#define PORT 8080
#define BUF_SIZE 1024

void handle_commands(int sock, const char *username);
```
Kumpulan header library yang kami gunakan untuk mengerjakan _final project_ ini. Dilanjut dengan pendefinisian `PORT` untuk koneksi _socket_ serta ukuran _buffer_, fungsi `handle_commands` akan menangani _input_ pengguna setelah _login_.

### 2. Fungsi `main` untuk Menginisialisasi _Socket_ dan Registrasi Pengguna
```
int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s REGISTER|LOGIN username -p password\n", argv[0]);
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

    if (strcmp(argv[1], "REGISTER") == 0) {
        snprintf(buffer, sizeof(buffer), "REGISTER %s -p %s", username, password);
        send(sock, buffer, strlen(buffer), 0);
        read(sock, buffer, BUF_SIZE);
        printf("%s\n", buffer);
    } else if (strcmp(argv[1], "LOGIN") == 0) {
        snprintf(buffer, sizeof(buffer), "LOGIN %s -p %s", username, password);
        send(sock, buffer, strlen(buffer), 0);
        read(sock, buffer, BUF_SIZE);
        if (strstr(buffer, "berhasil login")) {
            printf("%s\n", buffer);
            handle_commands(sock, username);
        } else {
            printf("Login gagal\n");
        }
    } else {
        fprintf(stderr, "Invalid command. Use REGISTER or LOGIN.\n");
    }

    close(sock);
    return 0;
}
```
Fungsi tersebut bertujuan menangani _command line_ registrasi dan _login_ pengguna dengan menginisialisasi koneksi _socket_ ke **server.c**, mengirim perintah `REGISTER` juga `LOGIN`, dan menangani respons _server_. Jika proses login berhasil, maka akan memanggil `handle_command` untuk mengelola interaksi pengguna selanjutnya. Di sisi lain, fungsi tersebut juga menangani _error_ koneksi dan memastikan _socket_ ditutup sebelum program berakhir.

### 3. Fungsi untuk Menampilkan _Prompt_ sesuai Konteks Pengguna
```
void handle_channel_prompt(int sock, const char *username, const char *channel) {
    char buffer[BUF_SIZE];
    snprintf(buffer, sizeof(buffer), "%s/%s", username, channel);
    printf("[%s] ", buffer);
    fflush(stdout);
}

void handle_room_prompt(int sock, const char *username, const char *channel, const char *room) {
    char buffer[BUF_SIZE];
    snprintf(buffer, sizeof(buffer), "%s/%s/%s", username, channel, room);
    printf("[%s] ", buffer);
    fflush(stdout);
}
```
Fungsi `handle_channel_prompt` berguna untuk menampilkan _prompt_ ketika pengguna berada di dalam _"channel"_, sedangkan `handle_room_prompt` untuk menampilkan _prompt_ di dalam _"room"_. _Prompt_ akan berguna bagi pengguna untuk memahami konteks struktur DiscorIT dengan menampilkan kombinasi _username_, _channel_, dan _room_.

### 4. Fungsi `handle_commands`
```
void handle_commands(int sock, const char *username) {
    char buffer[BUF_SIZE];
    char channel[BUF_SIZE] = "";
    char key[BUF_SIZE];
    char room[BUF_SIZE] = "";
    int key_prompt = 0;
    int in_channel = 0;
    int in_room = 0;
    char new_username[BUF_SIZE];
```
Merupakan inti dari interaksi pengguna dalam DiscorIT dengan mengelola _loop_ utama yang terus menerima _input_ dari user, menghubungkannya ke **server.c**, dan menangani respons sesuai _state_ pengguna seperti `JOIN` atau `EXIT` serta memperbarui informasi lokal seperti _username_, nama _channel_, nama _room_, dan pesan.
```
    while (1) {
        if (in_channel && in_room) {
            handle_room_prompt(sock, username, channel, room);
        } else if (in_channel) {
            handle_channel_prompt(sock, username, channel);
        } else if (key_prompt) {
            printf("Key: ");
            fflush(stdout);
            key_prompt = 0;
        } else {
            printf("[%s] ", username);
        }
```
Logika untuk menampilkan _prompt_ kepada pengguna sesuai _state user_ (apakah sedang berada di _channel_ atau _room_ atau memerlukan _input key_) lalu akan memanggilnya. Vital untuk pengguna agar mereka selalu memiliki konteks visual tentang posisi mereka dalam struktur DisorIT.
```
fgets(buffer, BUF_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0; // Remove newline character

        if (strcmp(buffer, "EXIT") == 0) {
            if (in_room) {
                send(sock, buffer, strlen(buffer), 0);
                in_room = 0;
                memset(room, 0, sizeof(room));
            } else if (in_channel) {
                send(sock, buffer, strlen(buffer), 0);
                in_channel = 0;
                memset(channel, 0, sizeof(channel));
            } else {
                send(sock, buffer, strlen(buffer), 0);
                break;
            }

            memset(buffer, 0, sizeof(buffer));
            int bytes_read = read(sock, buffer, BUF_SIZE);
            buffer[bytes_read] = '\0';

            if (strstr(buffer, "Keluar Room")) {
                printf("%s\n", buffer);
            } else if (strstr(buffer, "Keluar Channel")) {
                printf("%s\n", buffer);
            } else {
                printf("%s\n", buffer);
            }
        } else {
            char command[BUF_SIZE];
            sscanf(buffer, "%s", command);

            if (strcmp(command, "JOIN") == 0) {
                char arg[BUF_SIZE];
                sscanf(buffer, "%*s %s", arg);

                if (in_channel) {
                    // Join room
                    snprintf(buffer, sizeof(buffer), "JOIN %s", arg);
                    in_room = 1;
                } else {
                    // Join channel
                    snprintf(buffer, sizeof(buffer), "JOIN %s", arg);
                }
            }

            send(sock, buffer, strlen(buffer), 0);

            memset(buffer, 0, sizeof(buffer));
            int bytes_read = read(sock, buffer, BUF_SIZE);
            buffer[bytes_read] = '\0';

            if (strstr(buffer, "bergabung dengan channel")) {
                char *channel_name = strstr(buffer, "bergabung dengan channel ") + strlen("bergabung dengan channel ");
                strcpy(channel, channel_name);
                in_channel = 1;
            } else if (strstr(buffer, "bergabung dengan room")) {
                char *room_name = strstr(buffer, "bergabung dengan room ") + strlen("bergabung dengan room ");
                strcpy(room, room_name);
                in_room = 1;
            } else if (strstr(buffer, "Key: ")) {
                key_prompt = 1;
            } else if (strstr(buffer, "Keluar Channel")) {
                in_channel = 0;
                memset(channel, 0, sizeof(channel));
            } else if (strstr(buffer, "Keluar Room")) {
                in_room = 0;
                memset(room, 0, sizeof(room));
            } else if (strstr(buffer, "Channel tidak ditemukan")) {
                printf("%s\n", buffer);
                memset(channel, 0, sizeof(channel));
                in_channel = 0;
            } else if (strstr(buffer, "Anda dibanned dari channel ini")) {
                printf("%s\n", buffer);
                memset(channel, 0, sizeof(channel));
                in_channel = 0;
            } else if (strstr(buffer, "Room tidak ditemukan")) {
                printf("%s\n", buffer);
                memset(room, 0, sizeof(room));
                in_room = 0;
            } else if (strstr(buffer, "berhasil diubah menjadi")){
                char *new_username = strstr(buffer, "berhasil diubah menjadi ") + strlen("berhasil diubah menjadi ");
                strcpy(username, new_username);
            } else if (strstr(buffer, "nama room berubah menjadi")){
                char *new_room = strstr(buffer, "nama room berubah menjadi ") + strlen("nama room berubah menjadi ");
                strcpy(room, new_room);
            } else if (strstr(buffer, "nama channel berubah menjadi")){
                char *new_channel = strstr(buffer, "nama channel berubah menjadi ") + strlen("nama channel berubah menjadi ");
                strcpy(channel, new_channel);
            } else if (strstr(buffer, "Chat Baru")) {
                printf("%s\n", buffer);
                memset(buffer, 0, sizeof(buffer));
            } else if (strstr(buffer, "Chat Diubah")) {
                printf("%s\n", buffer);
                memset(buffer, 0, sizeof(buffer));
            } else if (strstr(buffer, "Chat Dihapus")) {
                printf("%s\n", buffer);
                memset(buffer, 0, sizeof(buffer));
            } else {
                printf("%s\n", buffer);
            }
        }
    }
}
```
_Loop_ utama yang menangani _input_ pengguna serta interaksi dengan **server.c**. Prosesnya adalah membaca _input_ pengguna > mengirimkannya ke _server_ > memprosesnya. Terdapat beberapa respons seperti _username_, nama _channel_ atau _room_, pesan baru, pesan yang diubah atau yang telah dihapus.

## monitor.c
berfungsi sebagai klien chat yang dapat menghubungkan diri ke server, login dengan menggunakan username dan password, dan memantau percakapan dalam chat room tertentu
### Definisi Konstanta dan Struktur
````
#define PORT 8080
#define BUF_SIZE 1024
#define DISCORIT_DIR "/home/ax3lrod/sisop/fp/DiscorIT"

typedef struct {
    char channel[BUF_SIZE];
    char room[BUF_SIZE];
    int sock;
} ChatMonitorArgs;

````
PORT adalah port yang digunakan untuk koneksi ke server.
BUF_SIZE adalah ukuran buffer yang digunakan untuk berbagai operasi string.
DISCORIT_DIR adalah direktori tempat file chat disimpan.
ChatMonitorArgs adalah struktur yang digunakan untuk menyimpan argumen yang dilewatkan ke thread pemantauan chat.


### Fungsi 'display-chat'
````
void display_chat(const char *channel, const char *room) {
    // ...
}

````
Fungsi ini membaca file chat CSV untuk channel dan room tertentu, kemudian menampilkan isinya ke layar.

### Fungsi 'monitor_chat'
````
void *monitor_chat(void *arg) {
    // ...
}
````
Fungsi ini dijalankan dalam thread terpisah untuk memantau perubahan file chat. Jika file chat berubah (diperbarui), fungsi ini akan memanggil display_chat untuk menampilkan isi chat yang terbaru.

### Fungsi 'handle_commands"
````
void handle_commands(int sock, const char *username) {
    // ...
}
````
Fungsi ini menangani perintah yang diterima dari server. Termasuk memulai thread pemantauan chat jika channel dan room berubah, dan menampilkan pesan dari server.

### Fungsi 'main"
````
int main(int argc, char *argv[]) {
    // ...
}
````
Fungsi ini adalah titik masuk program.
Memeriksa argumen program untuk login (LOGIN username -p password).
Menginisialisasi socket dan menghubungkan ke server.
Mengirim perintah login ke server dan membaca responsnya.
Jika login berhasil, fungsi handle_commands dipanggil untuk menangani interaksi lebih lanjut dengan server.

### Alur Program Utama:

Program memeriksa argumen command line untuk login.
Membuat socket dan menghubungkan ke server.
Mengirimkan perintah login ke server dan menunggu respons.
Jika login berhasil, program menunggu perintah dari server, termasuk perintah untuk mengganti channel dan room, serta perintah untuk keluar.
Jika channel dan room baru diterima, program memulai thread untuk memantau perubahan pada file chat dan menampilkan isi chat.

### Pemantauan dan Tampilan Chat:

Thread pemantauan (dijalankan oleh monitor_chat) akan terus memeriksa perubahan pada file chat setiap detik.
Jika ada perubahan, isi chat akan dibaca ulang dan ditampilkan ke layar dengan fungsi display_chat.

### Penghentian Program:

Jika perintah EXIT diterima dari server, atau jika thread pemantauan diakhiri, program akan keluar dari loop dan menutup socket sebelum berhenti.

Secara keseluruhan, kode ini berfungsi sebagai client untuk memonitor dan menampilkan pesan chat dari server dalam format yang terstruktur menggunakan thread untuk pemantauan file chat yang berubah.
