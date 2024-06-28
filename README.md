# Sisop-FP-2024-MH-IT07

------------ Anggota Kelompok -------------

Dzaky Faiq Fayyadhi 5027231047 Kelas B

Randist Prawandha Putera 5027231059 Kelas B

Radella Chesa Syaharani 5027231064 Kelas A

# Server.c

Struktur Fungsi Main :
```
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
```
- #include mencakup berbagai header file yang diperlukan untuk operasi jaringan, threading, enkripsi, logging, dan operasi sistem file.
- #define digunakan untuk mendefinisikan konstanta seperti port server, ukuran buffer, jumlah maksimal klien, dan lokasi file yang
  menyimpan data pengguna dan saluran.
- UserLoginStatus: Menyimpan status login pengguna biasa dan monitor.
- Session: Menyimpan informasi sesi untuk setiap pengguna yang login, termasuk status login, ID pengguna, username, role, saluran dan
  ruangan saat ini, serta status monitor.
- monitorSession: Struktur untuk menyimpan status login monitor.
- Client: Menyimpan informasi untuk setiap klien yang terhubung, termasuk socket, status monitor, status login, dan username.
- logged_in_users: Array yang menyimpan status login pengguna berdasarkan ID.
- clients: Array yang menyimpan informasi klien yang terhubung.
- client_count: Menyimpan jumlah klien yang terhubung saat ini.
- Prototipe untuk berbagai fungsi yang digunakan dalam server untuk menangani klien, mengelola saluran dan ruangan, mengedit informasi      pengguna, dan mengirim pesan.
- handle_client(void *arg): Fungsi untuk menangani komunikasi dengan klien.
- bcrypt(const char *password): Fungsi untuk mengenkripsi kata sandi menggunakan bcrypt.
- Fungsi lain untuk mengelola saluran, ruangan, dan pengguna, serta untuk mengirim dan mengedit pesan.

Deskripsi Fungsi :
```
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

```
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

Fungsi remove direktory

```
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
```
