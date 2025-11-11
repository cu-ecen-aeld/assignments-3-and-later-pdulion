#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <features.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include <linux/limits.h>

#define ACCEPT_BACKLOG 10

const char *DATA_FILE = "/var/tmp/aesdsocketdata";
const int INET_BLOCK_SIZE = 1024;

int exit_code = EXIT_FAILURE;
int fd_listen = -1;
int fd_client = -1;
int fd_write = -1;

int init_server() {
    int fd = -1;
    int rc;
    struct addrinfo hints = {0}, *info;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rc = getaddrinfo(NULL, "9000", &hints, &info)) != 0) {
        syslog(LOG_ERR, "Error retrieving host address: %s", gai_strerror(rc));
        goto exit_init;
    }

    for (struct addrinfo *entry = info; entry != NULL; entry = entry->ai_next) {
        int yes = 1;

        if ((fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol)) == -1) {
            syslog(LOG_WARNING, "Could not create socket: %s", strerror(errno));
            continue;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            syslog(LOG_ERR, "Failed setting socket options: %s", strerror(errno));
            close(fd);
            continue;
        }

        if (bind(fd, entry->ai_addr, entry->ai_addrlen) == -1) {
            close(fd);
            syslog(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
            continue;
        }

        break;
    }

    freeaddrinfo(info);

exit_init:
    return fd;
}

void handle_signals(int signum) {
    const int old_errno = errno;

    if (signum == SIGCHLD) {
        while (waitpid(-1, NULL, WNOHANG) > 0);
    } else if (signum == SIGINT || signum == SIGTERM) {
        if (fd_client != -1) shutdown(fd_client, SHUT_RDWR);
        if (fd_listen != -1) shutdown(fd_listen, SHUT_RDWR);
        if (fd_write != -1) {
            close(fd_write);
            fd_write = -1;
        }

        exit_code = EXIT_SUCCESS;
    }

    errno = old_errno;
}

int init_signals() {
    struct sigaction sa;

    sa.sa_handler = handle_signals;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &sa, NULL) == -1) return -1;
    if (sigaction(SIGTERM, &sa, NULL) == -1) return -1;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) return -1;
    return 0;
}

void *get_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &((struct sockaddr_in *) sa)->sin_addr;
    }
    return &((struct sockaddr_in6 *) sa)->sin6_addr;
}

void log_client_ip(struct sockaddr_storage *client_addr) {
    void *addr;
    char client_ip[INET6_ADDRSTRLEN];

    if (client_addr->ss_family == AF_INET) {
        addr = &((struct sockaddr_in *) client_addr)->sin_addr;
    } else {
        addr = &((struct sockaddr_in6 *) client_addr)->sin6_addr;
    }
    inet_ntop(client_addr->ss_family, addr, client_ip, sizeof client_ip);
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);
}

void close_fd(int *fd) {
    sigset_t new_mask;
    sigset_t old_mask;

    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGINT);
    sigaddset(&new_mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) == -1) {
        syslog(LOG_ERR, "Signal block failed: %s", strerror(errno));
    }

    if (*fd != -1) {
        close(*fd);
        *fd = -1;
    }

    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1) {
        syslog(LOG_ERR, "Signal restoration failed: %s", strerror(errno));
    }
}

void handle_client() {
    size_t bytes_in, bytes_out;

    char *buf = malloc(INET_BLOCK_SIZE + 1);
    if (buf == NULL) {
        goto exit_start;
    }

    int block_count = 0;
    size_t received = 0;
    size_t capacity = INET_BLOCK_SIZE;
    buf[0] = '\0';
    while ((bytes_in = recv(fd_client, buf + received, capacity, 0)) != 0) {
        if (bytes_in == -1) {
            syslog(LOG_ERR, "Error while receiving data: %s", strerror(errno));
            goto exit_receiving;
        }

        buf[received + bytes_in] = '\0';
        if (strchr(buf + received, '\n')) {
            break;
        }
        received += bytes_in;

        if (bytes_in < capacity) {
            capacity -= bytes_in;
            continue;
        }

        char *tmp;
        if ((tmp = realloc(buf, ++block_count * INET_BLOCK_SIZE + 1)) == NULL) {
            syslog(LOG_ERR, "Failed buffer expansion: %s", strerror(errno));
            goto exit_receiving;
        }
        buf = tmp;
        capacity = INET_BLOCK_SIZE;
    }

    if (write(fd_write, buf, strlen(buf)) == -1) {
        syslog(LOG_ERR, "Error while writing to temp file: %s", strerror(errno));
        goto exit_receiving;
    }

    int fd_read = open(DATA_FILE, O_RDONLY);
    capacity = block_count * INET_BLOCK_SIZE;
    while ((bytes_in = read(fd_read, buf, capacity)) != 0) {
        if (bytes_in == -1) {
            if (errno == EINTR) continue;;
            syslog(LOG_ERR, "Unable to read from data file: %s", strerror(errno));
            goto exit_sending;
        }

        size_t sent = 0;
        while (sent < bytes_in) {
            bytes_out = send(fd_client, buf + sent, bytes_in - sent, 0);
            if (bytes_out == -1) {
                syslog(LOG_ERR, "Unable to send from data file: %s", strerror(errno));
                goto exit_sending;
            }
            if (bytes_out == 0) {
                syslog(LOG_WARNING, "Client disconnected");
                break;
            }
            sent += bytes_out;
        }
    }

    exit_code = EXIT_SUCCESS;

exit_sending:
    close(fd_read);

exit_receiving:
    free(buf);

exit_start:
    close_fd(&fd_client);
    close_fd(&fd_write);
    exit(exit_code);
}

void run_server() {
    struct sockaddr_storage client_addr;
    socklen_t client_len;

    syslog(LOG_INFO, "Waiting for connections");

    while (true) {
        client_len = sizeof(client_addr);
        fd_client = accept(fd_listen, (struct sockaddr *) &client_addr, &client_len);
        if (fd_client == -1) {
            if (errno == EINTR) {
                continue;
            }
            syslog(LOG_INFO, "Accept failed, exiting");
            return;
        }

        log_client_ip(&client_addr);
        pid_t pid = fork();
        if (pid == -1) {
            syslog(LOG_ERR, "Fork failed: %s", strerror(errno));
            close_fd(&fd_client);
            return;
        }

        if (pid > 0) {
            // Detach parent's reference to client_fd
            close_fd(&fd_client);
        } else {
            // Detach child's reference to listen_fd
            close_fd(&fd_listen);
            handle_client();
        }
    }
}

int main(int argc, char *argv[]) {
    openlog("aesdsocket", 0, LOG_USER);

    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        pid_t pid = fork();
        if (pid == -1) {
            syslog(LOG_ERR, "Fork failed: %s", strerror(errno));
            goto exit_syslog;
        }
        if (pid > 0) {
            exit_code = EXIT_SUCCESS;
            goto exit_syslog;
        }
        if (setsid() == -1) {
            syslog(LOG_ERR, "Failed to create new session and process group: %s", strerror(errno));
            goto exit_syslog;
        }
        if (chdir("/") == -1) {
            syslog(LOG_ERR, "Failed to change directory to /");
            goto exit_syslog;
        }
        for (int i = 0; i < NR_OPEN; i++) close(i);
        open("/dev/null", O_RDWR);
        dup(STDIN_FILENO);
        dup(STDIN_FILENO);
    }

    fd_listen = init_server();
    if (fd_listen == -1) {
        syslog(LOG_ERR, "Unable to bind to host port");
        goto exit_data_fd;
    }

    if (init_signals() == -1) {
        syslog(LOG_ERR, "Unable to configure signal handling: %s", strerror(errno));
        goto exit_server_fd;
    }

    if ((fd_write = creat(DATA_FILE, 0644)) == -1) {
        syslog(LOG_ERR, "Unable to create socket data file: %s", strerror(errno));
        goto exit_syslog;
    }

    if (listen(fd_listen, ACCEPT_BACKLOG) == -1) {
        syslog(LOG_ERR, "Unable to listen: %s", strerror(errno));
        goto exit_server_fd;
    }

    run_server();

exit_data_fd:
    close_fd(&fd_write);
    if (remove(DATA_FILE) == -1) {
        syslog(LOG_ERR, "Unable to remove data file: %s", strerror(errno));
    }

exit_server_fd:
    close_fd(&fd_listen);

exit_syslog:
    syslog(LOG_INFO, "Exiting");
    closelog();

    // Set to EXIT_SUCCESS by SIGTERM and SIGINT in handle_signals()
    return exit_code;
}
