#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <features.h>
#include <linux/limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#define ACCEPT_BACKLOG 10

const char *DATA_FILE = "/var/tmp/aesdsocketdata";
const int INET_BLOCK_SIZE = 1024;

bool is_shutdown = false;
int listener_fd = -1;

int init_server() {
    int fd = -1;
    int rc;
    struct addrinfo hints = {0}, *info;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rc = getaddrinfo(NULL, "9000", &hints, &info)) != 0) {
        syslog(LOG_ERR, "Error retrieving host address: %s", gai_strerror(rc));
        goto exit_start;
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

exit_start:
    return fd;
}

void signal_handler(int signum) {
    const int old_errno = errno;

    if (signum == SIGCHLD) {
        while (waitpid(-1, NULL, WNOHANG) > 0);
    } else if (signum == SIGINT || signum == SIGTERM) {
        is_shutdown = true;
        if (listener_fd >= 0) shutdown(listener_fd, SHUT_RDWR);
    }

    errno = old_errno;
}

int init_signals() {
    struct sigaction sa;

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &sa, NULL) == -1) return -1;
    if (sigaction(SIGTERM, &sa, NULL) == -1) return -1;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) return -1;
    return 0;
}

void close_listener_fd() {
    sigset_t new_mask;
    sigset_t old_mask;

    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGINT);
    sigaddset(&new_mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) == -1) {
        syslog(LOG_ERR, "Signal block failed: %s", strerror(errno));
    }

    if (listener_fd != -1) {
        close(listener_fd);
        listener_fd = -1;
    }

    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1) {
        syslog(LOG_ERR, "Signal restoration failed: %s", strerror(errno));
    }
}

void await_child_processes() {
    sigset_t new_mask;

    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &new_mask, NULL) == -1) {
        syslog(LOG_ERR, "Signal block failed: %s", strerror(errno));
    }

    while (waitpid(-1, NULL, 0) > 0) {
    }
}

void connection_handler(int fd_client, char *client_host) {
    int exit_code = EXIT_FAILURE;
    syslog(LOG_INFO, "Accepted connection from %s", client_host);

    ssize_t capacity = INET_BLOCK_SIZE;
    char *buf = malloc(capacity);
    if (!buf) {
        syslog(LOG_ERR, "Failed buffer allocation: %s", strerror(errno));
        goto exit_start;
    }

    ssize_t pkt_len = 0, recv_len;
    for (;;) {
        recv_len = recv(fd_client, buf + pkt_len, capacity - pkt_len, 0);
        if (recv_len == -1) {
            if (errno == EINTR) continue;;
            syslog(LOG_ERR, "Error while receiving data: %s", strerror(errno));
            goto exit_buffer;
        }
        if (recv_len == 0) {
            syslog(LOG_ERR, "Client closed without newline");
            goto exit_buffer;
        }

        const char *newline = memchr(buf + pkt_len, '\n', recv_len);
        if (newline) {
            // Add 1 to include newline in packet
            pkt_len = newline - buf + 1;
            break;
        }

        pkt_len += recv_len;
        if (pkt_len < capacity) {
            continue;
        }

        capacity += INET_BLOCK_SIZE;
        char *tmp = realloc(buf, capacity);
        if (!tmp) {
            syslog(LOG_ERR, "Failed buffer expansion: %s", strerror(errno));
            goto exit_buffer;
        }
        buf = tmp;
    }

    const int fd_data = open(DATA_FILE, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd_data == -1) {
        syslog(LOG_ERR, "Unable to open data file for reading: %s", strerror(errno));
        goto exit_buffer;
    }

    if (flock(fd_data, LOCK_EX) == -1) {
        syslog(LOG_ERR, "Unable to lock temp file: %d - %s", errno, strerror(errno));
        goto exit_file;
    }

    if (write(fd_data, buf, pkt_len) == -1) {
        syslog(LOG_ERR, "Unable to write to temp file: %d - %s", errno, strerror(errno));
        goto exit_lock;
    }

    if (lseek(fd_data, 0, SEEK_SET) == -1) {
        syslog(LOG_ERR, "Unable to move to start of file: %s", strerror(errno));
        goto exit_lock;
    }

    for (;;) {
        ssize_t read_len = read(fd_data, buf, capacity);
        if (read_len == -1) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "Unable to read from data file: %s", strerror(errno));
            goto exit_lock;
        }
        if (read_len == 0) {
            break;
        }

        ssize_t sent = 0;
        while (sent < read_len) {
            const ssize_t send_len = send(fd_client, buf + sent, read_len - sent, 0);
            if (send_len == -1) {
                if (errno == EINTR) continue;;
                syslog(LOG_ERR, "Unable to send from data file: %s", strerror(errno));
                goto exit_lock;
            }
            if (send_len == 0) {
                syslog(LOG_WARNING, "Client disconnected");
                break;
            }
            sent += send_len;
        }
    }

    exit_code = EXIT_SUCCESS;

exit_lock:
    flock(fd_data, LOCK_UN);

exit_file:
    close(fd_data);

exit_buffer:
    free(buf);

exit_start:
    close(fd_client);
    syslog(LOG_INFO, "Closed connection from %s", client_host);
    exit(exit_code);
}

void run_server() {
    struct sockaddr_storage client_addr;
    socklen_t client_len;

    syslog(LOG_INFO, "Waiting for connections");
    for (;;) {
        client_len = sizeof(client_addr);
        int client_fd = accept(listener_fd, (struct sockaddr *) &client_addr, &client_len);
        if (client_fd == -1) {
            if (errno == EINTR) {
                continue;
            }
            if (is_shutdown) {
                return;
            }
            syslog(LOG_INFO, "Accept failed: %s", strerror(errno));
            return;
        }

        pid_t pid = fork();
        if (pid == -1) {
            syslog(LOG_ERR, "Fork failed: %s", strerror(errno));
            close(client_fd);
            return;
        }

        if (pid > 0) {
            // Detach parent's reference to client_fd
            close(client_fd);
        } else {
            // Detach child's reference to listen_fd
            char client_host[INET6_ADDRSTRLEN];
            void *addr;
            if (client_addr.ss_family == AF_INET) {
                addr = &((struct sockaddr_in *) &client_addr)->sin_addr;
            } else {
                addr = &((struct sockaddr_in6 *) &client_addr)->sin6_addr;
            }
            inet_ntop(client_addr.ss_family, addr, client_host, sizeof(client_host));
            close_listener_fd();
            connection_handler(client_fd, client_host);
        }
    }
}

int main(int argc, char *argv[]) {
    int exit_code = EXIT_FAILURE;
    openlog("aesdsocket", 0, LOG_USER);

    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        pid_t pid = fork();
        if (pid == -1) {
            syslog(LOG_ERR, "Fork failed: %s", strerror(errno));
            goto exit_start;
        }
        if (pid > 0) {
            // Parent: Daemon successfully created
            exit_code = EXIT_SUCCESS;
            goto exit_start;
        }
        // Child: Configure for Daemon mode!
        if (setsid() == -1) {
            syslog(LOG_ERR, "Failed to create new session and process group: %s", strerror(errno));
            goto exit_start;
        }
        if (chdir("/") == -1) {
            syslog(LOG_ERR, "Failed to change directory to /");
            goto exit_start;
        }
        for (int i = 0; i < NR_OPEN; i++) close(i);
        open("/dev/null", O_RDWR);
        dup(STDIN_FILENO);
        dup(STDIN_FILENO);
    }

    listener_fd = init_server();
    if (listener_fd == -1) {
        syslog(LOG_ERR, "Unable to bind to host port");
        goto exit_server_init;
    }

    if (init_signals() == -1) {
        syslog(LOG_ERR, "Unable to configure signal handling: %s", strerror(errno));
        goto exit_server_init;
    }

    if (listen(listener_fd, ACCEPT_BACKLOG) == -1) {
        syslog(LOG_ERR, "Unable to listen for connections: %s", strerror(errno));
        goto exit_file_init;
    }

    run_server();
    if (is_shutdown) {
        syslog(LOG_INFO, "Caught signal, exiting");
        exit_code = EXIT_SUCCESS;
    }

    await_child_processes();

exit_file_init:
    if (remove(DATA_FILE) == -1) {
        syslog(LOG_ERR, "Unable to remove data file: %s", strerror(errno));
    }

exit_server_init:
    close_listener_fd();

exit_start:
    closelog();

    // Set to EXIT_SUCCESS by SIGTERM and SIGINT in handle_signals()
    return exit_code;
}
