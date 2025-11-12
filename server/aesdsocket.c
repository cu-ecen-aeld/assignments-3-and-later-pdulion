#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#define ACCEPT_BACKLOG 10

static const char *DATA_FILE = "/var/tmp/aesdsocketdata";
static const size_t INET_BLOCK_SIZE = 1024;

volatile sig_atomic_t g_shutdown = false;
int listener_fd = -1;

static int daemonize() {
    pid_t pid = fork();
    if (pid == -1) {
        syslog(LOG_ERR, "Failed to create daemon process: %s", strerror(errno));
        return -1;
    }
    if (pid > 0) {
        // Parent: Daemon successfully created
        closelog();

        // Sleep a moment before exiting to make sure child is listening
        sleep(1);
        _exit(EXIT_SUCCESS);
    }

    // Child: Configure for Daemon mode!
    if (setsid() == -1) {
        syslog(LOG_ERR, "Failed to create new session and process group: %s", strerror(errno));
        return -1;
    }

    umask(0);
    if (chdir("/") == -1) {
        syslog(LOG_ERR, "Failed changing to root directory: %s", strerror(errno));
        return -1;
    }

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
        syslog(LOG_ERR, "Failed limit for open files: %s", strerror(errno));
        return -1;
    }
    for (int i = 0; i < (int) rl.rlim_max; i++) close(i);

    const int fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        syslog(LOG_ERR, "Failed to open /dev/null: %s", strerror(errno));
        return -1;
    }
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO) close(fd);

    return 0;
}

static void shutdown_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        // Signal triggers EINTR during accept
        g_shutdown = true;
    }
}

static void child_exit_handler(int signum) {
    // Do nothing, Let EINTR handle cleanup
}

static int init_signals() {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = shutdown_handler;
    if (sigaction(SIGINT, &sa, NULL) == -1) return -1;
    if (sigaction(SIGTERM, &sa, NULL) == -1) return -1;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = child_exit_handler;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) return -1;

    // Ignore SIGPIPE whenever child breaks its connection
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) return -1;
    return 0;
}

static int open_listener() {
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
            fd = -1;
            continue;
        }

        if (bind(fd, entry->ai_addr, entry->ai_addrlen) == -1) {
            syslog(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
            close(fd);
            fd = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(info);

exit_start:
    return fd;
}

static void close_listener() {
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

static void reap_children(int options) {
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, options)) > 0) {
        if (WIFEXITED(status)) {
            syslog(LOG_INFO, "Child process %d exited with status %d", pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            syslog(LOG_INFO, "Child process %d was terminated by signal %d", pid, WTERMSIG(status));
        } else if (WIFSTOPPED(status)) {
            syslog(LOG_INFO, "Child process %d was stopped by signal %d", pid, WSTOPSIG(status));
        } else {
            syslog(LOG_WARNING, "Child process %d did not exit successfully", pid);
        }
    }
}

static void await_child_processes() {
    sigset_t new_mask;
    sigset_t old_mask;

    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) == -1) {
        syslog(LOG_ERR, "Signal block failed: %s", strerror(errno));
    }

    reap_children(0);

    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1) {
        syslog(LOG_ERR, "Signal restoration failed: %s", strerror(errno));
    }
}

static void connection_handler(const int fd_client, const char *client_host) {
    int exit_code = EXIT_FAILURE;
    syslog(LOG_INFO, "Accepted connection from %s", client_host);

    size_t capacity = INET_BLOCK_SIZE;
    char *buf = malloc(capacity);
    if (!buf) {
        syslog(LOG_ERR, "Failed buffer allocation: %s", strerror(errno));
        goto exit_start;
    }

    size_t pkt_len = 0;
    for (;;) {
        ssize_t recv_len = recv(fd_client, buf + pkt_len, capacity - pkt_len, 0);
        if (recv_len == -1) {
            if (errno == EINTR) continue;
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
        syslog(LOG_ERR, "Unable to lock data file: %d - %s", errno, strerror(errno));
        goto exit_file;
    }

    for (size_t written = 0; written < pkt_len;) {
        const ssize_t write_len = write(fd_data, buf + written, pkt_len - written);
        if (write_len == -1) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "Unable to write to data file: %d - %s", errno, strerror(errno));
            goto exit_lock;
        }
        written += write_len;
    }

    if (lseek(fd_data, 0, SEEK_SET) == -1) {
        syslog(LOG_ERR, "Unable to move to start of file: %s", strerror(errno));
        goto exit_lock;
    }

    for (;;) {
        const ssize_t read_len = read(fd_data, buf, capacity);
        if (read_len == -1) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "Unable to read from data file: %s", strerror(errno));
            goto exit_lock;
        }
        if (read_len == 0) {
            break;
        }

        for (ssize_t sent = 0; sent < read_len;) {
            const ssize_t send_len = send(fd_client, buf + sent, read_len - sent, 0);
            if (send_len == -1) {
                if (errno == EINTR) continue;
                syslog(LOG_ERR, "Unable to send from data file: %s", strerror(errno));
                goto exit_lock;
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
    _exit(exit_code);
}

static void run_server() {
    struct sockaddr_storage client_addr;
    socklen_t client_len;

    syslog(LOG_INFO, "Waiting for connections");
    while (!g_shutdown) {
        client_len = sizeof(client_addr);
        const int client_fd = accept(listener_fd, (struct sockaddr *) &client_addr, &client_len);
        if (client_fd == -1) {
            if (errno == EINTR) {
                reap_children(WNOHANG);
                continue;
            }
            if (errno == ECONNABORTED || errno == EPROTO || errno == ENETDOWN) {
                syslog(LOG_WARNING, "Accept transient error: %s", strerror(errno));
                continue;
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
            void *addr;
            if (client_addr.ss_family == AF_INET) {
                addr = &((struct sockaddr_in *) &client_addr)->sin_addr;
            } else {
                addr = &((struct sockaddr_in6 *) &client_addr)->sin6_addr;
            }

            char client_ip[INET6_ADDRSTRLEN];
            if (!inet_ntop(client_addr.ss_family, addr, client_ip, sizeof(client_ip))) {
                memset(client_ip, 0, sizeof(client_ip));
                strncpy(client_ip, "unknown", sizeof(client_ip));
            }

            close_listener();
            connection_handler(client_fd, client_ip);
        }
    }
}

int main(int argc, char *argv[]) {
    int exit_code = EXIT_FAILURE;
    openlog("aesdsocket", LOG_PID, LOG_USER);

    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        if (daemonize() == -1) {
            goto exit_start;
        }
    }

    if (init_signals() == -1) {
        syslog(LOG_ERR, "Unable to configure signal handling: %s", strerror(errno));
        goto exit_start;
    }

    listener_fd = open_listener();
    if (listener_fd == -1) {
        syslog(LOG_ERR, "Unable to bind to host port");
        goto exit_start;
    }

    if (listen(listener_fd, ACCEPT_BACKLOG) == -1) {
        syslog(LOG_ERR, "Unable to listen for connections: %s", strerror(errno));
        goto exit_server_init;
    }

    run_server();
    await_child_processes();
    if (g_shutdown) {
        syslog(LOG_INFO, "Caught signal, exiting");
        exit_code = EXIT_SUCCESS;
        if (remove(DATA_FILE) == -1 && errno != ENOENT) {
            syslog(LOG_ERR, "Unable to remove %s: %s", DATA_FILE, strerror(errno));
        }
    }

exit_server_init:
    close_listener();

exit_start:
    closelog();

    // Set to EXIT_SUCCESS by SIGTERM and SIGINT in handle_signals()
    return exit_code;
}
