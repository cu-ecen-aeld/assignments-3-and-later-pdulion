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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#define ACCEPT_BACKLOG 10

static const uint16_t PORT = 9000;
static const char *DATA_FILE = "/var/tmp/aesdsocketdata";
static const size_t INET_BLOCK_SIZE = 1024;
static const int ENABLE = 1;
static const int STARTED = 1;
static const int STOPPED = 0;
static const int PARENT_PIPE = 0;
static const int CHILD_PIPE = 1;

volatile sig_atomic_t g_shutdown = false;
int listener_fd = -1;

static int daemonize(const char *pid_file) {
    int pipe_fds[2];
    pid_t pid;

    if (pipe(pipe_fds) == -1) {
        syslog(LOG_ERR, "Unable to create pipe for daemon child: %s", strerror(errno));
        goto exit_start;
    }

    if ((pid = fork()) == -1) {
        syslog(LOG_ERR, "Unable to create daemon process: %s", strerror(errno));
        goto exit_pipe;
    }

    if (pid > 0) {
        // Parent: Daemon child successfully created, capture pid
        if (pid_file) {
            int pid_fd = creat(pid_file, 0644);
            if (pid_fd == -1) {
                syslog(LOG_ERR, "Unable to create pid file %s: %s", pid_file, strerror(errno));
            } else {
                char buffer[32];
                const int len = snprintf(buffer, sizeof(buffer), "%d\n", pid);
                if (write(pid_fd, buffer, len) == -1) {
                    syslog(LOG_ERR, "Unable to write pid to file %s: %s", pid_file, strerror(errno));
                }
                close(pid_fd);
            }
        }

        // Wait for it to initialize
        int daemon_started = 0;
        read(pipe_fds[PARENT_PIPE], &daemon_started, sizeof(daemon_started));

        // Daemon child has indicated startup or failure, so let's return to caller
        close(pipe_fds[PARENT_PIPE]);
        close(pipe_fds[CHILD_PIPE]);
        closelog();
        _exit(daemon_started ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    // Child: Configure for Daemon mode!
    if (setsid() == -1) {
        syslog(LOG_ERR, "Unable to create new session and process group: %s", strerror(errno));
        goto exit_pipe;
    }

    umask(0);
    if (chdir("/") == -1) {
        syslog(LOG_ERR, "Unable to change to root directory: %s", strerror(errno));
        goto exit_pipe;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    const int fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        syslog(LOG_ERR, "Unable to open /dev/null: %s", strerror(errno));
        goto exit_pipe;
    }
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO) close(fd);

    close(pipe_fds[PARENT_PIPE]);
    return pipe_fds[CHILD_PIPE];

exit_pipe:
    close(pipe_fds[PARENT_PIPE]);
    close(pipe_fds[CHILD_PIPE]);

exit_start:
    return -1;
}

static void shutdown_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        // Indicate shutdown, let EINTR handle shutdown in accept loop.
        g_shutdown = true;
    }
}

static void child_exit_handler(int signum) {
    // Do nothing, let EINTR handle cleanup in accept loop.
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
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    int fd;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        syslog(LOG_WARNING, "Unable to create socket: %s", strerror(errno));
        goto exit_start;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &ENABLE, sizeof(ENABLE)) == -1) {
        syslog(LOG_ERR, "Unable to set socket options: %s", strerror(errno));
        goto exit_socket;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        syslog(LOG_ERR, "Unable to bind socket: %s", strerror(errno));
        goto exit_socket;
    }

    if (listen(fd, ACCEPT_BACKLOG) == -1) {
        syslog(LOG_ERR, "Unable to listen for connections: %s", strerror(errno));
        goto exit_socket;
    }

    return fd;

exit_socket:
    close(fd);

exit_start:
    return -1;
}

static void close_listener() {
    sigset_t new_mask;
    sigset_t old_mask;

    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGINT);
    sigaddset(&new_mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) == -1) {
        syslog(LOG_ERR, "Unable to block SIGINT & SIGTERM: %s", strerror(errno));
    }

    if (listener_fd != -1) {
        close(listener_fd);
        listener_fd = -1;
    }

    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1) {
        syslog(LOG_ERR, "Unable to unblock SIGINT & SIGTERM: %s", strerror(errno));
    }
}

static void reap_children(int options) {
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, options)) > 0) {
        if (WIFEXITED(status)) {
            syslog(LOG_INFO, "Client process %d exited with status %d", pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            syslog(LOG_INFO, "Client process %d was terminated by signal %d", pid, WTERMSIG(status));
        } else if (WIFSTOPPED(status)) {
            syslog(LOG_INFO, "Client process %d was stopped by signal %d", pid, WSTOPSIG(status));
        } else {
            syslog(LOG_WARNING, "Client process %d did not exit successfully", pid);
        }
    }
}

static void await_child_processes() {
    sigset_t new_mask;
    sigset_t old_mask;

    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) == -1) {
        syslog(LOG_ERR, "Unable to block SIGCHLD: %s", strerror(errno));
    }

    reap_children(0);

    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1) {
        syslog(LOG_ERR, "Unable to unblock SIGCHLD: %s", strerror(errno));
    }
}

static void connection_handler(const int fd_client, const char *client_host) {
    int exit_code = EXIT_FAILURE;
    syslog(LOG_INFO, "Accepted connection from %s", client_host);

    size_t capacity = INET_BLOCK_SIZE;
    char *buf = malloc(capacity);
    if (!buf) {
        syslog(LOG_ERR, "Unable to allocate client buffer: %s", strerror(errno));
        goto exit_start;
    }

    size_t pkt_len = 0;
    for (;;) {
        const ssize_t recv_len = recv(fd_client, buf + pkt_len, capacity - pkt_len, 0);
        if (recv_len == -1) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "Unable to receive client data: %s", strerror(errno));
            goto exit_buffer;
        }
        if (recv_len == 0) {
            syslog(LOG_WARNING, "Client closed without newline");
            goto exit_buffer;
        }

        // A packet is completed by a single newline. Anything after that is discarded.
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
            syslog(LOG_ERR, "Unable to expand client buffer: %s", strerror(errno));
            goto exit_buffer;
        }
        buf = tmp;
    }

    const int fd_data = open(DATA_FILE, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd_data == -1) {
        syslog(LOG_ERR, "Unable to open data file for reading: %s", strerror(errno));
        goto exit_buffer;
    }

    // Lock the file all the way writing to the data file until we've sent the contents
    // back to the client. Probably unnecessary for this assignment, and ultimately
    // not scalable, especially if the client is slow to receive.
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
    if (flock(fd_data, LOCK_UN) == -1) {
        syslog(LOG_ERR, "Unable to unlock data file: %d - %s", errno, strerror(errno));
    }

exit_file:
    close(fd_data);

exit_buffer:
    free(buf);

exit_start:
    close(fd_client);
    syslog(LOG_INFO, "Closed connection from %s", client_host);
    _exit(exit_code);
}

static void run() {
    struct sockaddr_storage client_addr;
    socklen_t client_len;

    syslog(LOG_INFO, "Waiting for connections");
    while (!g_shutdown) {
        reap_children(WNOHANG);
        client_len = sizeof(client_addr);
        const int client_fd = accept(listener_fd, (struct sockaddr *) &client_addr, &client_len);
        if (client_fd == -1) {
            if (errno == EINTR) continue;
            if (errno == ECONNABORTED || errno == EPROTO || errno == ENETDOWN) {
                syslog(LOG_WARNING, "Accept transient error: %s", strerror(errno));
                continue;
            }
            syslog(LOG_ERR, "Unable to accept connections: %s", strerror(errno));
            return;
        }

        pid_t pid = fork();
        if (pid == -1) {
            syslog(LOG_ERR, "Unable to fork client process: %s", strerror(errno));
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
    char *pid_file = NULL;
    int pipe_fd = -1;

    openlog("aesdsocket", LOG_PID, LOG_USER);

    if (argc >= 2 && strcmp(argv[1], "-d") == 0) {
        if (argc == 3) {
            pid_file = argv[2];
        }

        pipe_fd = daemonize(pid_file);
        if (pipe_fd == -1) {
            goto exit_start;
        }
    }

    if (init_signals() == -1) {
        syslog(LOG_ERR, "Unable to configure signal handling: %s", strerror(errno));
        goto exit_pipe;
    }

    listener_fd = open_listener();
    if (listener_fd == -1) {
        syslog(LOG_ERR, "Unable to bind to host port");
        goto exit_pipe;
    }

    if (pipe_fd != -1) {
        write(pipe_fd, &STARTED, sizeof(STARTED));
        close(pipe_fd);
    }

    run();

    // Make sure child processes have closed their file handles before removing data file.
    await_child_processes();
    if (g_shutdown) {
        syslog(LOG_INFO, "Caught signal, exiting");
        if (remove(DATA_FILE) == -1 && errno != ENOENT) {
            syslog(LOG_ERR, "Unable to remove %s: %s", DATA_FILE, strerror(errno));
        }
        if (pid_file) {
            if (remove(pid_file) == -1 && errno != ENOENT) {
                syslog(LOG_ERR, "Unable to remove %s: %s", pid_file, strerror(errno));
            }
        }
    }

    close_listener();
    closelog();
    return EXIT_SUCCESS;

exit_pipe:
    if (pipe_fd != -1) {
        write(pipe_fd, &STOPPED, sizeof(STOPPED));
        close(pipe_fd);
    }

exit_start:
    closelog();
    return EXIT_FAILURE;
}
