#include <arpa/inet.h>
#include <features.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#define ACCEPT_BACKLOG 10

int listen_fd = -1;
int client_fd = -1;

int init_server() {
    int fd = -1;
    int rc;
    struct addrinfo hints = {0}, *addrs;

    // memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rc = getaddrinfo(NULL, "9000", &hints, &addrs)) != 0) {
        syslog(LOG_ERR, "Getting address information: %s", gai_strerror(rc));
        goto error_host_info;
    }

    for (struct addrinfo *entry = addrs; entry != NULL; entry = entry->ai_next) {
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

error_host_info:
    freeaddrinfo(addrs);
    return fd;
}

void handle_signals(int signum) {
    int old_errno = errno;

    if (signum == SIGCHLD) {
        while (waitpid(-1, NULL, WNOHANG) > 0);
    } else if (signum == SIGINT || signum == SIGTERM) {
        if (client_fd > STDERR_FILENO)
            shutdown(client_fd, SHUT_RDWR);
        if (listen_fd > STDERR_FILENO)
            shutdown(listen_fd, SHUT_RDWR);
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

void block_signals(sigset_t *oldmask) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &set, oldmask) == -1) {
        syslog(LOG_ERR, "sigprocmask(SIG_BLOCK) failed: %s", strerror(errno));
    }
}

void restore_signals(const sigset_t *oldmask) {
    if (sigprocmask(SIG_SETMASK, oldmask, NULL) == -1) {
        syslog(LOG_ERR, "sigprocmask(SIG_SETMASK) failed: %s", strerror(errno));
    }
}

void handle_client() {
    if (send(client_fd, "Hello, world!", 13, 0) == -1) {
        syslog(LOG_ERR, "Send failed: %s", strerror(errno));
    }
    close(client_fd);
    exit(0);
}

void run_server() {
    struct sockaddr_storage client_addr;
    socklen_t client_len;
    sigset_t old_mask;

    syslog(LOG_INFO, "Waiting for connections");

    while (true) {
        client_len = sizeof(client_addr);
        client_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &client_len);
        if (client_fd == -1) {
            if (errno == EINTR) {
                continue;
            }
            syslog(LOG_INFO, "Accept failed, exiting");
            break;
        }

        log_client_ip(&client_addr);
        pid_t pid = fork();
        if (pid == -1) {
            syslog(LOG_ERR, "Fork failed: %s", strerror(errno));
            break;
        }

        if (pid > 0) {
            // Detach parent's reference to client_fd
            block_signals(&old_mask);
            close(client_fd);
            client_fd = -1;
            restore_signals(&old_mask);
        } else {
            // Detach child's reference to listen_fd
            block_signals(&old_mask);
            close(listen_fd);
            listen_fd = -1;
            restore_signals(&old_mask);

            handle_client();
        }
    }
}

int main(int argc, char *argv[]) {
    int exit_code = EXIT_FAILURE;
    openlog("aesdsocket", 0, LOG_USER);
    bool daemonize = false;

    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        daemonize = true;
    }

    if (daemonize) {
        syslog(LOG_ERR, "Daemonize not yet implemented");
        goto error_syslog;
    }

    listen_fd = init_server();
    if (listen_fd == -1) {
        syslog(LOG_ERR, "Unable to bind to host port");
        goto error_syslog;
    }

    if (init_signals() == -1) {
        syslog(LOG_ERR, "Unable to configure signal handling: %s", strerror(errno));
        goto error_server_fd;
    }

    if (listen(listen_fd, ACCEPT_BACKLOG) == -1) {
        syslog(LOG_ERR, "Unable to listen: %s", strerror(errno));
        goto error_server_fd;
    }

    run_server();
    exit_code = EXIT_SUCCESS;

error_server_fd:
    close(listen_fd);

error_syslog:
    syslog(LOG_INFO, "Exiting");
    closelog();
    return exit_code;
}
