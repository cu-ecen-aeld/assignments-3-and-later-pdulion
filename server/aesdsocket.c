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

#define BACKLOG 10

void handle_signals(int);
int init_server();
int init_signals();
void run_server();

int listen_fd = -1;
int connect_fd = -1;

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

    if ((listen_fd = init_server()) == -1) {
        syslog(LOG_ERR, "Unable to bind to host port");
        goto error_syslog;
    }

    if (init_signals() == -1) {
        syslog(LOG_ERR, "Unable to configure signal handling: %m");
        goto error_server_fd;
    }

    if (listen(listen_fd, BACKLOG) == -1) {
        syslog(LOG_ERR, "Unable to listen: %m");
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

int init_server() {
    int fd = -1;
    int rc;
    struct addrinfo hints, *addrs, *entry;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rc = getaddrinfo(NULL, "9000", &hints, &addrs)) != 0) {
        syslog(LOG_ERR, "Getting address information: %s", gai_strerror(rc));
        goto error_host_info;
    }

    for (entry = addrs; entry != NULL; entry = entry->ai_next) {
        int yes = 1;

        if ((fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol)) == -1) {
            syslog(LOG_WARNING, "Could not create socket: %m");
            continue;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            syslog(LOG_ERR, "Failed setting socket options: %m");
            close(fd);
            continue;
        }

        if (bind(fd, entry->ai_addr, entry->ai_addrlen) == -1) {
            close(fd);
            syslog(LOG_ERR, "Failed to bind socket: %m");
            continue;
        }

        break;
    }

error_host_info:
    freeaddrinfo(addrs);
    return fd;
}

void handle_signals(int signo) {
    int saved_errno = errno;

    if (signo == SIGINT || signo == SIGTERM) {
        shutdown(connect_fd, SHUT_RDWR);
        shutdown(listen_fd, SHUT_RDWR);
    } else if (signo == SIGCHLD) {
        while (waitpid(-1, NULL, WNOHANG) > 0);
    }

    errno = saved_errno;
}

int init_signals() {
    struct sigaction sa;

    sa.sa_handler = handle_signals;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    return sigaction(SIGINT, &sa, NULL);
}

void *get_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &((struct sockaddr_in *) sa)->sin_addr;
    }
    return &((struct sockaddr_in6 *) sa)->sin6_addr;
}

void run_server() {
    struct sockaddr_storage client_addr;
    socklen_t client_len;
    char client_ip[INET6_ADDRSTRLEN];

    syslog(LOG_INFO, "Waiting for connections");

    while (true) {
        client_len = sizeof(client_addr);
        connect_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &client_len);
        if (connect_fd == -1) {
            if (errno == EINVAL) {
                syslog(LOG_INFO, "Accept failed, exiting");
                break;
            }
            // Fix invalid argument
            continue;
        }

        inet_ntop(client_addr.ss_family, get_addr((struct sockaddr *) &client_addr), client_ip, sizeof client_ip);
        syslog(LOG_INFO, "Accepted connection from %s", client_ip);
        pid_t pid = fork();
        if (pid == -1) {
            syslog(LOG_ERR, "Fork failed: %m");
        } else if (pid > 0) {
            // Parent
            close(connect_fd);
        } else {
            // Child
            close(listen_fd);
            if (send(connect_fd, "Hello, world!", 13, 0) == -1) {
                syslog(LOG_ERR, "Send failed: %m");
            }
            close(connect_fd);
            exit(0);
        }
    }
}
