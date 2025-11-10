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

void handle_signal(int);

int bind_host();

void run_host(int);

int main(int argc, char *argv[]) {
    openlog("aesdsocket", 0, LOG_USER);
    bool daemonize = false;
    int listen_fd;
    struct sigaction act;

    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        daemonize = true;
    }

    if (daemonize) {
        syslog(LOG_ERR, "Daemonize not yet implemented");
        closelog();
        return EXIT_FAILURE;
    }

    if ((listen_fd = bind_host()) == -1) {
        syslog(LOG_ERR, "Unable to bind");
        closelog();
        return EXIT_FAILURE;
    }

    act.sa_handler = handle_signal;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &act, NULL) == -1) {
        syslog(LOG_ERR, "Unable to bind to set action: %m");
        close(listen_fd);
        closelog();
        return EXIT_FAILURE;
    }

    if (listen(listen_fd, BACKLOG) == -1) {
        syslog(LOG_ERR, "Unable to listen: %m");
        close(listen_fd);
        closelog();
        return EXIT_FAILURE;
    }
    run_host(listen_fd);

    syslog(LOG_INFO, "Exiting");
    closelog();
    return EXIT_SUCCESS;
}

int bind_host() {
    int listen_fd;
    struct addrinfo hints, *host_info, *info;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rc = getaddrinfo(NULL, "9000", &hints, &host_info)) != 0) {
        syslog(LOG_ERR, "Getting address information: %s", gai_strerror(rc));
        closelog();
        exit(EXIT_FAILURE);
    }

    for (info = host_info; info != NULL; info = info->ai_next) {
        int yes = 1;

        if ((listen_fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol)) == -1) {
            syslog(LOG_ERR, "Could not open socket: %m");
            continue;
        }

        if ((rc = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) == -1) {
            close(listen_fd);
            syslog(LOG_ERR, "Setting socket options: %m");
            freeaddrinfo(host_info);
            closelog();
            exit(EXIT_FAILURE);
        }

        if ((rc = bind(listen_fd, info->ai_addr, info->ai_addrlen)) == -1) {
            close(listen_fd);
            syslog(LOG_ERR, "Binding socket: %m");
            continue;
        }

        break;
    }

    freeaddrinfo(host_info);
    return listen_fd;
}

void handle_signal(int signo) {
    (void) signo;

    int saved_errno;

    saved_errno = errno;
    syslog(LOG_INFO, "Received signal");
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &((struct sockaddr_in *) sa)->sin_addr;
    }

    return &((struct sockaddr_in6 *) sa)->sin6_addr;
}

void run_host(int listen_fd) {
    struct sockaddr_storage client_addr;
    socklen_t client_len;
    int client_fd;
    char client_ip[INET6_ADDRSTRLEN];

    syslog(LOG_INFO, "Waiting for connections");

    while (true) {
        client_len = sizeof(client_addr);
        client_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &client_len);
        if (client_fd == -1) {
            syslog(LOG_ERR, "Accept failed: %m");
            continue;
        }

        inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr *) &client_addr), client_ip, sizeof client_ip);
        syslog(LOG_INFO, "Connection from %s", client_ip);
        if (!fork()) {
            if (send(client_fd, "Hello, world!", 13, 0) == -1) {
                syslog(LOG_ERR, "Send failed: %m");
            }
            close(client_fd);
        }
    }
}
