#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>

int main(int argc, char* argv[]) {
    openlog("writer", 0, LOG_USER);
    if (argc != 3) {
        // We expect two arguments, but argc also counts the program name
        syslog(LOG_ERR, "Error: Incorrect number of arguments: %d", argc - 1);
        return 1;
    }

    char* write_file = argv[1];
    char* write_str = argv[2];


    int fd = creat(write_file, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "Could not open or create %s: %m", write_file);
        closelog();
        return 1;
    }

    ssize_t nout = write(fd, write_str, strlen(write_str));
    if (nout < 0) {
        syslog(LOG_ERR, "Could not write to %s: %m", write_file);
        close(fd);
        closelog();
        return 1;
    }

    close(fd);
    closelog();
    return 0;
}