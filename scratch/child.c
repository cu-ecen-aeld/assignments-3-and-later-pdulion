#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
    if (seteuid(0) != 0) {
        perror("Child could not change UID");
    }
    if (setsid() == -1) {
        perror("Child could not create new session");
    } else {
        printf("Child created new session: %d\n", getsid(getpid()));
    }
    printf("Child application with PID: %d, and owner: %d\n", getpid(), geteuid());
    return 0;
}
