#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    printf("Parent application with PID: %d, and effective owner: %d\n", getpid(), geteuid());
    if (setsid() == -1) {
        perror("Parent could not create new session");
    }
    printf("Parent is member of session group: %d\n", getsid(getpid()));
    pid_t pid = fork();
    if (pid > 0) {
        // Parent process
        printf("I am the parent process for PID: %d\n", pid);

        int status;
        pid = wait(&status);
        if (WIFEXITED(status)) {
            printf("Child process %d exited with status %d\n", pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Child process %d was terminated by signal %d\n", pid, WTERMSIG(status));
        } else if (WIFSTOPPED(status)) {
            printf("Child process %d was stopped by signal %d\n", pid, WSTOPSIG(status));
        } else {
            printf("Child process %d did not exit successfully\n", pid);
        }
    } else if (pid == 0) {
        // Child process
        printf("I am the chlid process PID: %d\n", getpid());
        execl("./child", "child", NULL);
    } else {
        // Fork failed
        perror("Fork failed");
        return 1;
    }
    return 0;
}
