#include "systemcalls.h"
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <wait.h>
#include <string.h>

size_t join_str(char *dest, size_t size, char ** strv, const char *delim);

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
 */
bool do_system(const char *cmd)
{
    int status = system(cmd);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/**
 * @param count -The numbers of variables passed to the function. The variables are command to execute.
 *   followed by arguments to pass to the command
 *   Since exec() does not perform path expansion, the command to execute needs
 *   to be an absolute path.
 * @param ... - A list of 1 or more arguments after the @param count argument.
 *   The first is always the full path to the command to execute with execv()
 *   The remaining arguments are a list of arguments to pass to the command in execv()
 * @return true if the command @param ... with arguments @param arguments were executed successfully
 *   using the execv() call, false if an error occurred, either in invocation of the
 *   fork, waitpid, or execv() command, or if a non-zero return value was returned
 *   by the command issued in @param arguments with the specified arguments.
 */

bool do_exec(int count, ...)
{
    bool result = false;
    openlog("systemcalls", 0, LOG_USER);
    syslog(LOG_INFO, "========== %s ==========", __func__);

    va_list args;
    va_start(args, count);
    char *command[count + 1];
    for (int i = 0; i < count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;

    char buffer [256];
    join_str(buffer, sizeof(buffer), command, " ");
    syslog(LOG_INFO, "Command: %s", buffer);

    pid_t pid = fork();
    if (pid > 0)
    {
        syslog(LOG_INFO, "Created child process with PID %d", pid);

        int status;
        pid_t term_pid = wait(&status);
        if (term_pid < 0)
        {
            syslog(LOG_ERR, "Failed to wait for child process: %m");
        }
        else if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        {
            result = true;
        }
    }
    else if (pid == 0)
    {
        syslog(LOG_INFO, "In child process with PID %d", getpid());

        execv(command[0], command);
        syslog(LOG_ERR, "Failed to execute child command: %m");
        _exit(1);
    }
    else
    {
        // Fork failed
        syslog(LOG_ERR, "Failed to fork process: %m");
    }

    syslog(LOG_INFO, "Done %s, with result: %d", __func__, result);

    va_end(args);
    closelog();
    return result;
}

/**
 * @param outputfile - The full path to the file to write with command output.
 *   This file will be closed at completion of the function call.
 * All other parameters, see do_exec above
 */
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    bool result = false;
    openlog("systemcalls", 0, LOG_USER);
    syslog(LOG_INFO, "========== %s ==========", __func__);

    va_list args;
    va_start(args, count);
    char *command[count + 1];
    int i;
    for (i = 0; i < count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;

    char buffer [256];
    join_str(buffer, sizeof(buffer), command, " ");
    syslog(LOG_INFO, "Command: %s", buffer);
    syslog(LOG_INFO, "Output file: %s", outputfile);

    // Open file to be used by child process for stdout
    int fd = creat(outputfile, 0644);
    if (fd < 0)
    {
        syslog(LOG_ERR, "Could not open or create output file: %m");
    }
    else
    {
        pid_t pid = fork();
        if (pid > 0)
        {
            syslog(LOG_INFO, "Created child process with PID %d", pid);

            int status;
            pid_t term_pid = wait(&status);
            if (term_pid < 0)
            {
                syslog(LOG_ERR, "Failed to wait for child process: %m");
            }
            else if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
            {
                result = true;
            }
        }
        else if (pid == 0)
        {
            syslog(LOG_INFO, "In child process with PID %d", getpid());

            if (dup2(fd, STDOUT_FILENO) < 0)
            {
                syslog(LOG_ERR, "Could not redirect standard output: %m");
                _exit(1);
            }
            execv(command[0], command);
            syslog(LOG_ERR, "Failed to execute child command: %m");
            _exit(1);
        }
        else
        {
            // Fork failed
            syslog(LOG_ERR, "Failed to fork: %m");
        }
    }
    close(fd);

    syslog(LOG_INFO, "Done %s, with result: %d", __func__, result);

    va_end(args);
    closelog();
    return result;
}

size_t join_str(char *dest, size_t size, char ** strv, const char *delim)
{
    size_t max_len = size - 1;
    size_t join_len = 0;
    size_t delim_len = strlen(delim);
    bool first = true;

    dest[0] = '\0';
    for (size_t i = 0; strv[i] != NULL; i++)
    {
        size_t str_len = strlen(strv[i]);
        if (!first)
        {
            if (join_len + delim_len < max_len)
            {
                strcpy(&dest[join_len], delim);
            }
            join_len += delim_len;
        }

        if (join_len + str_len < max_len)
        {
            strcpy(&dest[join_len], strv[i]);
        }
        join_len += str_len;
        first = false;
    }

    return join_len;
}
