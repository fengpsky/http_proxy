#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <syslog.h>

#include <event2/event.h>

#include "util-internal.h"
#include "log-internal.h"

#include "nsutil.h"

void ev_debug_log_core(uint32_t level, const char* funcname, int lineno, const char *fmt, ...);

int32_t init_daemon(int32_t    nochdir, int32_t noclose)
{
    int pid;
    int ret = 0;
    if ((pid = fork()) > 0)
        exit(0);
    else if (pid < 0)
        return -1; /* fork失败 */

    setsid(); /* 第一子进程成为新的会话组长和进程组长 */
    /* 并与控制终端分离 */

    if ((pid = fork()) > 0)
        exit(0); 
    else if (pid < 0)
        return -1; /* fork失败 */

    /* 是第二子进程，继续 */
    /* 第二子进程不再是会话组长 */

    /* Change directory to root. */
    if (!nochdir) {
        ret = chdir("/");
        if (ret < 0) {
           ev_error_msg("xdaemon: chdir error");
           return ret;
        }   
    }   

    /* parasoft suppress item BD-RES-INVFREE-1 */
    /* 关闭标准输入输出，标准错误的文件描述符 */
   /* File descriptor close. */
    if (!noclose) {
        int fd; 

        fd = open("/dev/null", O_RDWR, 0); 
        if (fd != -1) {
          dup2(fd, STDIN_FILENO);
          dup2(fd, STDOUT_FILENO);
          dup2(fd, STDERR_FILENO);
          if (fd > 2)
              close(fd);
        }   
    }   

    umask(0);
    return 0;
}

int32_t sock_ntop(struct sockaddr *sa, int32_t socklen, uint8_t *buf, int32_t len,
    uint16_t port)
{
    uint8_t               *p;
    struct sockaddr_in   *sin;
    int32_t                n;
    struct sockaddr_in6  *sin6;

    switch (sa->sa_family) {

    case AF_INET:

        sin = (struct sockaddr_in *) sa;
        p = (uint8_t *) &sin->sin_addr;

        if (port) {
            p = snprintf(buf, len, "%ud.%ud.%ud.%ud:%d",
                             p[0], p[1], p[2], p[3], ntohs(sin->sin_port));
        } else {
            p = snprintf(buf, len, "%ud.%ud.%ud.%ud",
                             p[0], p[1], p[2], p[3]);
        }

        return (p - text);

    case AF_INET6:

        sin6 = (struct sockaddr_in6 *) sa;

        n = 0;

        if (port) {
            buf[n++] = '[';
        }

        n = inet6_ntop(sin6->sin6_addr.s6_addr, &buf[n], len);

        if (port) {
            n = sprintf(&buf[1 + n], "]:%d",
                            ntohs(sin6->sin6_port)) - buf;
        }

        return n;

    default:
        return 0;
    }
}




