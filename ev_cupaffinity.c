#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <>
#include <event2/util.h>
#include <event2/event-config.h>
#include <util-internal.h>
#include <log-internal.h>


#if (EV_HAVE_CPUSET_SETAFFINITY)

#include <sys/cpuset.h>

void
ev_setaffinity(uint64_t cpu_affinity)
{
    cpuset_t    mask;
    uint32_t  i;

    

    CPU_ZERO(&mask);
    i = 0;
    do {
        if (cpu_affinity & 1) {
            CPU_SET(i, &mask);
        }
        i++;
        cpu_affinity >>= 1;
    } while (cpu_affinity);

    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                           sizeof(cpuset_t), &mask) == -1)
    {
        ev_error_msg("cpuset_setaffinity() failed");
    }

    ev_debug_msg(EV_DEBUG_LEVEL11, "cpuset_setaffinity(0x%08 "PRu" )", cpu_affinity);                       
}

#elif (EV_HAVE_SCHED_SETAFFINITY)

void
ev_setaffinity(uint64_t cpu_affinity)
{
    cpu_set_t   mask;
    uint32_t  i;

    CPU_ZERO(&mask);
    i = 0;
    do {
        if (cpu_affinity & 1) {
            CPU_SET(i, &mask);
        }
        i++;
        cpu_affinity >>= 1;
    } while (cpu_affinity);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        ev_error_msg("sched_setaffinity() failed");
    }
    ev_debug_msg(EV_DEBUG_LEVEL11, "cpuset_setaffinity(0x%08 "PRu" )", cpu_affinity); 
}

#endif



extern char **environ;
int              ev_argc = 0;
char           **ev_argv = NULL;

char           **ev_os_argv = NULL;
static char *ev_os_argv_last;


int32_t
save_env_argc_init_setproctitle(int argc, char *const *argv)
{ 
    uint8_t      *p;
    int32_t       size, len;
    uint32_t   i;
    
    ev_os_argv = (char **)argv;
    
    ev_argc = argc;
    ev_argv = argv;
    
    ev_argv = malloc((argc + 1) * sizeof(char *));
    if (ev_argv == NULL) {
        return EV_ERROR;
    }

    for (i = 0; i < argc; i++) {
        len = strlen(argv[i]) + 1;

        ev_argv[i] = malloc(len);
        if (ev_argv[i] == NULL) {
            return EV_ERROR;
        }

        (void) strncpy((char *) ev_argv[i], len, (char *) argv[i]);
    }

    ev_argv[i] = NULL;
   

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    p = malloc(size);
    if (p == NULL) {
        return EV_ERROR;
    }

    ev_os_argv_last = ev_argv[0];

    for (i = 0; ev_argv[i]; i++) {
        if (ev_os_argv_last == ev_argv[i]) {
            ev_os_argv_last = ev_argv[i] + strlen(ev_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (ev_os_argv_last == environ[i]) {

            size = strlen(environ[i]) + 1;
            ev_os_argv_last = environ[i] + size;

            strncpy(p, size, (char *) environ[i]);
            environ[i] = (char *) p;
            p += size;
        }
    }

    ev_os_argv_last--;

    return EV_OK;
}


void
ev_set_process_proctitle(char *title)
{
    char     *p;


    ev_os_argv[1] = NULL;

    p = strncpy((char *) ev_os_argv[0], ev_os_argv_last - ev_os_argv[0], (char *) "waf: ");

    p = strncpy(p, ev_os_argv_last - (char *) p, (char *) title);


    if (ev_os_argv_last - (char *) p) {
        memset(p, ' ', ev_os_argv_last - (char *) p);
    }

    ev_info_msg("setproctitle: \"%s\"", ev_os_argv[0]);
}



