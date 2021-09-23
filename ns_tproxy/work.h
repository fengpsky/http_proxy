#ifndef _WORK_HEAD_H_
#define _WORK_HEAD_H_

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/cpuset.h>

typedef void (*ev_clone_proc_pf) (void *cycle, void *data);

#define MAX_PROCESS_NAME (48)

struct ev_process_t{
    pid_t           pid;
    int32_t         status;
    int32_t        ev_channel_pair[2];

    ev_clone_proc_pf   proc;
    void               *data;
    char               name[MAX_PROCESS_NAME];
    uint32_t            detached:1;
    uint32_t            exiting:1;
    uint32_t            exited:1;
};

#endif