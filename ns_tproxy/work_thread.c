
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include "tproxy.h"



static LIBEVENT_DISPATCHER_THREAD dispatcher_thread;
static LIBEVENT_THREAD *threads = NULL;


static void thread_libevent_process(int fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    CQ_ITEM *item;
    char buf[1];

    if (read(fd, buf, 1) != 1)
        if (settings.verbose > 0)
            fprintf(stderr, "Can't read from libevent pipe\n");

    switch (buf[0]) {
    case 'c': //dispatch_conn_new
	//从CQ队列中读取一个item，因为是pop所以读取后，CQ队列会把这个item从队列中删除
    item = cq_pop(me->new_conn_queue);

    if (NULL != item) {
		//为sfd分配一个conn结构体，并且为这个sfd建立一个event，然后让base监听这个event
		//这个sfd的事件回调函数是event_handler
        conn *c = conn_new(item->sfd, item->init_state, item->event_flags,
                           item->read_buffer_size, item->transport, me->base);
        if (c == NULL) {
            if (IS_UDP(item->transport)) {
                fprintf(stderr, "Can't listen for events on UDP socket\n");
                exit(1);
            } else {
                if (settings.verbose > 0) {
                    fprintf(stderr, "Can't listen for events on fd %d\n",
                        item->sfd);
                }
                close(item->sfd);
            }
        } else {
            c->thread = me;
        }
        cqi_free(item);
    }
        break;
    //switch_item_lock_type触发走到这里
    /* we were told to flip the lock type and report in */
    case 'l': //参考switch_item_lock_type //切换item到段级别  
    //唤醒睡眠在init_cond条件变量上的迁移线程  
    me->item_lock_type = ITEM_LOCK_GRANULAR;
    register_thread_initialized();
        break;
    case 'g'://切换item锁到全局级别  
    me->item_lock_type = ITEM_LOCK_GLOBAL;
    register_thread_initialized();
        break;
    }
}



static int32_t  set_thread_info(LIBEVENT_THREAD *me) 
{
	int ret = 0;
    assert(me);
    
    me->base = event_init();
    if (! me->base) {
        ev_error_msg("Can't allocate event base\n");
        ret = -1;
        goto out;
    }

    /* Listen for notifications from other threads */
    event_set(&me->notify_event, me->notify_receive_fd,
              EV_READ | EV_PERSIST, thread_libevent_process, me);

    event_base_set(me->base, &me->notify_event);

    if (event_add(&me->notify_event, 0) == -1) {
        ev_error_msg("Can't monitor libevent notify pipe\n");
        ret = -1;
        goto out;
    }

    return 0;
    
out:
    if (me->base){
        event_base_free(me->base);
        me->base = NULL;
    }
    return ret;
}


int32_t thread_init(int nthreads, struct event_base *main_base) 
{
    int32_t i =0, ret = 0;
    
    dispatcher_thread.base = main_base;
    dispatcher_thread.thread_id = pthread_self();
    
    threads = calloc(nthreads, sizeof(LIBEVENT_THREAD));
    if (!threads) {
        ev_error_msg("can't allocate memory for thread descriptors errno:%d\n", errno);
        ret = -1;
        goto out;
    }
    memset(threads, 0, nthreads * sizeof(LIBEVENT_THREAD));
    
    for (i = 0; i < nthreads; i++) {
        int fds[2];
        if (pipe(fds)) {
           ev_error_msg("Can't create notify pipe");
           ret = -1;
           goto out;
        }

        threads[i].notify_receive_fd = fds[0];
        threads[i].notify_send_fd = fds[1];
        ret = set_thread_info(&threads[i]);
        if (ret) {
           ev_error_msg(" set thread info init failed ret:%d\n", ret);
           goto out;
        }
    }
    return ret;
    
out:
    for (i = 0; i < nthreads; ++i) {
        if (threads[i].base) {
            event_base_free(threads[i].base);
            threads[i].base = NULL;
        }
    }
    
    if(threads) {
        free(threads);
        threads = NULL;
    }
    return ret;
}


int32_t ev_fork_process_cycle(struct listening_st *ls, int num)
{
    int32_t i = 0, ret = 0;
    
    for (i = 0; i < num； ++i ){
        
    }

}

