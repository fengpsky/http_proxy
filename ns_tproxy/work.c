#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
//#include <pthread.h>
#include <sys/cpuset.h>

#define MAX_PROCE_CNT (64)

struct ev_process_t  process_ary[MAX_PROCE_CNT];

int32_t process_slot = 0;
ev_socket  chaild_chn_fd = -1;
int32_t  work_cpu = 0;
int32_t work_cnt = 0;
pid_t ev_pid = 0;
struct event_base *work_base = NULL;

int32_t init_process_info()
{
    int i = 0;
    int ret = 0;
    memset(process_ary, 0, sizeof(process_ary));
    
    for (i = 0; i < MAX_PROCE_CNT, ++i) {
        process_ary[i].pid = -1;
    }
    return ret;
}

int32_t set_process_priority(int32_t priority)
{
    int32_t ret = 0;
    ret = setpriority(PRIO_PROCESS, 0, priority);
    if (ret < 0) {
        ev_error_msg("set process(%s) priority failed\n", process_ary[process_slot].name);
    }
    ev_debug_msg(EV_DEBUG_LEVEL11, "set process(%s) priority sucessed\n", 
                 process_ary[process_slot].name)
    return ret;
}

int32_t set_work_ulimit_resource(int32_t work_cpu)
{
    struct rlimit     rlmt;
    uint64_t  cpu_affinity = 0;
    
    const int32_t  rlimit_nofile = 1000000;
    const int32_t  rlimit_core = 1000000;
 
    rlmt.rlim_cur = rlimit_nofile;
    rlmt.rlim_max = rlimit_nofile;   
    if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        ev_error_msg("setrlimit(RLIMIT_NOFILE, %d) failed", rlimit_nofile);
     }
    ev_debug_msg(EV_DEBUG_LEVEL11, "setrlimit(RLIMIT_NOFILE:%d) sucessed", rlimit_nofile);

    /* allow coredump after setuid() in Linux 2.4.x */
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0) {
        ev_error_msg("PR_SET_DUMPABLE failed prctl:errno:%d %m.", ev_errno);
    }
    
    rlmt.rlim_cur = rlimit_core;
    rlmt.rlim_max = rlimit_core;
    if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
        ev_error_msg("setrlimit(RLIMIT_CORE, %d) failed", rlimit_core);
    }
    ev_debug_msg(EV_DEBUG_LEVEL11, "setrlimit(RLIMIT_CORE:%d) sucessed", rlimit_core);

    if(work_cpu > 0) {
        cpu_affinity = 1 << work_cpu ;
        ev_setaffinity(cpu_affinity);
    }
    
}




int32_t 
assign_listener_to_new_event(struct listening_st *listener, 
            struct bufferevent *b_in)
{
    ev_socket fd = b_in->ev_read->ev_fd;
    int32_t on = 1, off = 0;
    
    b_in->reuseport = listener->reuseport;
    b_in->deferred_accept = listener->deferred_accept;
    b_in->fastopen = listener->fastopen;
    b_in->ipv6only = listener->ipv6only;
    b_in->http2 = listener->http2;
    b_in->ssl = listener->ssl;
    b_in->en_keepalive = listener->en_keepalive;
    b_in->tcp_keepidle = listener->tcp_keepidle;
    b_in->tcp_keepintvl = listener->tcp_keepintvl;
    b_in->tcp_keepcnt = listener->tcp_keepcnt;
    b_in->sock_rcvbuf = listener->rcvbuf;
    b_in->sock_sndbuf = listener->sndbuf;
    b_in->sock_type = listener->sock_type;
  
    b_in->tcp_nodelay = listener->tcp_nodelay;
    b_in->en_tproxy = listener->en_tproxy;
    b_in->tcp_crok = listener->tcp_crok;
    
    if(listener->reuseport) {
        (void)evutil_set_socket_options(fd, EV_SO_REUSEPORT, on);
    }

    if(listener->deferred_accept) {
        (void)evutil_set_socket_options(fd, EV_TCP_DEFER_ACCEPT, on);
    }

    if (listener->fastopen) {
        (void)evutil_set_socket_options(fd, EV_TCP_FASTOPEN, on);
    }

    if (listener->ipv6only) {
        (void)evutil_set_socket_options(fd, EV_IPV6_V6ONLY, on);
    }

    if (b_in->en_keepalive) {
        (void)evutil_set_socket_options(fd, EV_SO_KEEPALIVE, on);
    }

    if (b_in->tcp_keepidle) {
        (void)evutil_set_socket_options(fd, EV_TCP_KEEPIDLE, b_in->tcp_keepidle);           
    }

    if (b_in->tcp_keepintvl) {
        (void)evutil_set_socket_options(fd, EV_TCP_KEEPINTVL, b_in->tcp_keepintvl);            
    }

    if (b_in->tcp_keepcnt) {
        (void)evutil_set_socket_options(fd, EV_TCP_KEEPCNT, b_in->tcp_keepcnt);     
    }

    if (b_in->sock_rcvbuf) {
        (void)evutil_set_socket_options(fd, EV_SO_RCVBUF, b_in->sock_rcvbuf); 
    }

    if (b_in->sock_sndbuf) {
        (void)evutil_set_socket_options(fd, EV_SO_SNDBUF, b_in->sock_sndbuf); 
    }
    
    if (b_in->tcp_nodelay) {
        (void)evutil_set_socket_options(fd, EV_TCP_NODELAY, on);
    }
    
    if (b_in->tcp_crok) {
        (void)evutil_set_socket_options(fd, EV_TCP_CORK, on);
    }

    if(b_in->en_tproxy) {
        (void)evutil_set_socket_options(fd, EV_IP_TRANSPARENT, on);
    }
   
}

static void
accept_event(struct listening_st *listener, ev_socket  fd, void *userdata)
{
	struct bufferevent *b_in = NULL;
    int32_t on = 1, ret = 0;
    
    socklen_t src_len = sizeof(struct sockaddr_storage), dst_len = sizeof(struct sockaddr_storage);
    
    /* Create two linked bufferevent objects: one to connect, one for the
	 * new connection */
	b_in = bufferevent_socket_new(work_base, fd,
	    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    assert(b_in);
    
    ret = getsockname(fd, (struct sockaddr *)&b_in->dst_sa, &dst_len);
    if (ret) {
        ev_error_msg("get sock name failed; fd:[%d] errno:%d %m.\n", fd, ev_errno);
        goto out;
    }
    ret = getpeername(fd, (struct sockaddr *)&b_in->src_sa, &src_len);
    if (ret) {
        ev_error_msg("get peer name failed; fd:[%d] errno:%d %m.\n", fd, ev_errno);
        goto out;
    }
    
	
    
    assign_listener_to_new_event(listener, b_in);
    
	bufferevent_setcb(b_in, process_rbuf_cb, NULL, eventcb, NULL);
	bufferevent_enable(b_in, EV_READ|EV_WRITE);

    return;
    
out:
    if (fd) {
        ev_close(fd);
        fd = -1;
    }
    
    if (b_in) {
        bufferevent_free(b_in);
        b_in = NULL;
    }
    return;
}


static void
ev_listener_read_cb(ev_socket fd, short what, void *p)
{
    struct listening_st *ls  = p;
    int err = 0;
    listener_conn_cb  cb;
    listener_conn_errorcb errorcb;
    
    while (1) {
        struct sockaddr_storage ss;
        socklen_t socklen = sizeof(ss);
        ev_socket new_fd = evutil_accept4_(fd, (struct sockaddr*)&ss, &socklen, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (new_fd < 0)
            break;
        if (socklen == 0) {
            /* This can happen with some older linux kernels in
             * response to nmap. */
            evutil_closesocket(new_fd);
            ev_info_msg("response to nmap so close fd \n");
            continue;
        }

        if (ls->process_new_fd_cb == NULL) {
            ev_info_msg("new fd process cb is null\n");
            evutil_closesocket(new_fd);
            return;
        }
 
        cb = ls->process_new_fd_cb;
        cb(ls, new_fd, NULL);
    }
    err = evutil_socket_geterror(fd);
    if (EVUTIL_ERR_ACCEPT_RETRIABLE(err)) {
        return;
    }
    if (ls->error_cb != NULL) {
        errorcb = ls->error_cb;
        errorcb(ls, NULL);
    } else {
        event_sock_warn(fd, "Error from accept() call");
    }
}


int32_t work_procrss_add_listen_event(struct event_base *base, struct listening_st *ls_ary)
{
    int32_t ret = 0, i = 0;
    struct listening_st *ls = NULL;
        
    for (i = 0; i < work_cnt; ++i) {
        ls = &ls_ary[i];
        ls->process_new_fd_cb = accept_event;
        ls->error_cb  = NULL;
        
        ret = event_assign(&ls->event, base, ls->sfd, EV_READ|EV_PERSIST, ev_listener_read_cb, &ls_ary[i]);
        if (ret) {
            ev_error_msg("assign ls fd[%d]addr:%s to event failed\n", ls->sfd, ls->addr_str);
            goto out;
        }

        ret =  event_add(&ls->event, NULL);
        if (ret){
            ev_error_msg("add fd[%d-%s]event into I/O multiplex failed\n", ls->sfd, ls->addr_str);
            goto out;
        }
        
    }
    
    return ret;
    
failed:
    //finit
    return ret;

}



static void
ngx_worker_process_cycle(void *parent, void *data) 
{
    int32_t cpu_af = (intptr_t) data;
    int32_t ret = 0;
    work_cpu = cpu_af;

    (void) set_process_priority(cpu_af);
    set_work_ulimit_resource(cpu_af);
    ev_set_process_proctitle(process_ary[process_slot].name);
    work_base = event_base_new();
    if (work_base == NULL) {
        ret = -1;
        ev_error_msg("malloc event base for work process  failed errno:%d %m.", ev_errno);
        goto out;
    }
    ret = work_procrss_add_listen_event(work_base, listenv4_ary);
    

    event_base_dispatch(work_base);
    ret = 0;
    
out:
    ev_info_msg("work process exit mask:%d", ret);
    return;
}




int32_t start_child_event(void *parent, ev_clone_proc_pf process_main, char *process_name, void *data)
{
    int32_t ret = 0, index = 0;
    pid_t  pid;
    for (index = 0; index < MAX_PROCE_CNT; ++index) {
        if (process_ary[index].pid == -1) {
            break;
        }
    }
    if (index == MAX_PROCE_CNT) {
        ev_error_msg("mo more than %d process can be cloned/spawned", MAX_PROCE_CNT);
        ret = -1;
        goto failed; 
    }
    ret = evutil_make_internal_pipe_(process_ary[index].ev_channel_pair);
    if (ret) {
        ev_error_msg("make channel pair failed\n, errno:%d %m.", ev_errno);
        goto failed;
    }
    
    chaild_chn_fd = process_ary[index].ev_channel_pair[1];
    process_slot = index;

    pid = fork();
    if (pid < 0) {
        ev_error_msg("fork failed while start child process errno:%d %m.", ev_errno);
        ret = pid;
        goto out;
    }else if (0 == pid) {
        ev_pid = getpid();
        process_main(parent, data);
    }else {
        ev_info_msg("master[pid:%u] start child[pid:%u]", ev_pid, pid);
    }
    
    process_ary[index].pid = pid;
    process_ary[index].status = 0; 
    process_ary[index].proc = process_main;
    process_ary[index].exited = 0;
    process_ary[index].exited = 0;
    strncpy(process_ary[index].name, process_name, MAX_PROCESS_NAME);

    ret = pid;
    return ret;
    
failed:
    return ret;
}

int32_t ev_fork_process(void *parent, int32_t num)
{
    int32_t ret = 0, i = 0;
    char work_name[MAX_PROCESS_NAME];
    
    for (i = 0; i < num; ++i) {
        memset(work_name, 0, sizeof(work_name));
        snprintf(work_name, MAX_PROCESS_NAME, "work process-%d", i)
        
        ret = start_child_event(parent, ngx_worker_process_cycle, work_name,  (void *) (intptr)i);
        if (ret < 0) {
            ev_error_msg("clone and start child process[%s] failed\n", work_name);
        }
    }

}


