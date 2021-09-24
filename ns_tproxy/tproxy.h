#ifndef TPROXY_H_
#define TPROXY_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <event.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>


#include "util-internal.h"
#include "log-internal.h"
#include "nsutil.h"
#include "work.h"


#define MAX_IPADDR_STR_LEN `(128)
#define MAX_TCP_BACKLOG (40960)

typedef struct {
    pthread_t thread_id;        /* unique ID of this thread */
    struct event_base *base;    /* libevent handle this thread uses */ 
    struct event notify_event;  /* listen event for notify pipe */ 
   
    int32_t notify_receive_fd;      /* receiving end of notify pipe */ 
    int32_t notify_send_fd;         /* sending end of notify pipe */ 
    struct thread_stats stats;  /* Stats generated by this thread */
} LIBEVENT_THREAD; //static LIBEVENT_THREAD *threads;


struct  ev_http_backend {
    struct bufferevent *buf_ev;
    void *data;
    
    uint32_t    state;

    uint32_t    proxy:1;
    uint32_t    cache:1;
    uint32_t    chunked:1; 
};



struct  ev_http_request {
    struct bufferevent *buf_ev;
    struct ev_http_backend *bk_http;
    
    uint32_t    state;

    uint32_t    proxy:1;
    uint32_t    cache:1;
    uint32_t    limit_conn_status:2;
    uint32_t    limit_req_status:3;
    uint32_t    limit_rate_on:1;
    uint32_t    chunked:1;
    uint32_t    lingering_close:1;
    uint32_t    chunked:1;
    
};


struct listening_st;

typedef void (*listener_conn_cb)(struct listening_st*, ev_socket ,  void *);
typedef void (*listener_conn_errorcb)(struct listening_st*, void *);

struct listening_st {
    int32_t    sfd;
    LIBEVENT_THREAD *thread; /* Pointer to the thread object serving this listen */

    int32_t     sock_type;
    struct sockaddr_storage sockaddr;
    int8_t      addr_str[MAX_IPADDR_STR_LEN];
    
    int32_t     backlog;
    
    uint32_t    is_set:1;//是否已经设置下面标志位
    uint32_t    listen:1;
    uint32_t    reuseport:1;
    uint32_t    deferred_accept:1;
    uint32_t    fastopen:1;
    uint32_t    ipv6only:1;
    uint32_t    http2:1;
    uint32_t    ssl:1;
    uint32_t    en_keepalive:1;
    uint32_t    tcp_nodelay:1;
    uint32_t    en_tproxy:1;
    uint32_t    tcp_crok:1;
    
    int32_t     tcp_keepidle;
    int32_t     tcp_keepintvl;
    int32_t     tcp_keepcnt;
    
    int32_t     rcvbuf;
    int32_t     sndbuf;
    
    struct event event;
    int16_t  ev_flags;
    listener_conn_cb process_new_fd_cb;
    listener_conn_errorcb error_cb;
    
};


typedef struct {
    pthread_t thread_id;        /* unique ID of this thread */
    struct event_base *base;    /* libevent handle this thread uses */
} LIBEVENT_DISPATCHER_THREAD;

#endif
