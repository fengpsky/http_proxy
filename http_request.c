#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
//#include <pthread.h>
#include <sys/cpuset.h>



#define MAX_OUTPUT (512*1024)

static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);

static void
readcb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;
	struct evbuffer *src, *dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	if (!partner) {
		evbuffer_drain(src, len);
		return;
	}
	dst = bufferevent_get_output(partner);
	evbuffer_add_buffer(dst, src);

	if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
		/* We're giving the other side data faster than it can
		 * pass it on.  Stop reading here until we have drained the
		 * other side to MAX_OUTPUT/2 bytes. */
		bufferevent_setcb(partner, readcb, drained_writecb,
		    eventcb, bev);
		bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2,
		    MAX_OUTPUT);
		bufferevent_disable(bev, EV_READ);
	}
}

static void
drained_writecb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;

	/* We were choking the other side until we drained our outbuf a bit.
	 * Now it seems drained. */
	bufferevent_setcb(bev, readcb, NULL, eventcb, partner);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	if (partner)
		bufferevent_enable(partner, EV_READ);
}

static void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_output(bev);

	if (evbuffer_get_length(b) == 0) {
		bufferevent_free(bev);
	}
}


static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	struct bufferevent *partner = ctx;

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (what & BEV_EVENT_ERROR) {
			unsigned long err;
			if (errno)
				perror("connection error");
		}

		if (partner) {
			/* Flush all pending data */
			readcb(bev, ctx);

			if (evbuffer_get_length(
				    bufferevent_get_output(partner))) {
				/* We still have to flush data from the other
				 * side, but when that's done, close the other
				 * side. */
				bufferevent_setcb(partner,
				    NULL, close_on_finished_writecb,
				    eventcb, NULL);
				bufferevent_disable(partner, EV_READ);
			} else {
				/* We have nothing left to say to the other
				 * side; close it. */
				bufferevent_free(partner);
			}
		}
		bufferevent_free(bev);
	}
}


int32_t new_init_server_sock(struct bufferevent *bev)
{
    ev_socket sockfd = -1;
    sockfd = socket(bev->src_sa.ss_family, bev->sock_type, 0);
    if (sockfd < 0) {
        ev_error_msg("create fd failed errno:%d %m.", ev_errno);
        goto failed;
    }
    
    evutil_socket_connect_(evutil_socket_t *fd_ptr, const struct sockaddr *sa, int socklen)
    

failed:
    return -1;
}

int32_t 
http_backend_connect(struct ev_http_request *r ,  struct ev_http_backend *u)
{
    ev_socket s = -1;
    int type = 0, ret = -1;
    struct bufferevent *bk_bev = u->buf_ev;
    
    type = bk_bev->sock_type ? bk_bev->sock_type : SOCK_STREAM;

    s = socket(bk_bev->src_sa.ss_family, type, 0);

    if (s < 0) {
        ev_error_msg("new socket failed errno:%d %m. ip addr:%s ->:%s\n", 
            ev_errno, bk_bev->src_addr_str, bk_bev->dst_addr_str);
        goto failed;
    }
    if (bind(s, (struct sockaddr *)&bk_bev->dst_sa, sizeof(bk_bev->dst_sa)) < 0) {
        ev_error_msg("bind socket fd[%d] closeonexec failed,errno:%d %m. ip addr:%s ->:%s\n", 
            ev_errno, bk_bev->src_addr_str, bk_bev->dst_addr_str);
        goto failed;
    }
    if (evutil_make_socket_nonblocking(s) < 0) {
        ev_error_msg("set socket fd[%d] noblocking failed,errno:%d %m. ip addr:%s ->:%s\n", 
            ev_errno, bk_bev->src_addr_str, bk_bev->dst_addr_str);
        goto failed;
    }
    
    if (evutil_make_socket_closeonexec(s) < 0) {
        ev_error_msg("set socket fd[%d] closeonexec failed,errno:%d %m. ip addr:%s ->:%s\n", 
            ev_errno, bk_bev->src_addr_str, bk_bev->dst_addr_str);
        goto failed;
    }

    if (bk_bev->sock_rcvbuf) {
        (void)evutil_set_socket_options(s, EV_SO_RCVBUF, bk_bev->sock_rcvbuf);
    }

    if (bk_bev->sock_sndbuf) {
        (void)evutil_set_socket_options(s, EV_SO_SNDBUF, bk_bev->sock_sndbuf);
    }
    
    if (bk_bev->tcp_nodelay) {
       (void)evutil_set_socket_options(s, EV_TCP_NODELAY, bk_bev->tcp_nodelay);
    }
    
    if (bk_bev->en_tproxy) {
        (void)evutil_set_socket_options(s, EV_IP_TRANSPARENT, bk_bev->en_tproxy);
    }

    event_change_fd(&bk_bev->ev_read, s);
    event_change_fd(&bk_bev->ev_write, s);
    
    ret = connect(s, &bk_bev->dst_sa, sizeof(bk_bev->dst_sa));
    if (ret < 0) {
		if (EVUTIL_ERR_CONNECT_RETRIABLE(ev_errno) || EVUTIL_ERR_IS_EAGAIN(ev_errno)) {
            struct bufferevent_private *bufev_p = BEV_UPCAST(bev);
        }else {
            (EVUTIL_ERR_CONNECT_REFUSED(e))
        }
    }
    
    return EV_OK;
failed:

    return EV_ERROR;
}


int32_t http_backend_stream_create(struct ev_http_request *r)
{   
    struct ev_http_backend *bend_stream = NULL;
    struct bufferevent *bufev = NULL;
    
    bend_stream = mm_malloc(sizeof(ev_http_backend));
    if (bend_stream == NULL) {
        ev_error_msg("malloc size[%d] failed errno:%d %m.", sizeof(ev_http_request), ev_errno); 
        goto failed;
    }
    bufev = bufferevent_socket_new(work_base, -1,
		    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    if (bufev == NULL) {
        ev_error_msg("new bufferevent_socket failed errno:%d %m.", ev_errno); 
        goto failed;
    }
    
    bend_stream->buf_ev = bufev;
    bufev->data = bend_stream;
    
    r->bk_http = bend_stream;
    bend_stream->data = r;
    return 0;
    
failed:
    //-----------------
    return -1;

}

int32_t http_init_backend_stream(struct ev_http_request *r)
{
    struct bufferevent *req_bev = NULL;
    struct bufferevent *bkend_bev = NULL;
    struct ev_http_backend *bk_stream = NULL;

    bk_stream = r->bk_http;

    bkend_bev = bk_stream->buf_ev;
    req_bev = r->buf_ev;

    bkend_bev->sock_type = req_bev->sock_type;
    
    bkend_bev->dst_sa = req_bev->dst_sa;
    memcpy(bkend_bev->dst_addr_str, req_bev->dst_addr_str, MAX_IPADDR_STR_LEN);    

    bkend_bev->src_sa = req_bev->dst_sa;
    memcpy(bkend_bev->dst_addr_str, req_bev->dst_addr_str, MAX_IPADDR_STR_LEN); 
    
    bkend_bev->is_set =  req_bev->is_set;
    //b_peer->reuseport = 
    //b_peer->deferred_accept = 
    bkend_bev->fastopen = req_bev->fastopen; 
    bkend_bev->ipv6only = req_bev->ipv6only;
    bkend_bev->http2 = req_bev->http2;
    bkend_bev->ssl = req_bev->ssl;
    bkend_bev->en_keepalive =  req_bev->en_keepalive;
    bkend_bev->tcp_keepidle =  req_bev->tcp_keepidle;
    bkend_bev->tcp_keepintvl = req_bev->tcp_keepintvl;
    bkend_bev->tcp_keepcnt = req_bev->tcp_keepcnt;
    bkend_bev->sock_rcvbuf =  req_bev->sock_rcvbuf;
    bkend_bev->sock_sndbuf = req_bev->sock_sndbuf;
    bkend_bev->en_tproxy = req_bev->en_tproxy;
    bkend_bev->tcp_nodelay = req_bev->tcp_nodelay;
    bkend_bev->tcp_crok = req_bev->tcp_crok;
    

}



int32_t http_proxy_handler_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *src, *dst;
    struct ev_http_request *r = NULL;
    struct bufferevent *b_peer = NULL;
	size_t len;
    int32_t ret = 0;
    
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
    if (len <= 0) {
        ev_error_msg("recv len=%d from normal read\n", len);
        return;
    }
    r =  mm_malloc(sizeof(ev_http_request));
    if (r == NULL) {
        ev_error_msg("malloc size[%d] failed errno:%d %m.", sizeof(ev_http_request), ev_errno); 
        goto failed;
    }
    r->buf_ev = bev;
    bev->data = r;
    
    ret = http_backend_stream_create(r);
    if (ret) {
        ev_error_msg("create backend stream failed, src:%s dst:%s", bev->src_addr_str, bev->dst_addr_str); 
        goto failed;    
    }

    ret = http_init_backend_stream(r);
    
    

failed:
    //if ()
    return -1;
}

