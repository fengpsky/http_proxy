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





int32_t http_proxy_handler_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *src, *dst;
    struct  ev_http_request *r = NULL, *peer_upstream = NULL;
    struct bufferevent *b_peer = NULL;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
    if (len <= 0) {
        ev_error_msg("recv len=%d from normal read\n", len);
        return;
    }
    r =  mm_malloc(sizeof(ev_http_request));
    if (r == NULL) {
        ev_error_msg("malloc size[%d] failed errno:%d %m.", sizeof(ev_http_request), ev_errno); 
        goto out;
    }
    r->buf_ev = bev;
    bev->data = r;
    
    peer_upstream = mm_malloc(sizeof(ev_http_request));
    if (peer_upstream == NULL) {
        ev_error_msg("malloc size[%d] failed errno:%d %m.", sizeof(ev_http_request), ev_errno); 
        goto out;
    }
    b_peer = bufferevent_socket_new(work_base, -1,
		    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    if (b_peer == NULL) {
        ev_error_msg("new bufferevent_socket failed errno:%d %m.", ev_errno); 
        goto out;
    }
    
    peer_upstream->buf_ev = b_peer;
    b_peer->data = peer_upstream;
    
    r->peer_http = peer_upstream;
    peer_upstream->peer_http = r;

    b_peer->sock_type = bev->sock_type;
    
    b_peer->dst_sa = bev->dst_sa;
    memcpy(b_peer->dst_addr_str, bev->dst_addr_str, MAX_IPADDR_STR_LEN);    

    b_peer->src_sa = bev->dst_sa;
    memcpy(b_peer->dst_addr_str, bev->dst_addr_str, MAX_IPADDR_STR_LEN); 
    
    b_peer->is_set =  bev->is_set;
    //b_peer->reuseport = 
    //b_peer->deferred_accept = 
    b_peer->fastopen = bev->fastopen; 
    b_peer->ipv6only = bev->ipv6only;
    b_peer->http2 = bev->http2;
    b_peer->ssl = bev->ssl;
    b_peer->en_keepalive =  bev->en_keepalive;
    b_peer->tcp_keepidle =  bev->tcp_keepidle;
    b_peer->tcp_keepintvl = bev->tcp_keepintvl;
    b_peer->tcp_keepcnt = bev->tcp_keepcnt;
    b_peer->sock_rcvbuf =  bev->sock_rcvbuf;
    b_peer->sock_sndbuf = bev->sock_sndbuf;
    
    
    

failed:
    //if ()
    return -1;
}

