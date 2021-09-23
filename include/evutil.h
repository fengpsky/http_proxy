/*
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef EVENT1_EVUTIL_H_INCLUDED_
#define EVENT1_EVUTIL_H_INCLUDED_

/** @file evutil.h

  Utility and compatibility functions for Libevent.

  The <evutil.h> header is deprecated in Libevent 2.0 and later; please
  use <event2/util.h> instead.
*/

#include <event2/util.h>


#define EV_SO_LINGER_OFF	2000 //默认设置so_linger的时候， so_Ligner是关闭的 ，此 flag用来表示off so_ligner




/* For setsockopt(2) */
#define EV_SO_REUSEADDR	2
#define EV_SO_TYPE		3
#define EV_SO_ERROR	4
#define EV_SO_DONTROUTE	5
#define EV_SO_BROADCAST	6
#define EV_SO_SNDBUF	7
#define EV_SO_RCVBUF	8
#define EV_SO_SNDBUFFORCE	32
#define EV_SO_RCVBUFFORCE	33
#define EV_SO_KEEPALIVE	9
#define EV_SO_OOBINLINE	10
#define EV_SO_NO_CHECK	11
#define EV_SO_PRIORITY	12
#define EV_SO_LINGER	13
#define EV_SO_BSDCOMPAT	14
#define EV_SO_REUSEPORT	15


/* TCP socket options */
#define EV_TCP_NODELAY		201	/* Turn off Nagle's algorithm. */
#define EV_TCP_MAXSEG		202	/* Limit MSS */
#define EV_TCP_CORK		2033	/* Never send partially complete segments */
#define EV_TCP_KEEPIDLE		204	/* Start keeplives after this period */
#define EV_TCP_KEEPINTVL		205	/* Interval between keepalives */
#define EV_TCP_KEEPCNT		206	/* Number of keepalives before death */
#define EV_TCP_SYNCNT		207	/* Number of SYN retransmits */
#define EV_TCP_LINGER2		208	/* Life time of orphaned FIN-WAIT-2 state */
#define EV_TCP_DEFER_ACCEPT	209	/* Wake up listener only when data arrive */
#define EV_TCP_WINDOW_CLAMP	210	/* Bound advertised window */
#define EV_TCP_INFO		211	/* Information about this connection. */
#define EV_TCP_QUICKACK		212	/* Block/reenable quick acks */
#define EV_TCP_CONGESTION		213	/* Congestion control algorithm */
#define EV_TCP_MD5SIG		214	/* TCP MD5 Signature (RFC2385) */
#define EV_TCP_THIN_LINEAR_TIMEOUTS 216      /* Use linear timeouts for thin streams*/
#define EV_TCP_THIN_DUPACK         217      /* Fast retrans. after 1 dupack */
#define EV_TCP_USER_TIMEOUT	218	/* How long for loss retry before timeout */
#define EV_TCP_REPAIR		219	/* TCP sock is under repair right now */
#define EV_TCP_REPAIR_QUEUE	220
#define EV_TCP_QUEUE_SEQ		221
#define EV_TCP_REPAIR_OPTIONS	222
#define EV_TCP_FASTOPEN		223	/* Enable FastOpen on listeners */
#define EV_TCP_TIMESTAMP		224
#define EV_TCP_NOTSENT_LOWAT	225	/* limit number of unsent bytes in write queue */
#define EV_TCP_CC_INFO		226	/* Get Congestion Control (optional) info */
#define EV_TCP_SAVE_SYN		227	/* Record SYN headers for new connections */
#define EV_TCP_SAVED_SYN		228	/* Get SYN headers recorded for connection */


/*
 *	IPV6 socket options
 */

#define EV_IPV6_ADDRFORM		401
#define EV_IPV6_2292PKTINFO	402
#define EV_IPV6_2292HOPOPTS	403
#define EV_IPV6_2292DSTOPTS	404
#define EV_IPV6_2292RTHDR		405
#define EV_IPV6_2292PKTOPTIONS	406
#define EV_IPV6_CHECKSUM		407
#define EV_IPV6_2292HOPLIMIT	408
#define EV_IPV6_NEXTHOP		409
#define EV_IPV6_AUTHHDR		410	/* obsolete */
#define EV_IPV6_FLOWINFO		411

#define EV_IPV6_UNICAST_HOPS	416
#define EV_IPV6_MULTICAST_IF	417
#define EV_IPV6_MULTICAST_HOPS	418
#define EV_IPV6_MULTICAST_LOOP	419
#define EV_IPV6_ADD_MEMBERSHIP	420
#define EV_IPV6_DROP_MEMBERSHIP	421
#define EV_IPV6_ROUTER_ALERT	422
#define EV_IPV6_MTU_DISCOVER	423
#define EV_IPV6_MTU		424
#define EV_IPV6_RECVERR		425
#define EV_IPV6_V6ONLY		426
#define EV_IPV6_JOIN_ANYCAST	427
#define EV_IPV6_LEAVE_ANYCAST	428




#define EV_IP_TOS		601
#define EV_IP_TTL		702
#define EV_IP_HDRINCL	803
#define EV_IP_OPTIONS	804
#define EV_IP_ROUTER_ALERT	805
#define EV_IP_RECVOPTS	806
#define EV_IP_RETOPTS	807
#define EV_IP_PKTINFO	808
#define EV_IP_PKTOPTIONS	809
#define EV_IP_MTU_DISCOVER	810
#define EV_IP_RECVERR	811
#define EV_IP_RECVTTL	812
#define	EV_IP_RECVTOS	813
#define EV_IP_MTU		814
#define EV_IP_FREEBIND	815
#define EV_IP_EV_IPSEC_POLICY	816
#define EV_IP_XFRM_POLICY	817
#define EV_IP_PASSSEC	818
#define EV_IP_TRANSPARENT	819

#endif /* EVENT1_EVUTIL_H_INCLUDED_ */
