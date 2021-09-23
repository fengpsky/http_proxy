/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
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
#ifndef LOG_INTERNAL_H_INCLUDED_
#define LOG_INTERNAL_H_INCLUDED_

#include "event2/util.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __GNUC__
#define EV_CHECK_FMT(a,b) __attribute__((format(printf, a, b)))
#define EV_NORETURN __attribute__((noreturn))
#else
#define EV_CHECK_FMT(a,b)
#define EV_NORETURN
#endif

#define EVENT_ERR_ABORT_ ((int)0xdeaddead)

#if !defined(EVENT__DISABLE_DEBUG_MODE) || defined(USE_DEBUG)
#define EVENT_DEBUG_LOGGING_ENABLED
#endif

#ifdef EVENT_DEBUG_LOGGING_ENABLED
EVENT2_CORE_EXPORT_SYMBOL extern ev_uint32_t event_debug_logging_mask_;
#define event_debug_get_logging_mask_() (event_debug_logging_mask_)
#else
#define event_debug_get_logging_mask_() (0)
#endif

EVENT2_EXPORT_SYMBOL
void event_err(int eval, const char *fmt, ...) EV_CHECK_FMT(2,3) EV_NORETURN;
EVENT2_EXPORT_SYMBOL
void event_warn(const char *fmt, ...) EV_CHECK_FMT(1,2);
EVENT2_EXPORT_SYMBOL
void event_sock_err(int eval, evutil_socket_t sock, const char *fmt, ...) EV_CHECK_FMT(3,4) EV_NORETURN;
EVENT2_EXPORT_SYMBOL
void event_sock_warn(evutil_socket_t sock, const char *fmt, ...) EV_CHECK_FMT(2,3);
EVENT2_EXPORT_SYMBOL
void event_errx(int eval, const char *fmt, ...) EV_CHECK_FMT(2,3) EV_NORETURN;
EVENT2_EXPORT_SYMBOL
void event_warnx(const char *fmt, ...) EV_CHECK_FMT(1,2);
EVENT2_EXPORT_SYMBOL
void event_msgx(const char *fmt, ...) EV_CHECK_FMT(1,2);
EVENT2_EXPORT_SYMBOL
void event_debugx_(const char *fmt, ...) EV_CHECK_FMT(1,2);


#define DEBUG_LEVEL_NUM  32 // 32个日志调试级别

#define EV_DEBUG_LEVEL1  (0x1) 
#define EV_DEBUG_LEVEL2  (0x1<<1)
#define EV_DEBUG_LEVEL3  (0x1<<2)
#define EV_DEBUG_LEVEL4  (0x1<<3)
#define EV_DEBUG_LEVEL5  (0x1<<4)
#define EV_DEBUG_LEVEL6  (0x1<<5)
#define EV_DEBUG_LEVEL7  (0x1<<6)
#define EV_DEBUG_LEVEL8  (0x1<<7)
#define EV_DEBUG_LEVEL9  (0x1<<8)
#define EV_DEBUG_LEVEL10 (0x1<<9)
#define EV_DEBUG_LEVEL11 (0x1<<10) // 初始化使用的debug log 等级
#define EV_DEBUG_LEVEL12 (0x1<<11)
#define EV_DEBUG_LEVEL13 (0x1<<12)
#define EV_DEBUG_LEVEL14 (0x1<<13)
#define EV_DEBUG_LEVEL15 (0x1<<14)
#define EV_DEBUG_LEVEL16 (0x1<<15)
#define EV_DEBUG_LEVEL17 (0x1<<16)
#define EV_DEBUG_LEVEL18 (0x1<<17)
#define EV_DEBUG_LEVEL19 (0x1<<18)
#define EV_DEBUG_LEVEL20 (0x1<<19)
#define EV_DEBUG_LEVEL21 (0x1<<20)
#define EV_DEBUG_LEVEL22 (0x1<<21)
#define EV_DEBUG_LEVEL23 (0x1<<22)
#define EV_DEBUG_LEVEL24 (0x1<<23)
#define EV_DEBUG_LEVEL25 (0x1<<24)
#define EV_DEBUG_LEVEL26 (0x1<<25)
#define EV_DEBUG_LEVEL27 (0x1<<26)
#define EV_DEBUG_LEVEL28 (0x1<<27)
#define EV_DEBUG_LEVEL29 (0x1<<28)
#define EV_DEBUG_LEVEL30 (0x1<<29)
#define EV_DEBUG_LEVEL31 (0x1<<30)
#define EV_DEBUG_LEVEL32 (0x1<<31)

extern uint32_t g_log_level;


#define ev_debug_msg(level, fmt, ...) \
        if (level & g_log_level) ev_debug_log_core(level, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
    

#if 0
#define ev_debug_msg(level, fmt, ...) \
    do { \
        if (level & g_log_level) {\
            ev_debug_log_core(level, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__); \
        }\
     }while(0)
#endif

#define ev_info_msg(fmt, ...) \
    ev_debug_log_core(EVENT_LOG_MSG, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
                  

#define ev_warn_msg(fmt, ...) \
          ev_debug_log_core(EVENT_LOG_WARN, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
              

#define ev_error_msg(fmt, ...) \
               ev_debug_log_core(EVENT_LOG_ERR, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)



EVENT2_EXPORT_SYMBOL
void event_logv_(int severity, const char *errstr, const char *fmt, va_list ap)
	EV_CHECK_FMT(3,0);

#ifdef EVENT_DEBUG_LOGGING_ENABLED
#define event_debug(x) do {			\
	if (event_debug_get_logging_mask_()) {	\
		event_debugx_ x;		\
	}					\
	} while (0)
#else
#define event_debug(x) ((void)0)
#endif

#undef EV_CHECK_FMT

#ifdef __cplusplus
}
#endif

#endif /* LOG_INTERNAL_H_INCLUDED_ */
