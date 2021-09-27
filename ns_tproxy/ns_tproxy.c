#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/socket.h>
#include <netinet/in.h>


#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "util-internal.h"
#include "log-internal.h"
#include "nsutil.h"
#include "tproxy.h"


static void
syntax(void)
{
	fputs("Syntax:\n", stderr);
	fputs("   le-proxy [-d]  <listen-on-addr> <connect-to-addr>\n", stderr);
	fputs("Example:\n", stderr);
	fputs("   le-proxy 127.0.0.1:8888 1.2.3.4:80\n", stderr);

	exit(1);
}




int32_t g_cpu_num = 0;
extern int32_t work_cnt;
int32_t g_log_console = 0;
int32_t g_daemon_mode = 0;

static char * s_log_file = NULL;
static FILE * s_log_fp = NULL;

const char appname[] = "le-proxy";

static int max_fds = 0;
struct conn_st **conns = NULL;

#define MAX_LISTEN_PORT (6963)
#define LISTEN_PORT_CNT (64)

static struct listening_st listenv4_ary[LISTEN_PORT_CNT];

/* Signal Ignore */
void *
signal_ignore(int signo)
{
	return signal_set(signo, NULL, NULL);
}


/* Initialize signal handler */
void
signal_init(void)
{
	signal_set(SIGHUP, sighup, NULL);
	signal_set(SIGINT, sigend, NULL);
	signal_set(SIGTERM, sigend, NULL);
	signal_ignore(SIGPIPE);
    
}



/* Usage function */
static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTION...]\n", prog);
	fprintf(stderr, "  -f, --log-file=FILE          Use the log  file\n");
	fprintf(stderr, "  -d, --daemon                 process on daemon\n");
    fprintf(stderr, "  -v, --version                Display the version number\n");
	fprintf(stderr, "  -h, --help                   Display this help message\n");
}

/* Command line parser */
static void
parse_cmdline(int argc, char **argv)
{
	int c;

	struct option long_options[] = {
		{"daemon-mode",       no_argument,       0, 'd'},
		{"log-file",          required_argument, 0, 'f'},
		{"version",           no_argument,       0, 'v'},
		{"help",              no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};


	while ((c = getopt_long(argc, argv, "hvf:d", long_options, NULL)) != EOF) {
		switch (c) {
		case 'v':
			fprintf(stderr, "le-proxy version 1.0");
			exit(0);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'd':
            g_daemon_mode = 1;
			break;
		case 'f':
        	s_log_file = optarg;
        	break;
		default:
			exit(0);
			break;
		}
	}

	if (optind < argc) {
		printf("Unexpected argument(s): ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}
}


void default_write_log(int severity, const char *msg)
{
	const char *severity_str;
	switch (severity) {
	case EVENT_LOG_DEBUG:
		severity_str = "debug";
		break;
	case EVENT_LOG_MSG:
		severity_str = "msg";
		break;
	case EVENT_LOG_WARN:
		severity_str = "warn";
		break;
	case EVENT_LOG_ERR:
		severity_str = "err";
		break;
	default:
		severity_str = "???";
		break;
	}
	(void)fprintf(s_log_fp, "[%s] %s\n", severity_str, msg);
	
}

int32_t init_log(const char *logfilename)
{   
    if (logfilename != NULL) {
        s_log_fp = fopen(logfilename, "a+");
        if(s_log_fp == NULL) {
            fprintf(stderr, "open log file failed!\n");
            exit(EX_OSERR);
        }
        event_set_log_callback(default_write_log);
    }else {
        event_set_log_callback(NULL);
    }
   
    return 0;
}

int32_t  enable_limits(void)
{
    int32_t ret = 0, lock_memory = 1;
    struct rlimit rl, rlim;
    int next_fd = dup(1);
    int headroom = 10; 
    
    max_fds = 1024 + headroom + next_fd; 
    close(next_fd);
    next_fd = -1;
    
    if (getrlimit(RLIMIT_CORE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
        if(setrlimit(RLIMIT_CORE, &rl) < 0) {
            ev_error_msg("%s: setrlimit: RLIMIT_CORE failed: %m", appname);
            ret = -1;
            goto out;
        }
    }else {
        ret = -1;
        ev_error_msg("%s: getrlimit: RLIMIT_CORE failed: %m", appname);
        goto out;
    }

    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
        ev_error_msg("failed to getrlimit number of files\n");
        ret = -1;
        goto out;
    } else {
        rlim.rlim_cur = 1000000;
        rlim.rlim_max = 1000000;
        if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
            ev_error_msg("failed to set rlimit for open files. Try starting as root or requesting smaller maxconns value.\n");
            ret = -1;
            goto out;
        }
        max_fds = rlim.rlim_max;
    }
    if (lock_memory) {
#ifdef HAVE_MLOCKALL
        int res = mlockall(MCL_CURRENT | MCL_FUTURE);
        if (res != 0) {
            fprintf(stderr, "warning: -k invalid, mlockall() failed: %s\n",strerror(errno));
        }
#else
        fprintf(stderr, "warning: -k invalid, mlockall() not supported on this platform.  proceeding without.\n");
#endif
    }
     if ((conns = calloc(max_fds, sizeof(struct conn_st *))) == NULL) {
        ev_error_msg("Failed to allocate connection structures\n");
        ret = -1;
        goto out;
    }
    return ret;
    
 out: 
   return ret;
}

struct conn_st* new_listen_st(int sfd, enum conn_states init_state)
{
    struct conn_st * ev_connlistener = NULL;

    ev_connlistener = conns[sfd];
    if (ev_connlistener == NULL) {
        ev_connlistener = (struct conn_st *)calloc(1, sizeof(struct conn_st));
        
    }

}


int32_t  set_listen_fd_opt(int32_t sockfd, struct listening_st *ls)
{
    int32_t ret = 0, on = 1;

    if (evutil_make_socket_nonblocking(sockfd) < 0) {
        ev_error_msg("set socket[%d] nonlock failed errno:[%d] %m.\n", sockfd, ev_errno);
		goto out;
	}
    
    if (evutil_make_socket_closeonexec(sockfd) < 0){
        ev_error_msg("set socket[%d] closeexec failed errno:[%d] %m\n", sockfd, ev_errno);
		goto out;
    }
    
    if (ls->reuseport) {
        ret = evutil_set_socket_options(sockfd, EV_SO_REUSEPORT, on);
        if (ret) {
            ev_error_msg("set socket[%d] reuseable failed errno:[%d]%m.\n", sockfd, ev_errno);
    		goto out;
        }
    }
    
    if (ls->deferred_accept) {
        ret = evutil_set_socket_options(sockfd, EV_TCP_DEFER_ACCEPT, on);
        if (ret) {
            ev_error_msg("set socket[%d] TCP_DEFER_ACCEPT failed errno:[%d]%m.\n", sockfd, errno);
    		goto out;
        }
    }

    if (ls->ipv6only) {
        ret = evutil_set_socket_options(sockfd, EV_IPV6_V6ONLY, on);
        if (ret) {
            ev_error_msg("set socket[%d] IPV6_V6ONLY failed errno:[%d]%m.\n", sockfd, errno);
    		goto out;
        }
    }
    
    ret = evutil_set_socket_options(sockfd, EV_SO_REUSEADDR, on);
    if (ret) {
        ev_error_msg("set socket[%d] SO_REUSEADDR failed errno:[%d]%m.\n", sockfd, errno);
        goto out;
        
    }
   
    return ret;
out: 

    return -1;

}

int32_t create_listening_socketfd()
{
    int sfd = -1, i = 0, flags = 1;
    struct sockaddr_in *sin = NULL;
    struct listening_st *ls= NULL;
    int family = 0, ret = 0;

    //int socktype = SOCK_STREAM | EVUTIL_SOCK_NONBLOCK | EVUTIL_SOCK_CLOEXEC;
    
    for (i = 0; i < g_cpu_num; ++i){
        ls = (struct listening_st*)&listenv4_ary[i];
        sin= ( struct sockaddr_in *)&ls->sockaddr;
    
        sfd = socket(sin->ss_family, ls->sock_type, 0);
        if (sfd < 0) {
            goto out;
        }
        
        ret = set_listen_fd_opt(sfd, ls);
        if (ret < 0) {
            ev_error_msg("set listend fd[%d] addr_str:%s  failed\n", sfd, ls->addr_str);
            goto out
        }
        
        ret = bind(sfd, (struct sockaddr *)(sin->ai_addr), sizeof(struct sockaddr_storage));
        if (ret) {
            ev_error_msg("bind sock[%d] addr_str:%s failed errno:%d %m.\n", sfd, ls->addr_str, ev_errno);
            goto out;
        }
        if (listen(sfd, MAX_TCP_BACKLOG) < 0) {
            ev_error_msg("sfd[%d] addr_str:%s listen failed, errno[%d]%m\n", sfd, ls->addr_str,   ev_errno);
            goto out;
        }
        
    }
    
    return 0;
    
out:
    if (sfd >= 0) {
        evutil_closesocket(sfd);
        sfd = -1;
    }
    return -1;
}

int32_t  init_listen_resource()
{
    int ret = 0, int i = 0;
    uint8_t buf[MAX_IPADDR_STR_LEN + 1] = {0};
    struct sockaddr_in *sin = NULL;
    struct listening_st *ls= NULL;
    
    
    memset(listenv4_ary, 0, sizeof(listenv4_ary));
    
    for (i = 0; i < work_cnt; ++i){        
        ls = (struct listening_st*)&listenv4_ary[i];
        
        ls->sfd = -1;
        ls->sock_type = SOCK_STREAM|EVUTIL_SOCK_NONBLOCK | EVUTIL_SOCK_CLOEXEC;
        sin = (struct sockaddr_in*)&(ls->sockaddr);
        sin->sin_port = htons(MAX_LISTEN_PORT - i);
        sin->sin_addr.s_addr = htonl(0x7f000001);
        sin->sin_family = AF_INET;

        memset(buf, 0 , MAX_IPADDR_STR_LEN);
        (void)sock_ntop((struct sockaddr *)sin, sizeof(struct sockaddr_in), 
            buf, MAX_IPADDR_STR_LEN, sin->sin_port);
        memcpy(ls->addr_str, buf, MAX_IPADDR_STR_LEN);
        
        ls->backlog = 102400;
        ls->reuseport = 0;
        ls->deferred_accept = 0;
        ls->fastopen = 0;
        ls->ipv6only = 0;
        ls->http2 = 0;
        ls->ssl = 0;
        ls->en_keepalive = 1;
        ls->tcp_keepidle = 60;
        ls->tcp_keepintvl = 1;
        ls->tcp_keepcnt = 2;
        
        ls->rcvbuf = 1024000;
        ls->sndbuf = 1024000;
        
    }
    return ret;
}


static int32_t resource_init(void)
{
    
    int32_t ret = 0;
    g_cpu_num = (int)sysconf(_SC_NPROCESSORS_ONLN);

    work_cnt = min(g_cpu_num, LISTEN_PORT_CNT);
    
    g_log_level = 0xffffffffff;

    ret = enable_limits();
    if(ret) {
        goto out;
    }

    ret = init_listen_resource();
    if (ret) {
        goto out;
    }

out:

    return ret;
}

int
main(int argc, char **argv)
{
    int32_t xdaemon = 0, ret = 0;
    static struct event_base *main_base;
    
	int i;
	int socklen;

	struct evconnlistener *listener;

    parse_cmdline(argc, argv);
    
    signal_init();
    
    ret = init_log(s_log_file);
    if (ret) {
        exit(1);
    }
    
    if (xdaemon) {
        ret = init_daemon(0, 0);
        if (ret < 0) {
           ev_error_msg("init daemon failed!");
           exit(-1);
        }
    }
    // ev_pid 在daemon 后获取
    ev_pid = getpid();
    ret =save_env_argc_init_setproctitle(argc, argv);
    if (ret) {
        ev_error_msg("save env init failed ret:%d, errno:%d\n", ret, ev_errno);
        goto out;
    }
    
    ret = resource_init();
    if (ret) {
        ev_error_msg("resource init failed ret:%d, errno:%d\n", ret, ev_errno);
        goto out;
    }
    
    ret = create_listening_socketfd();
    if (ret) {
        ev_error_msg("transform listen socket info 2 file descriptor failed ret:%d\n", ret);
        goto out;
    }
    
    ret = ev_fork_process();
    if (ret) {
        ev_error_msg("fork process failed ret:%d\n", ret);
        goto out;
    }
    
	main_base = event_base_new();
	if (!main_base) {
		ev_error_msg("create  event_base_new failed");
		return 1;
	}
    ret = thread_init(g_cpu_num, main_base);
    if (ret) {
        ev_error_msg("thread init failed, ret=%d\n", ret);
        goto out;
    }
    
	event_base_dispatch(main_base);
out:
    
	evconnlistener_free(listener);
	event_base_free(main_base);

	return 0;
}
