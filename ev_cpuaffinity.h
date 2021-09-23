
#ifndef _EV_SETAFFINITY_H_INCLUDED_
#define _EV_SETAFFINITY_H_INCLUDED_


#if (EV_HAVE_SCHED_SETAFFINITY || EV_HAVE_CPUSET_SETAFFINITY)

#define NGX_HAVE_CPU_AFFINITY 1

void ev_setaffinity(uint64_t cpu_affinity);

#else

#define 
(cpu_affinity)

#endif


#endif 
