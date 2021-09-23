#ifndef __BIT_TYPES_DEFINED_NS__
#define __BIT_TYPES_DEFINED_NS__


typedef signed char	      int8_t;
typedef unsigned char	    uint8_t;
typedef short		     int16_t;
typedef unsigned short	   uint16_t;
typedef int		     int32_t;
typedef unsigned int	   uint32_t;


/*
#if __WORDSIZE == 64
typedef unsigned long int       uint64_t;
#else
__extension__
typedef unsigned long long int  uint64_t;
#endif
*/

#if __WORDSIZE == 64

    typedef unsigned long int       uint64_t;  
    typedef long int                int64_t; 
    #define PRI "%ld"
    #define PRu "%lu"
#else

    typedef long long int           int64_t;  
    typedef unsigned long long int       uint64_t;  
    #define PRI "%lld"
    #define PRu "%llu"
#endif


#endif

