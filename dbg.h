#ifndef __DBG_H__
#define __DBG_H__

#define DEBUG 3

#if defined(DEBUG) && DEBUG > 0
 #define dbg(fmt, args...) printf("%s:%d: %s: " fmt "\n", __FILE__, __LINE__, __func__, ##args)
#else
 #define dbg(fmt, args...)
#endif


#endif
