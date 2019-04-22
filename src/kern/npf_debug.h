/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   npf_debug.h
 * Author: alexk
 *
 * Created on June 21, 2016, 1:40 AM
 */

#ifndef NPF_DEBUG_H
#define NPF_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ALEXK_DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define	dprintf(...)
#endif

#ifdef ALEXK_DEBUG	
static inline void
hex_dump(const char *desc, const void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

#define d_hex_dump(p1, p2, p3) hex_dump(p1, p2, p3)

#else
#define d_hex_dump(...)
#endif

	
/* log context */
#define NPF_LOG_CONN			1
#define NPF_LOG_CONN_DBG	2
	
#ifdef NPF_LOG_DEBUG
#define npf_log g_log_func
#else
#define	npf_log(...)
#endif


#ifdef ALEXK_DEBUG2
#define dprintf2(...) printf(__VA_ARGS__)
#else
#define	dprintf2(...)
#endif

#ifdef ALEXK_DEBUG2
#define dprintf3(...) syslog(LOG_DEBUG, __VA_ARGS__)
#else
#define	dprintf2(...)
#endif


#ifdef __cplusplus
}
#endif

#endif /* NPF_DEBUG_H */

