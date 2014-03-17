/* C source code header -*- coding: utf-8 -*-
 * Created: [21.41:29 Март 17 2014]
 * Modified: [21.41:30 Март 17 2014]
 *  ---------------------------
 * Author: Stanislav M. Ivankin
 * Email: lessgrep@gmail.com
 * Tags: modem,at,parser
 * License: LGPL-2.1
 *  ---------------------------
 * Description:
 */

/*
 * Code:
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>

#include "utils.h"

void circ_buf_put(circ_buf_t *cb, uint8_t *input, size_t sz)
{
    unsigned int i;

    for (i = 0; i < sz; i++) {
        cb->buf[cb->end] = input[i];
        cb->end = (cb->end + 1) % cb->size;
        if (cb->end == cb->start)
            cb->start = (cb->start + 1) % cb->size;
    }
}

int circ_buf_str(circ_buf_t *cb, const uint8_t *str, off_t off, size_t sz)
{
    unsigned int   i = 0;
    char  ch;
    off_t peek;

    peek = (off == 0) ? cb->start : off;

    do {
        if (i == 0) {
            ch = cb->buf[peek];
            peek = (peek + 1) % cb->size;
        }

        for (i = 0; i < sz; i++) {
            if (ch != str[i] || peek == cb->start)
                break;

            ch = cb->buf[peek];
            peek = (peek + 1) % cb->size;
        }

        if (i == sz) /* Found */
            return peek;

    } while (peek != cb->start);

    return -1;
}

#if 0
static int __rx_buf_str(rx_buf_t *rxb, const uint8_t *str, size_t sz)
{
    while (!__rx_buf_empty(rxb)) {
        if (i == 0) {
            ch = __rx_buf_get(rxb);
        }

        for (i = 0; i < sz; i++) {
            if (ch != str[i] || __rx_buf_empty(rxb))
                break;

            ch = __rx_buf_get(rxb);
        }

        if (i == sz)
            return 0;
    }

    return 1;
}
#endif
