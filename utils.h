#ifndef __UTILS_H
#define __UTILS_H

typedef struct __circ_buf
{
    off_t   start;
    off_t   end;
    size_t  size;
    uint8_t *buf;
} circ_buf_t;

void circ_buf_put(circ_buf_t *cb, uint8_t *input, size_t sz);
int circ_buf_str(circ_buf_t *cb, const uint8_t *str, off_t off, size_t sz);

static inline int circ_buf_empty(const circ_buf_t *cb)
{
    return cb->end == cb->start;
}

static inline void circ_buf_destroy(circ_buf_t *cb)
{
    free(cb->buf);
    memset(cb, 0, sizeof(*cb));
}

static inline int circ_buf_full(const circ_buf_t *cb)
{
    return (off_t)((cb->end + 1) % cb->size) ==  cb->start;
}

static inline int circ_buf_init(circ_buf_t *cb, size_t size)
{
    cb->start = cb->end = 0;
    cb->size  = size + 1;
    cb->buf   = malloc(size);

    return (!cb->buf) ? -errno : 0;
}

static inline char circ_buf_get(circ_buf_t *cb)
{
    char ch;

    ch = cb->buf[cb->start];
    cb->start = (cb->start + 1) % cb->size;

    return ch;
}

void pretty_time(char *str);

#endif /* __UTILS_H */
