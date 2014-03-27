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
#include <stdio.h>

#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <poll.h>

#include <arpa/inet.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <pthread.h>

#include <errno.h>

#include "utils.h"
#include "modem.h"

#define MODEM_DEBUG

#define POLL_FDNUM 1

#define MODEM_WAIT_FLUSH_SLEEP 50000
#define MODEM_SYSSTART_WAIT_TRIES 100

#define MODEM_READ_BYTES 256

/* Grace time */
#define AT_TIMEOUT_REPLY_WAIT 100000

#define URC_SYSSTART "^SYSSTART"
#define URC_SHUTDOWN "^SHUTDOWN"

#define IS_URC(str) (!memcmp(__rxbuf, (str), strlen(str)))

#ifdef MODEM_DEBUG
#define dbg(format, arg...)                     \
    do {                                        \
        char str[9];                            \
        pretty_time(str);                       \
        printf("[DEBUG/%s] ", str);             \
        printf(format, ##arg);                  \
    } while (0)

#else
#define dbg(x...) do {} while (0)
#endif

#define FILL_PROF(str,prof)                     \
    do {                                        \
        (str)[0] = (char)(48 + (prof));         \
        (str)[1] = '\0';                        \
    } while (0)

#define CHECK_RET(x)                            \
    do {                                        \
        modem_ret_t ret;                        \
        if ((ret = (x)) != MODEM_RET_OK)        \
            return ret;                         \
    } while (0)

#define GRACE_TIME(time)                        \
    do {                                        \
        if (time != 0)                          \
            usleep(time);                       \
    } while (0)

uint8_t __rxbuf[MODEM_RXBUF_MAXLEN];

static modem_dev_t  __modem; /* Modem control structure  */
static urc_parser_t __urcp;  /* URC parser               */
static reply_parser_t __rp;  /* Command parser           */
static at_cmd_t     __atcmd; /* AT command buffer        */

modem_cmd_t modem_cmd[] = {
    {MODEM_CMD_ECHO_SET,      "ATE#",                    1},
    {MODEM_CMD_QUALITY_GET,   "AT+CSQ",                  0},
    {MODEM_CMD_IMEI_GET,      "AT+GSN",                  0},
    {MODEM_CMD_PIN_AUTH,      "AT+CPIN=#",               1},
    {MODEM_CMD_CREG_GET,      "AT+CREG?",                0},
    {MODEM_CMD_CREG_SET,      "AT+CREG=#",               1},
    {MODEM_CMD_AT,            "AT",                      0},
    {MODEM_CMD_SICS,          "AT^SICS=#,#,#",           3},
    {MODEM_CMD_SISS,          "AT^SISS=#,#,#",           3},
    {MODEM_CMD_PACKET_SEND1,  "AT^SISW=#,#",             2},
    {MODEM_CMD_PACKET_SEND2,  "AT^SISW=#,#,#",           3},
    {MODEM_CMD_DATA_READ,     "AT^SISR=#,#",             2},
    {MODEM_CMD_CONN_START,    "AT^SISO=#",               1},
    {MODEM_CMD_CONN_STOP,     "AT^SISC=#",               1},
    {MODEM_CMD_CONN_CHECK,    "AT^SISI=#",               1},
    {MODEM_CMD_CEER,          "AT+CEER",                 0},
    {MODEM_CMD_SISS_SETUP,    "AT^SISS?",                0},
    {MODEM_CMD_SICS_SETUP,    "AT^SICS?",                0},
    {MODEM_CMD_ADC_TMP,       "AT^SBV",                  0},
    {MODEM_CMD_CLOCK_GET,     "AT+CCLK?",                0},
    {MODEM_CMD_CUSD,          "AT+CUSD=1,#",             1},
    {MODEM_CMD_CFUN,          "AT+CFUN=#,#",             2},
    {MODEM_CMD_SISE,          "AT^SISE=#",               1},
    {MODEM_CMD_BAUD_SET,      "AT+IPR=#",                1},
    {MODEM_CMD_SCFG,          "AT^SCFG=#,#",             2},
    {MODEM_CMD_RESCODE_FMT,   "ATV#",                    1},
    {MODEM_CMD_SAVE_PROFILE,  "AT^SIPS=#,#",             2},
    {MODEM_CMD_GPRS_REG,      "AT+CGATT=#",              1},
    {MODEM_CMD_FLUSH,         "\r\r\r\r\r\r",            0},
    {-1, NULL, -1},
};

#ifdef MODEM_DEBUG
static void __print_output(const unsigned char *buf, off_t s, size_t sz);
#else
#define __print_output(x...) do { } while (0)
#endif /* MODEM_DEBUG */

static void *__modem_thread(void *arg);
static void __prepare_at_cmd(modem_cmd_id_t id, va_list ap);
static modem_ret_t __send_at_cmd(void);
static void __reset_reply_parser(void);
static int __process_DATA(const uint8_t *buf, size_t sz, int cmd_mode);
static void __process_URC(const uint8_t *buf, size_t sz);
static void __parse_URC(void);
static modem_ret_t __get_reply(uint8_t **data, ssize_t *len, int *res);

modem_ret_t modem_init(const char *path)
{
    int            ret;
    struct termios term;
    char           c;

    memset(&__modem, 0, sizeof(__modem));
    memset(&__urcp,  0, sizeof(__urcp));
    memset(&__rp,    0, sizeof(__rp));
    memset(&__atcmd, 0, sizeof(__atcmd));
    memset(&term,    0, sizeof(term));

    /* We dont want to hang on read call, better use nonblocking approach. */
    __modem.fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (__modem.fd < 0)
        return MODEM_RET_IO;

    /* Serial setup */
    term.c_cflag    = CREAD | CS8;
    term.c_cc[VMIN] = 1;
    cfsetispeed(&term, B115200);
    cfsetospeed(&term, B115200);
    tcsetattr(__modem.fd, TCSANOW, &term);

    dbg("Flushing modem.\n");

    /* Flush buffer */
    while (read(__modem.fd, &c, 1) != -1);
    if (errno != EAGAIN) {
        close(__modem.fd);
        return MODEM_RET_IO;
    }

    ret = pthread_mutex_init(&__modem.lock, NULL);
    if (ret != 0) {
        ret = errno;
        close(__modem.fd);
        if (ret == ENOMEM)
            return MODEM_RET_MEM;
        /* Any other possibility considered system related error, probably
           resources */
        return MODEM_RET_SYS;
    }

    /* Setup initial status and reset error variable */
    __modem.status = MODEM_STATUS_ONLINE;
    __modem.err    = 0;

    dbg("Creating modem output parser process.\n");

    /* Start up modem parser thread */
    ret = pthread_create(&__modem.tid, NULL, __modem_thread, NULL);
    if (ret != 0) {
        close(__modem.fd);
        pthread_mutex_destroy(&__modem.lock);
        return MODEM_RET_SYS;
    }

    /* Initial modem flush just in case */
    modem_send_cmd(MODEM_CMD_FLUSH, NULL, NULL, NULL, 0);

    return MODEM_RET_OK;
}

void modem_destroy(void)
{
    pthread_mutex_lock(&__modem.lock);
    pthread_detach(__modem.tid);
    pthread_cancel(__modem.tid);
    pthread_mutex_destroy(&__modem.lock);

    close(__modem.fd);
}

void modem_get_status(modem_status_t *status, modem_err_t *err)
{
    pthread_mutex_lock(&__modem.lock);
    *status = __modem.status;
    *err    = __modem.err;
    pthread_mutex_unlock(&__modem.lock);
}

modem_ret_t modem_get_connstate(unsigned int prof, conn_state_t *s)
{
    char sprof[2];
    modem_ret_t ret;
    int res;
    uint8_t *buf;
    ssize_t len;

    FILL_PROF(sprof, prof);

    ret = modem_send_cmd(MODEM_CMD_CONN_CHECK, &buf, &len, &res, 0, sprof);
    if (ret != MODEM_RET_OK)
        return ret;

    if (res != AT_RESULT_CODE_OK) {
        free(buf);
        return MODEM_RET_AT;
    }

    sscanf((const char *)(buf + 1), "^SISI: %d,%d,%d,%d,%d,%d\r0",
           &s->prof_id, &s->state, &s->rx, &s->tx, &s->ack, &s->unack);

    free(buf);

    return MODEM_RET_OK;
}

modem_ret_t modem_get_err(int *loc, int *reason)
{
    uint8_t     *reply;
    ssize_t     len;
    modem_ret_t ret;
    int         unused, sret;

    ret = modem_send_cmd(MODEM_CMD_CEER, &reply, &len, NULL, 0);
    if (ret != MODEM_RET_OK)
        return ret;

    sret = sscanf((const char *)reply, "\r+CEER: %d,%d,%d\r\n",
                  loc, reason, &unused);
    free(reply);

    if (sret == EOF || sret != 3)
        return MODEM_RET_PARSER;

    return MODEM_RET_OK;
}

modem_ret_t modem_send_raw(const uint8_t *data, size_t len)
{
    int ret;

    ret = write(__modem.fd, data, len);
    if (ret == -1 || (unsigned int)ret < len)
        return MODEM_RET_IO;

    return MODEM_RET_OK;
}

modem_ret_t modem_send_cmd(modem_cmd_id_t id, uint8_t **reply, ssize_t *sz,
                           int *res, unsigned int delay, ...)
{
    va_list           ap;
    modem_ret_t       ret;
    modem_status_t    status;
    struct timespec   tstart, tnow;

    /* TODO: Process SISR separately */

    status = __modem.status;
    /* Check if modem is initialized and ready to serve commands */
    if ((status & MODEM_STATUS_ONLINE) == 0)
        return MODEM_RET_AT;

    /* Prepare and send AT command, set appropriate flags for appropriate
       parser to be called */
    pthread_mutex_lock(&__modem.lock);
    va_start(ap, delay);
    __prepare_at_cmd(id, ap);
    va_end(ap);
    if (reply) {
        /* If we are issuing SISR command set appropriate flag, so we wont
           crash parsing binary data, thinking its a regular command */
        if (id == MODEM_CMD_DATA_READ)
            __modem.status |= MODEM_STATUS_DATACHECK;
        else
            __modem.status |= MODEM_STATUS_CMDCHECK;

        __reset_reply_parser();
    }

    ret = __send_at_cmd();

    /* TODO: Reset parsers */

    pthread_mutex_unlock(&__modem.lock);
    if (ret != MODEM_RET_OK)
        return ret;

    /* Wait a bit before returning control, we easily can spam modem with
       commands */
    GRACE_TIME(AT_TIMEOUT_REPLY_WAIT);

    /* Check if reply is actually needed */
    if (!reply)
        return MODEM_RET_OK;

    /* Set default timer timeout if delay was not specified */
    if (delay == 0)
        delay = REPLY_DEFAULT_TIMEOUT;
    clock_gettime(CLOCK_MONOTONIC, &tstart);

    do {
        pthread_mutex_lock(&__modem.lock);
        /* Check if modem is operating correctly, since it can go down while
           wre are waiting for command reply */
        if ((__modem.status & MODEM_STATUS_ONLINE) == 0)
            return MODEM_RET_AT;
        ret = __get_reply(reply, sz, res);
        pthread_mutex_unlock(&__modem.lock);
        if (ret == MODEM_RET_OK)
            break;
        /* Wait small amount of time before requesting reply again */
        GRACE_TIME(AT_TIMEOUT_REPLY_WAIT);
        clock_gettime(CLOCK_MONOTONIC, &tnow);
    } while ((tnow.tv_sec - tstart.tv_sec) < delay);

    /* Timeout checking */
    if (ret != MODEM_RET_OK) {
        pthread_mutex_lock(&__modem.lock);
        __modem.status &= ~MODEM_STATUS_CMDCHECK;
        pthread_mutex_unlock(&__modem.lock);
        return MODEM_RET_TIMEOUT;
    }

    if (res != NULL)
        dbg("Command result=%d\n", *res);

    return ret;
}

modem_ret_t modem_conn_start(unsigned int prof)
{
    uint8_t     sprof[2], *reply;
    ssize_t     sz;
    modem_ret_t ret;
    int         res;

    if (prof > 9)
        return MODEM_RET_PARAM;

    FILL_PROF(sprof, prof);

    ret = modem_send_cmd(MODEM_CMD_CONN_START, &reply, &sz, &res, 0, sprof);
    if (ret != MODEM_RET_OK)
        return ret;

    free(reply);

    if (res != 0)
        return MODEM_RET_AT;

    return MODEM_RET_OK;
}

modem_ret_t modem_conn_stop(unsigned int prof)
{
    uint8_t     *reply, sprof[2];
    ssize_t     sz;
    modem_ret_t ret;
    int         res;

    if (prof > 9)
        return MODEM_RET_PARAM;

    FILL_PROF(sprof, prof);

    ret = modem_send_cmd(MODEM_CMD_CONN_STOP, &reply, &sz, &res, 0, sprof);
    if (ret != MODEM_RET_OK)
        return ret;

    free(reply);

    if (res != 0)
        return MODEM_RET_AT;

    return MODEM_RET_OK;
}

modem_ret_t modem_base_config(void)
{
    int     ret, res;
    ssize_t sz;
    uint8_t *reply;

    /* Basic modem configuration
     * 1. Set bitrate
     * 2. Change command response format
     * 3. Turn on CREG URC messages
     */
    modem_send_cmd(MODEM_CMD_BAUD_SET,    NULL, NULL, NULL, 0, "115200");
    modem_send_cmd(MODEM_CMD_RESCODE_FMT, NULL, NULL, NULL, 0, "0");
    modem_send_cmd(MODEM_CMD_CREG_SET,    NULL, NULL, NULL, 0, "2");

    /* Try to register with GPRS service */
    ret = modem_send_cmd(MODEM_CMD_GPRS_REG, &reply, &sz, &res,
                         REPLY_REG_TIMEOUT,"1");
    if (ret != MODEM_RET_OK)
        return ret;

    free(reply);

    if (res != 0)
        return MODEM_RET_AT;

    /* Setup internet connection URC's */
    modem_send_cmd(MODEM_CMD_SCFG, NULL, NULL, NULL, 0, "Tcp/WithURCs", "on");

    return MODEM_RET_OK;
}

modem_ret_t modem_prof_config(const char *id, const char *type,
                              const char *dns1, const char *dns2,
                              const char *apn, const char *user,
                              const  char *passwd)
{
    /* Configure internet connection setup profile */
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,0,id,"CONTYPE",type);
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,0,id,"DNS1",   dns1);
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,0,id,"DNS2",   dns2);
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,0,id,"PASSWD", passwd);
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,0,id,"USER",   user);
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,0,id,"APN",    apn);

    return MODEM_RET_OK;
}

modem_ret_t modem_sock_config(const char *id, const char *sics_id,
                              const char *addr)
{
    uint8_t *reply;
    int     res;
    ssize_t sz;

    modem_send_cmd(MODEM_CMD_SISS,NULL,NULL,NULL,0, id, "CONID",   sics_id);
    modem_send_cmd(MODEM_CMD_SISS,NULL,NULL,NULL,0, id, "SRVTYPE", "Socket");
    modem_send_cmd(MODEM_CMD_SISS,&reply,&sz,&res,0, id, "ADDRESS", addr);

    free(reply);

    return MODEM_RET_OK;
}

modem_ret_t modem_http_config(const char *id, const char *sics_id,
                              const char *addr)
{
    ssize_t sz;
    int     res;
    uint8_t *reply;

    modem_send_cmd(MODEM_CMD_SISS,NULL,NULL,NULL,0, id, "CONID",    sics_id);
    modem_send_cmd(MODEM_CMD_SISS,NULL,NULL,NULL,0, id, "SRVTYPE",  "Http");
    modem_send_cmd(MODEM_CMD_SISS,NULL,NULL,NULL,0, id, "hcMethod", "0");
    modem_send_cmd(MODEM_CMD_SISS,NULL,NULL,NULL,0, id, "secOpt",   "-1");
    modem_send_cmd(MODEM_CMD_SISS,&reply,&sz,&res,0, id, "ADDRESS",  addr);

    free(reply);

    return MODEM_RET_OK;
}

modem_ret_t modem_save_config(void)
{
    /* Save profule */
    modem_send_cmd(MODEM_CMD_SAVE_PROFILE, NULL, NULL, NULL, 0, "all", "save");

    return MODEM_RET_OK;
}

modem_ret_t modem_send_packet(unsigned int prof,
                              const uint8_t *data, size_t len)
{
    char     plen[5], sprof[2];
    uint8_t  ps[2];
    uint16_t len_no;

    if ((len + 2) & 0x1FFFF0000)
        return MODEM_RET_PARAM;
    if (prof > 9)
        return MODEM_RET_PARAM;

    FILL_PROF(sprof, prof);

    len_no = htons(len);
    memcpy(ps, &len_no, 2);

    snprintf(plen, 5, "%d", (uint16_t)(len + 2));

    pthread_mutex_lock(&__modem.lock);
    if ((__modem.status & MODEM_STATUS_WREADY) == 0) {
        pthread_mutex_unlock(&__modem.lock);
        return MODEM_RET_AT;
    }

    __modem.status &= ~MODEM_STATUS_WREADY;
    pthread_mutex_unlock(&__modem.lock);

    CHECK_RET(modem_send_cmd(MODEM_CMD_PACKET_SEND1,
                             NULL, NULL, NULL, 0, sprof, plen));
    CHECK_RET(modem_send_raw(ps, 2));
    CHECK_RET(modem_send_raw(data, len));
    CHECK_RET(modem_send_cmd(MODEM_CMD_PACKET_SEND2,
                             NULL, NULL, NULL, 0, sprof, "0", "0"));

    return MODEM_RET_OK;
}

/* ==================================================================== */

static void *__modem_thread(void *arg)
{
    ssize_t       sz;
    int           ret, timeout;
    struct pollfd fds[POLL_FDNUM];
    uint8_t       buf[MODEM_READ_BYTES];

    (void)arg;

    /* Using poll because of system requirements */
    for (;;) {
        fds[0].fd      = __modem.fd;
        fds[0].events  = POLLIN;
        fds[0].revents = 0;

        timeout = 0;

        ret = poll(fds, 1, 1);
        if (ret < 0)
            continue;
        else if (ret == 0)
            timeout = 1;

        if (timeout) continue;

        if (fds[0].revents & POLLIN) {
            do {
                pthread_mutex_lock(&__modem.lock);

                sz = read(fds[0].fd, buf, MODEM_READ_BYTES);
                if (sz <= 0) {
                    if (sz == -1 && errno != EAGAIN) {
                        __modem.status |= MODEM_STATUS_ERR;
                        __modem.err    |= MODEM_ERR_IO;
                        dbg("Err=(%d:%d)\n", (int)sz, errno);
                    } else if (sz == 0) {
                        __modem.status |= MODEM_STATUS_ERR;
                        __modem.err    |= MODEM_ERR_EOF;
                    }
                    pthread_mutex_unlock(&__modem.lock);
                    continue;
                }

                /* NOTE: Unless we retrieve reply URC parsing isnt possible
                   with current approach, maybe we should move URC parsing to
                   a different buffer or change algorithm somehow?
                   If reply check isn't performed __rxbuf data may be
                   overwritten by URC */

                if (__modem.status & MODEM_STATUS_REPLY) {
                    pthread_mutex_unlock(&__modem.lock);
                    continue;
                }

                /* Only 1 parser can be active at a time, else we may receive
                   false positive matches, esp when alot of binary data come
                   in */
                if (__modem.status & MODEM_STATUS_DATACHECK) { /* SISR */
                    if (__process_DATA(buf, sz, 0) == 1) {
                        __modem.status &= ~MODEM_STATUS_DATACHECK;
                        __modem.status |= MODEM_STATUS_REPLY;
                    }
                } else if (__modem.status & MODEM_STATUS_CMDCHECK) {
                    if (__process_DATA(buf, sz, 1) == 1) { /* CMD */
                        __modem.status &= ~MODEM_STATUS_CMDCHECK;
                        __modem.status |=  MODEM_STATUS_REPLY;
                    }
                } else /* URC */
                    __process_URC(buf, sz);

                pthread_mutex_unlock(&__modem.lock);
            } while (sz > 0);
        }
    }

    return NULL;
}

static int __process_DATA(const uint8_t *buf, size_t sz, int cmd_mode)
{
    unsigned int i;
    uint8_t      *ptr;

    for (i = 0; i < sz; i++) {
        /* Check for buffer overflow */
        if (__rp.ind == MODEM_RXBUF_MAXLEN) {
            __reset_reply_parser();
            return -1;
        }

        switch (__rp.state) {
        case REPLY_PARSER_NONE: /* Check for command echo */
            if (__atcmd.buf[__atcmd.ind] == buf[i])
                __atcmd.ind ++;
            else /* No match, reset CMD search */
                __atcmd.ind = 0;

            if (__atcmd.ind == __atcmd.len) { /* Command echo match */
                __atcmd.ind = 0;
                if (cmd_mode == 0)
                    /* If issued command is SISR, look for <^SISR: n,m> */
                    __rp.state  = REPLY_PARSER_SISR;
                else
                    /* Else, parse for regular command output */
                    __rp.state  = REPLY_PARSER_REPLY;
            }
            break;
        case REPLY_PARSER_SISR:
            __rxbuf[__rp.ind++] = buf[i];
            if (buf[i] == '\n') { /* \r\n - ending combination for ^SISR */
                __rp.rlen = strtol((const char *)(__rxbuf+10),(char **)&ptr,10);
                __rp.ind  = 0;
                if (ptr == __rxbuf + 10) {
                    __reset_reply_parser();
                    __rp.state = REPLY_PARSER_NONE;
                }

                if (__rp.rlen <= 0)
                    __rp.state = REPLY_PARSER_DELIM;
                else
                    __rp.state = REPLY_PARSER_DATA;
            }
            break;
        case REPLY_PARSER_DATA:
            __rxbuf[__rp.ind++] = buf[i];
            if (__rp.ind == __rp.rlen)
                __rp.state = REPLY_PARSER_REPLY;
            break;
        case REPLY_PARSER_REPLY: /* Check for regular command reply */
            __rxbuf[__rp.ind++] = buf[i];
            /* Looking for \r as a sign of next line or endof reply */
            if (buf[i] == '\r')
                __rp.state = REPLY_PARSER_DELIM;
            break;
        case REPLY_PARSER_DELIM:
            if (isdigit(buf[i])) { /* if next ch == \r, reply found */
                __rp.resp = __rxbuf + __rp.ind;
                __rxbuf[__rp.ind++] = buf[i];
                __rp.state = REPLY_PARSER_ENDCHECK;
            } else if (buf[i] != '\n' && buf[i] != '\r') { /* Next line */
                __rp.state = REPLY_PARSER_REPLY;
                __rxbuf[__rp.ind++] = buf[i];
            }
            break;
        case REPLY_PARSER_ENDCHECK:
            if (buf[i] == '\r') { /* Done */
                if (cmd_mode)
                    __rp.rlen = (unsigned int)(__rp.resp - __rxbuf);
                return 1;
            } else { /* Continue looking for an end */
                __rxbuf[__rp.ind++] = buf[i];
                __rp.resp    = NULL;
                __rp.state = REPLY_PARSER_REPLY;
            }
            break;
        }
    }

    return 0;
}

static void __process_URC(const uint8_t *buf, size_t sz)
{
    unsigned int i;

    for (i = 0; i < sz; i++) {
        switch (__urcp.state) {
        case URC_PARSER_NONE:
            if (buf[i] == '+' || buf[i] == '^')  {
                __urcp.ind               = 0;
                __rxbuf[__urcp.ind++] = buf[i];
                __urcp.state          = URC_PARSER_CMD_CHECK;
                continue;
            }
            break;
        case URC_PARSER_CMD_CHECK:
            if (buf[i] == '\r') {
                if (!memcmp(__rxbuf, URC_SYSSTART, 9)) {
                    /* Modem has been started/restarted, reset states */
                    dbg("SYSSTART event.\n");
                    __modem.status = 0;
                    __modem.err    = 0;
                } else if (!memcmp(__rxbuf, URC_SHUTDOWN, 9)) {
                    /* Modem entered shutdown mode, modem op blocked */
                    __modem.status &= ~MODEM_STATUS_ONLINE;
                    __modem.status |=  MODEM_STATUS_SHUTDOWN;
                }

                __urcp.state = URC_PARSER_NONE;
            } else if (buf[i] == ':') {
                __urcp.state = URC_PARSER_DATA_CHECK;
                __urcp.cmd_end   = (char *)(buf + i);
            }

            __rxbuf[__urcp.ind++] = buf[i];

            continue;
        case URC_PARSER_DATA_CHECK:
            if (buf[i] == '\r')
                __urcp.state = URC_PARSER_DATA_ENDCHECK;
            else {
                __rxbuf[__urcp.ind++] = buf[i];
            }

            continue;
        case URC_PARSER_DATA_ENDCHECK:
            /* <CMDID>: <DATA> */
            if (buf[i] == '\n') {
                __rxbuf[__urcp.ind] = '\0';
                __parse_URC();
            }
            __urcp.state = URC_PARSER_NONE;
            break;
        }
    }
}

static void __parse_URC_CREG(void)
{
    int reg;
    int net_lac, net_cellid;

    reg = net_lac = net_cellid = -1;

    if (strlen((const char *)__rxbuf) > 22) { /* CREG request reply in 2nd
                                                 mode while registered */
        reg        = strtol((const char *)(__rxbuf + 9),  NULL, 10);
        net_lac    = strtol((const char *)(__rxbuf + 12), NULL, 16);
        net_cellid = strtol((const char *)(__rxbuf + 19), NULL, 16);
    } else if (strlen((const char *)__rxbuf) > 10) { /* CREG event in 2nd
                                                          mode while reg. */
        reg        = strtol((const char *)(__rxbuf + 7),  NULL, 10);
        net_lac    = strtol((const char *)(__rxbuf + 10), NULL, 16);
        net_cellid = strtol((const char *)(__rxbuf + 17), NULL, 16);
    } else if (strlen((const char *)__rxbuf) > 8) /* CREG request reply in 2nd
                                                     mode while not reg. */
        reg = strtol((const char *)(__rxbuf + 9), NULL, 10);
    else /* CREG even in 2nd mode while not registered */
        reg = strtol((const char *)(__rxbuf + 7), NULL, 10);

    if (reg != -1) {
        if (reg == MODEM_AT_REG_OK || reg == MODEM_AT_REG_ROAMING)
            __modem.status |= MODEM_STATUS_REG;
        else {
            __modem.status &= ~MODEM_STATUS_REG;
        }
    }
}

static void __parse_URC_SISW(void)
{
    int prof, urcCode;

    prof = urcCode = -1;
    (void)prof;

    prof    = strtol((const char *)(__rxbuf + 7), NULL, 10);
    urcCode = strtol((const char *)(__rxbuf + 9), NULL, 10);

    if (urcCode == AT_URC_SISW_WREADY)
        __modem.status |= (MODEM_STATUS_CONN|MODEM_STATUS_WREADY);
    else if (urcCode == AT_URC_SISW_WCLOSED)
        __modem.status &= ~(MODEM_STATUS_CONN|MODEM_STATUS_WREADY);
}

static void __parse_URC_SISR(void)
{
    int prof, urcCode;

    prof = urcCode = -1;
    (void)prof;

    prof    = strtol((const char *)(__rxbuf + 7), NULL, 10);
    urcCode = strtol((const char *)(__rxbuf + 9), NULL, 10);

    if (urcCode == AT_URC_SISR_RPEND)
        __modem.status |= MODEM_STATUS_RPEND;
    else if (urcCode == AT_URC_SISR_RCLOSED)
        __modem.status &= ~(MODEM_STATUS_CONN|MODEM_STATUS_RPEND);

    dbg("SISR urcCode=%d\n", urcCode);
}

static void __parse_URC_SIS(void)
{
    unsigned int prof;
    unsigned int urc_cause, urc_infoid;

    prof       = strtol((const char *)(__rxbuf + 6),  NULL, 10);
    urc_cause  = strtol((const char *)(__rxbuf + 8),  NULL, 10);
    urc_infoid = strtol((const char *)(__rxbuf + 10), NULL, 10);

    dbg("Error. Profile=%d; Cause=%d; Info=%d\n", prof, urc_cause, urc_infoid);

    if (urc_cause == 0) {
        if (urc_infoid == URC_INFOID_SOCK_PEERCLOSE) {
            __modem.status &= ~(MODEM_STATUS_CONN|MODEM_STATUS_RPEND|
                                MODEM_STATUS_WREADY);
        }
    }
}


static void __parse_URC(void)
{
    dbg("<URC>(%X):  ", __modem.status);
    __print_output((uint8_t *)__rxbuf, 0, __urcp.ind);

    if (IS_URC("+CREG:")) {
        __parse_URC_CREG();
    } else if (IS_URC("^SISW:")) {
        __parse_URC_SISW();
    } else if (IS_URC("^SISR:")) {
        __parse_URC_SISR();
    } else if (IS_URC("^SIS:")) {
        __parse_URC_SIS();
    }
}

static void __reset_reply_parser(void)
{
    __rp.state  = REPLY_PARSER_NONE;
    __rp.ind    = 0;
    __rp.rlen   = 0;
    __rp.resp = NULL;
    memset(__rxbuf, 0, MODEM_RXBUF_MAXLEN);
}

static modem_ret_t __send_at_cmd(void)
{
    modem_ret_t ret;

    dbg("Sending: ");
    __print_output((unsigned char *)__atcmd.buf, 0, __atcmd.len + 1);

    /* Just in case we have a command beng processed by modem */
    modem_send_raw((uint8_t *)"\r", 1);
    ret = modem_send_raw((uint8_t *)__atcmd.buf, __atcmd.len + 1);
    if (ret != MODEM_RET_OK) {
        __modem.status |= MODEM_STATUS_ERR;
        __modem.err    |= MODEM_ERR_IO;
        return ret;
    }

    return MODEM_RET_OK;
}

static void __prepare_at_cmd(modem_cmd_id_t id, va_list ap)
{
    int         args;
    const char  *ptr_s;
    char        *ptr_d, *arg;
    modem_cmd_t *cmd;

    cmd   = &modem_cmd[id];
    args  = cmd->args_num;
    ptr_s = cmd->cmd;

    ptr_d       = __atcmd.buf;
    __atcmd.len = 0;

    if (args == 0) {
        /* If theres no arguments to a command, just copy it in cmd buffer */
        __atcmd.len = strlen(cmd->cmd);
        memcpy(__atcmd.buf, cmd->cmd, __atcmd.len);
    } else {
        while (args) {
            if (*ptr_s != '#') {
                /* If its not an arg markup, just byte copy */
                *ptr_d ++ = *ptr_s;
                __atcmd.len ++;
            } else {
                /* Arg markup, fill it with supplied data */
                arg = va_arg(ap, char *);
                memcpy(ptr_d, arg, strlen(arg));
                ptr_d += strlen(arg);
                __atcmd.len += strlen(arg);
                args --;
            }

            ptr_s++;
        }
    }

    /* Set <LN>.  Terminate with '\0' for debug purposes. */
    __atcmd.buf[__atcmd.len]     = '\r';
    __atcmd.buf[__atcmd.len + 1] = '\0';
}

static modem_ret_t __get_reply(uint8_t **data, ssize_t *len, int *res)
{
    dbg("Looking for %s\n", __atcmd.buf);

    /* If reply was found */
    if ((__modem.status & MODEM_STATUS_REPLY) == 0)
        return MODEM_RET_PARSER;

    dbg("Result(%d): ", __rp.ind);
    __print_output((uint8_t *)__rxbuf, 0, __rp.ind);

    /* Return reply size, only actual answer is counter, command echo and
       command executiong result excluded */
    *len  = __rp.rlen;

    if (__rp.rlen <= 0)
        *data = NULL;
    else {
        if (!(*data = malloc(__rp.rlen)))
            return MODEM_RET_MEM;
        memcpy(*data, __rxbuf, __rp.rlen);
    }

    /* If res is supplied, return AT result code */
    if (res != NULL)
        *res = strtol((const char *)__rp.resp, NULL, 10);

    __modem.status &= ~MODEM_STATUS_REPLY;
    /* Get rid of command. We have to check for SISW and SISR URC's and
       sometimes they can match with commands/replies being looked for. */
    __atcmd.buf[0] = '\0';
    __atcmd.ind = __atcmd.len = 0;

    return MODEM_RET_OK;
}

#ifdef MODEM_DEBUG
static void __print_output(const unsigned char *buf, off_t s, size_t sz)
{
    unsigned int i;
    const unsigned char *ptr = buf + s;

    for (i = 0; i < sz; i++, ptr++) {
        if (*ptr == '\r') {
            putchar('\\');
            putchar('r');
        } else if (*ptr == '\n') {
            putchar('\\');
            putchar('n');
        } else if (*ptr == '\t') {
            putchar('\\');
            putchar('t');
        } else if (*ptr > 127 || *ptr < 32) {
            printf("\\x%02x", *ptr);
        } else
            putchar(*ptr);
    }

    printf("\n");
}
#endif

#if 0
modem_ret_t modem_get_data(uint8_t **data, ssize_t *len, ...)
{
    char         sprof[2];//, sdlen[4];
    modem_status_t    status;
    uint8_t      buf[1500 + 15]; /* 1500b of packet + 15b at max of AT URC */
    uint8_t      *ptr;
    int          res, r_read;
    unsigned int r_prof;
    ssize_t      sz;
    uint16_t     psz;
    va_list ap;
    modem_ret_t ret;

    status = __modem.status;
    if ((status & MODEM_STATUS_ONLINE) == 0)
        return MODEM_RET_AT;

//    if (dlen > 1500 || sscanf(sdlen, "%hu", dlen) == EOF)
//        return MODEM_RET_PARAM;

//    FILL_PROF(sprof, prof);

    /* Prepare SISR command and set flag to parse binary data */
    pthread_mutex_lock(&__modem.lock);
    /* Clear read pending flag */
    if (__modem.status & MODEM_STATUS_RPEND)
        __modem.status &= ~MODEM_STATUS_RPEND;
    va_start(ap, len);
    __prepare_at_cmd(MODEM_CMD_DATA_READ, ap);
    va_end(ap);
    __modem.status |= MODEM_STATUS_DATACHECK;
    __reset_data_parser();
    ret = __send_at_cmd();
    pthread_mutex_unlock(&__modem.lock);

    if (ret != MODEM_RET_OK)
        return ret;

    GRACE_TIME(AT_TIMEOUT_REPLY_WAIT);

    r_prof = strtol((const char *)(buf + 8), NULL, 10);
    r_read = strtol((const char *)(buf + 10), (char **)&ptr, 10);
    /* Check if profile number returned match profile number requested */
//    if (r_prof != prof)
//        return MODEM_RET_AT;
    /* Check that we have parsed leading <SISR: n,m> string correctly */
    if ((buf + 10) == ptr)
        return MODEM_RET_PARSER;
    else if (r_read <= 0)
        return MODEM_RET_AT;

    memcpy(&psz, ptr + 1, 2);
    psz = ntohs(psz);

    dbg("Packet size=%d. Read size=%d\n", psz, r_read);

    /* Check if we received message body correctly */
    if ((psz + 2) != r_read)
        return MODEM_RET_PARSER;

    *data = calloc(1, psz);
    if (!*data)
        return MODEM_RET_MEM;

    *len = psz;
    memcpy(*data, ptr + 3, psz); /* Exclude leading \r and frame header */

    dbg(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    __print_output(*data, 0, *len);
    dbg("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

    return MODEM_RET_OK;
}
#endif
