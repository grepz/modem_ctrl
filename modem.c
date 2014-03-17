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

#define MODEM_WAIT_REPLY_TRIES 100
#define MODEM_WAIT_REPLY_SLEEP 100000
#define MODEM_WAIT_FLUSH_SLEEP 50000

#define MODEM_SYSSTART_WAIT_TRIES 100

#define MODEM_CMDBUF_SZ  256
#define MODEM_RXBUF_SZ   2048
#define MODEM_READ_BYTES 256

/* Default reply timeout */
#define AT_TIMEOUT_REPLY_WAIT 50000

#define URC_SYSSTART "^SYSSTART"
#define URC_SHUTDOWN "^SHUTDOWN"

#define IS_URC(str) (!memcmp(__urcp.buf, (str), strlen(str)))

#ifdef MODEM_DEBUG
#define dbg(format, arg...) printf("[DEBUG] "format, ##arg)
#else
#define dbg(x...) do {} while (0)
#endif

#define CHECK_RET(x)                            \
    do {                                        \
        modem_ret_t ret;                        \
        if ((ret = (x)) != MODEM_RET_OK)        \
            return ret;                         \
    } while (0)

static modem_dev_t  __modem; /* Modem control structure  */
static urc_parser_t __urcp;  /* URC parser               */
static cmd_parser_t __cmdp;  /* Command parser           */
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
    {MODEM_CMD_FLUSH,         "\r\r\r\r\r\r",            0},
    {-1, NULL, -1},
};

static void __print_output(const unsigned char *buf, off_t s, size_t sz);
static void *__modem_thread(void *arg);

static void __reset_CMD_parser(void);

static int  __process_CMD(const char *buf, size_t sz);
static void __process_URC(const char *buf, size_t sz);
static void __parse_URC(void);

modem_ret_t modem_init(const char *path)
{
    int            ret;
    struct termios term;
    char           c;

    memset(&__modem, 0, sizeof(__modem));
    memset(&__urcp,  0, sizeof(__urcp));
    memset(&__cmdp,  0, sizeof(__cmdp));
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

    dbg("Creating modem process.\n");

    /* Start up modem parser thread */
    ret = pthread_create(&__modem.tid, NULL, __modem_thread, NULL);
    if (ret != 0) {
        close(__modem.fd);
        pthread_mutex_destroy(&__modem.lock);
        return MODEM_RET_SYS;
    }

    /* Setup initial status and reset error variable */
    pthread_mutex_lock(&__modem.lock);
    __modem.status = MODEM_STATUS_ONLINE;
    __modem.err    = 0;
    pthread_mutex_unlock(&__modem.lock);

    modem_send_raw((uint8_t *)"\r\r\r\r\r\r\r\r\r\r", 10);

    return 0;
}

void modem_destroy(void)
{
    pthread_mutex_lock(&__modem.lock);
    pthread_detach(__modem.tid);
    pthread_cancel(__modem.tid);
    pthread_mutex_destroy(&__modem.lock);

    close(__modem.fd);
}

void modem_status_get(modem_status_t *status, modem_err_t *err)
{
    pthread_mutex_lock(&__modem.lock);
    *status = __modem.status;
    *err    = __modem.err;
    pthread_mutex_unlock(&__modem.lock);
}

modem_ret_t modem_get_err(int *loc, int *reason)
{
    char        reply[128];
    ssize_t     len;
    modem_ret_t ret;
    int         unused, sret;

    ret = modem_send_cmd(MODEM_CMD_CEER, reply, &len, NULL, 1);
    if (ret != MODEM_RET_OK)
        return ret;

    sret = sscanf(reply, "+CEER: %d,%d,%d\r\n", loc, reason, &unused);
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

modem_ret_t modem_get_reply(char *data, ssize_t *len, int *res)
{
    pthread_mutex_lock(&__modem.lock);

    dbg("Looking for %s\n", __atcmd.buf);

    if ((__modem.status & MODEM_STATUS_REPLY) == 0) {
        pthread_mutex_unlock(&__modem.lock);
        return MODEM_RET_PARSER;
    }

    dbg("Result(%d): ", __cmdp.ind);
    __print_output((uint8_t *)__cmdp.buf, 0, __cmdp.ind);

    *len = (unsigned int)(__cmdp.resptr - __cmdp.buf);

    memcpy(data, __cmdp.buf, *len);
    if (res != NULL) {
        *res = atoi(__cmdp.resptr);
    }
    __modem.status &= ~MODEM_STATUS_REPLY;
    pthread_mutex_unlock(&__modem.lock);

    return MODEM_RET_OK;
}

modem_ret_t modem_send_cmd(modem_cmd_id_t id, char *reply, ssize_t *sz,
                           int *res, unsigned int delay, ...)
{
    va_list           ap;
    modem_ret_t       ret;
    char              *arg;
    char              *ptr_d;
    const char        *ptr_s;
    const modem_cmd_t *cmd;
    int               args, try;

    try   = 0;
    cmd   = &modem_cmd[id];
    args  = cmd->args_num;
    ptr_s = cmd->cmd;

    pthread_mutex_lock(&__modem.lock);

    ptr_d       = __atcmd.buf;
    __atcmd.len = 0;

    if (args == 0) {
        /* If theres no arguments to a command, just copy it in cmd buffer */
        __atcmd.len = strlen(cmd->cmd);
        memcpy(__atcmd.buf, cmd->cmd, __atcmd.len);
    } else {
        /* Format cmd buffer according to modem_cmd_id_t entry and args
           supplied */
        va_start(ap, delay);

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

        va_end(ap);
    }

    /* Set <LN>.  Terminate with '\0' for debug purposes. */
//   __atcmd.buf[__atcmd.len ++] = '\r';
//   __atcmd.buf[__atcmd.len]    = '\0';
    __atcmd.buf[__atcmd.len]     = '\r';
    __atcmd.buf[__atcmd.len + 1] = '\0';

    dbg("Sending: ");
    __print_output((unsigned char *)__atcmd.buf, 0, __atcmd.len + 1);

    ret = modem_send_raw((uint8_t *)__atcmd.buf, __atcmd.len + 1);
    if (ret != MODEM_RET_OK) {
        __modem.status |= MODEM_STATUS_ERR;
        __modem.err    |= MODEM_ERR_IO;
        pthread_mutex_unlock(&__modem.lock);
        return ret;
    }

    if (reply) {
        __modem.status |= MODEM_STATUS_CMDCHECK;
        __reset_CMD_parser();
    }

    pthread_mutex_unlock(&__modem.lock);

    if (delay != 0)
        GRACE_TIME(AT_TIMEOUT_REPLY_WAIT);

    /* Check if reply is actually needed */
    if (!reply)
        return MODEM_RET_OK;

    *sz = -1;
    if (reply) {
    __get_reply_retry:
        if (try > MODEM_WAIT_REPLY_TRIES)
            return MODEM_RET_TIMEOUT;
        ret = modem_get_reply(reply, sz, res);
        if (ret != MODEM_RET_OK) {
            GRACE_TIME(MODEM_WAIT_REPLY_SLEEP);
            try ++;
            goto __get_reply_retry;
        }

        if (res != NULL)
            dbg("Command result=%d\n", *res);
    }

    return ret;
}

modem_ret_t modem_conn_start(unsigned int prof)
{
    char        sprof[2], reply[64];
    ssize_t      sz;
    modem_ret_t ret;
    int         res;

    if (prof > 9)
        return MODEM_RET_PARAM;

    sprof[0] = (char)(48 + prof);
    sprof[1] = '\0';

    ret = modem_send_cmd(MODEM_CMD_CONN_START, reply, &sz, &res, 1, sprof);
    if (ret != MODEM_RET_OK)
        return ret;
    if (res != 0)
        return MODEM_RET_AT;

    return MODEM_RET_OK;
}

modem_ret_t modem_conn_stop(unsigned int prof)
{
    char        reply[128];
    char        sprof[2];
    ssize_t     sz;
    modem_ret_t ret;
    int         res;

    if (prof > 9)
        return MODEM_RET_PARAM;

    sprof[0] = (char)(48 + prof);
    sprof[1] = '\0';

    ret = modem_send_cmd(MODEM_CMD_CONN_STOP, reply, &sz, &res, 1, sprof);
    if (ret != MODEM_RET_OK)
        return ret;
    if (res != 0)
        return MODEM_RET_AT;

    return MODEM_RET_OK;
}

modem_ret_t modem_configure(void)
{
    char    reply[512];
    ssize_t sz;
    int     res;

    /* Base configuration, set baud rate and commands response format */
    modem_send_cmd(MODEM_CMD_RESCODE_FMT, NULL, NULL, NULL, 1, "0");
    modem_send_cmd(MODEM_CMD_BAUD_SET,    NULL, NULL, NULL, 1, "115200");
    /* SICS setup */
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,1,"0", "CONTYPE", "GPRS0");
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,1,"0", "DNS1", "81.18.113.2");
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,1,"0", "DNS2", "81.18.112.50");
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,1,"0", "PASSWD", "none");
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,1,"0", "USER", "none");
    modem_send_cmd(MODEM_CMD_SICS,NULL,NULL,NULL,1,"0", "APN", "inet.bwc.ru");
    /* SISS setup */
    modem_send_cmd(MODEM_CMD_SISS,NULL,NULL,NULL,1,"0", "SRVTYPE", "Socket");
    modem_send_cmd(MODEM_CMD_SISS,NULL,NULL,NULL,1,"0", "CONID", "0");
    modem_send_cmd(MODEM_CMD_SISS,reply,&sz,&res,1,"0", "ADDRESS",
                   "socktcp://46.254.241.6:48026;disnagle=1");

    return MODEM_RET_OK;
}

modem_ret_t modem_send_packet(unsigned int prof,
                              const uint8_t *data, size_t len)
{
//    modem_ret_t ret;
    char        plen[5], sprof[2];
    uint8_t     ps[2];
    uint16_t    len_no;

    if ((len + 2) & 0x1FFFF0000)
        return MODEM_RET_PARAM;
    if (prof > 9)
        return MODEM_RET_PARAM;

    sprof[0] = (char)(48 + prof);
    sprof[1] = '\0';

    len_no = htons(len);
    memcpy(ps, &len_no, 2);

    snprintf(plen, 5, "%d", (uint16_t)(len + 2));
    CHECK_RET(modem_send_cmd(MODEM_CMD_PACKET_SEND1,
                             NULL, NULL, NULL, 1, "1", plen));
    CHECK_RET(modem_send_raw(ps, 2));
    CHECK_RET(modem_send_raw(data, len));
    CHECK_RET(modem_send_cmd(MODEM_CMD_PACKET_SEND2,
                             NULL, NULL, NULL, 1, sprof, "0", "0"));

    return MODEM_RET_OK;
}

static void *__modem_thread(void *arg)
{
    ssize_t       sz;
    int           ret, timeout;
    struct pollfd fds[POLL_FDNUM];
    uint8_t       buf[MODEM_READ_BYTES];

    (void)arg;

    /* Use epoll if possible, this code is for specific embedded system */
    for (;;) {
        fds[0].fd      = __modem.fd;
        fds[0].events  = POLLIN;
        fds[0].revents = 0;

        timeout = 0;

        ret = poll(fds, 1, 100);
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

                /* Parse for command if we are waiting one */
                if (__modem.status & MODEM_STATUS_CMDCHECK &&
                    __process_CMD((char *)buf, sz) == 1) {
                    __modem.status &= ~MODEM_STATUS_CMDCHECK;
                    __modem.status |=  MODEM_STATUS_REPLY;
                }
                /* Even if urc mode disabled we can get some urc's */
                __process_URC((char *)buf, sz);

                pthread_mutex_unlock(&__modem.lock);
            } while (sz > 0);
        }
    }

    return NULL;
}

static int __process_CMD(const char *buf, size_t sz)
{
    unsigned int i;

    for (i = 0; i < sz; i++) {
        if (__cmdp.ind == CMD_PARSER_BUF_SZ) { /* Command reply is longer then
                                                  supplied buffer */
            __reset_CMD_parser();
            return -1;
        }
        switch (__cmdp.cmd_state) {
        case CMD_PARSER_NONE: /* Start by looking for command echo */
            if (__atcmd.buf[__atcmd.ind] == buf[i])
                __atcmd.ind ++;
            else
                __atcmd.ind = 0;

            /* Command echo match */
            if (__atcmd.ind == __atcmd.len) {
                __atcmd.ind      = 0;
                __cmdp.cmd_state = CMD_PARSER_REPLY;
            }
            break;
        case CMD_PARSER_REPLY:
            /* Looking for \r as a sign of next line or endof reply */
            if (buf[i] == '\r')
                __cmdp.cmd_state = CMD_PARSER_DELIM;
            else
                __cmdp.buf[__cmdp.ind++] = buf[i];
            break;
        case CMD_PARSER_DELIM:
            if (isdigit(buf[i])) { /* if next ch == \r, reply is succ found */
                __cmdp.resptr = __cmdp.buf + __cmdp.ind;
                __cmdp.buf[__cmdp.ind++] = buf[i];
                __cmdp.cmd_state = CMD_PARSER_ENDCHECK;
            } else if (buf[i] != '\n' && buf[i] != '\r') /* Next line */
                __cmdp.cmd_state = CMD_PARSER_REPLY;

//            __cmdp.ind ++;
            break;
        case CMD_PARSER_ENDCHECK:
            if (buf[i] == '\r') { /* Done */
                return 1;
            } else { /* Continue looking for an end */
                __cmdp.buf[__cmdp.ind++] = buf[i];
                __cmdp.resptr    = NULL;
                __cmdp.cmd_state = CMD_PARSER_REPLY;
            }
            break;
        }
    }

    return 0;
}

static void __process_URC(const char *buf, size_t sz)
{
    unsigned int i;

    for (i = 0; i < sz; i++) {
        switch (__urcp.urc_state) {
        case URC_PARSER_NONE:
            if (buf[i] == '+' || buf[i] == '^')  {
                __urcp.ind               = 0;
                __urcp.buf[__urcp.ind++] = buf[i];
                __urcp.urc_state         = URC_PARSER_CMD_CHECK;
                continue;
            }
            break;
        case URC_PARSER_CMD_CHECK:
            if (buf[i] == '\r') {
                if (!memcmp(__urcp.buf, URC_SYSSTART, 9)) {
                    /* Modem has been started/restarted, reset states */
                    dbg("SYSSTART event.\n");
                    __modem.status = 0;
                    __modem.err    = 0;
                } else if (!memcmp(__urcp.buf, URC_SHUTDOWN, 9)) {
                    /* Modem entered shutdown mode, modem op blocked */
                    __modem.status &= ~MODEM_STATUS_ONLINE;
                    __modem.status |=  MODEM_STATUS_SHUTDOWN;
                }

                __urcp.urc_state = URC_PARSER_NONE;
            } else if (buf[i] == ':') {
                __urcp.urc_state = URC_PARSER_DATA_CHECK;
                __urcp.cmd_end   = (char *)(buf + i);
            }

            __urcp.buf[__urcp.ind++] = buf[i];

            continue;
        case URC_PARSER_DATA_CHECK:
            if (buf[i] == '\r')
                __urcp.urc_state = URC_PARSER_DATA_ENDCHECK;
            else {
                __urcp.buf[__urcp.ind++] = buf[i];
            }

            continue;
        case URC_PARSER_DATA_ENDCHECK:
            /* <CMDID>: <DATA> */
            if (buf[i] == '\n') {
                __urcp.buf[__urcp.ind] = '\0';
                __parse_URC();
            }
            __urcp.urc_state = URC_PARSER_NONE;
            break;
        }
    }
}

static void __parse_URC_CREG(void)
{
    int reg;
    int net_lac, net_cellid;

    reg = net_lac = net_cellid = -1;

    if (strlen(__urcp.buf) > 22) { /* CREG request reply in 2nd mode while
                                      registered */
        reg        = strtol(__urcp.buf + 9,  NULL, 10);
        net_lac    = strtol(__urcp.buf + 12, NULL, 16);
        net_cellid = strtol(__urcp.buf + 19, NULL, 16);
    } else if (strlen(__urcp.buf) > 10) { /* CREG event in 2nd mode while
                                             registered */
        reg        = strtol(__urcp.buf + 7,  NULL, 10);
        net_lac    = strtol(__urcp.buf + 10, NULL, 16);
        net_cellid = strtol(__urcp.buf + 17, NULL, 16);
    } else if (strlen(__urcp.buf) > 8) /* CREG request reply in 2nd mode while
                                          not registered */
        reg = strtol(__urcp.buf + 9, NULL, 10);
    else /* CREG even in 2nd mode while not registered */
        reg = strtol(__urcp.buf + 7, NULL, 10);

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

    prof    = strtol(__urcp.buf + 7, NULL, 10);
    urcCode = strtol(__urcp.buf + 9, NULL, 10);

    if (prof == 0 && urcCode == 1)
        __modem.status |= (MODEM_STATUS_CONN|MODEM_STATUS_WREADY);
}

static void __parse_URC_SISR(void)
{
    int prof, urcCode;

    prof = urcCode = -1;

    prof    = strtol(__urcp.buf + 7, NULL, 10);
    urcCode = strtol(__urcp.buf + 9, NULL, 10);

    if (prof == 0 && urcCode == 2) {
        __modem.status &= ~MODEM_STATUS_CONN;
    }
}

static void __parse_URC_SIS(void)
{
    char msg[128];
    unsigned int prof;
    unsigned int urc_cause, urc_infoid;

    prof       = strtol(__urcp.buf + 6,  NULL, 10);
    urc_cause  = strtol(__urcp.buf + 8,  NULL, 10);
    urc_infoid = strtol(__urcp.buf + 10, NULL, 10);

    dbg("Error. Profile=%d; Cause=%d; Info=%d\n", prof, urc_cause, urc_infoid);
}


static void __parse_URC(void)
{
    dbg("URC: ");
    __print_output((uint8_t *)__urcp.buf, 0, __urcp.ind);

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

static void __reset_CMD_parser(void)
{
    __cmdp.cmd_state = CMD_PARSER_NONE;
    __cmdp.ind       = 0;
    __cmdp.resptr    = NULL;
    memset(__cmdp.buf, 0, CMD_PARSER_BUF_SZ);
}

#ifdef DEBUG
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
        } else
            putchar(*ptr);
    }

    printf("\n");
}
#else
#define __print_output(x...) do { } while (0)
#endif
