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

#include "modem.h"

#define MODEM_DEBUG

#define POLL_FDNUM 1

#define MODEM_WAIT_REPLY_TRIES 100
#define MODEM_WAIT_REPLY_SLEEP 100000
#define MODEM_WAIT_FLUSH_SLEEP 50000

#define MODEM_SYSSTART_WAIT_TRIES 100

#define MODEM_CMDBUF_SZ  256
#define MODEM_RXBUF_SZ   4096
#define MODEM_READ_BYTES 128

/* Default reply timeout */
#define AT_TIMEOUT_REPLY_WAIT 50000

#define URC_SYSSTART "^SYSSTART"
#define URC_SHUTDOWN "^SHUTDOWN"
#if 0
#define RX_BUF_INIT() (__rx_buf.start = __rx_buf.end = 0)

#define RX_BUF_FULL()                           \
    (((__rx_buf.end + 1) % __rx_buf.size) ==  __rx_buf.start)

#define RX_BUF_EMPTY() (__rx_buf.end == __rx_buf.start)
#endif
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

static modem_dev_t __modem;

static uint8_t __rx_buf[MODEM_RXBUF_SZ];
static char __cmd_buf[MODEM_CMDBUF_SZ];

static off_t __rx_ind       = 0;
static size_t __cmd_buf_len = 0;

static urc_parser_t __urcp;

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

static inline void __reset_RX(void);

static void __print_output(const unsigned char *buf, off_t s, size_t sz);
static void *__modem_thread(void *arg);

static void __process_URC_mode(const uint8_t *buf, size_t sz);
static void __parse_URC(void);
#if 0
static void __rx_buf_put(uint8_t *input, size_t sz);
static char __rx_buf_get(void);
#endif
modem_ret_t modem_init(const char *path)
{
    int            ret;//, i;
    struct termios term;
    char           c;
//    modem_err_t    err;

    memset(&__modem, 0, sizeof(__modem));
    memset(__rx_buf, 0, sizeof(__rx_buf));
    memset(&term,    0, sizeof(term));
    memset(&__urcp,  0, sizeof(__urcp));

    __rx_ind = __cmd_buf_len = 0;

    /* We dont want to hang on read call, better use nonblocking approach. */
    __modem.fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (__modem.fd < 0)
        return MODEM_RET_IO;

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
        /* Any other possibility concidered system related error, probably
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

    sleep(5);

    /* Set to command mode, since we are going to configure modem first */
    ret = modem_set_urcmode(0);
    if (ret != MODEM_RET_OK) {
        close(__modem.fd);
        return ret;
    }
#if 0
    /* Seek for SYSSTART URC */
    for (i = 0; i < MODEM_SYSSTART_WAIT_TRIES; i++) {
        usleep(MODEM_SYSSTART_WAIT_USEC);
        err = __modem.err;
        if (err & MODEM_ERR_URC_SYSSTART)
            break;
    };

    if (i == MODEM_SYSSTART_WAIT_TRIES) {
        /* Failed seeking for SYSSTART URC, concidering that modem is
           misbehaving */
        modem_destroy();
        return MODEM_RET_TIMEOUT;
    }
#endif
    /* Setup initial status and reset error variable */
    pthread_mutex_lock(&__modem.lock);
    __modem.status = MODEM_STATUS_ONLINE;
    __modem.err    = 0;
    pthread_mutex_unlock(&__modem.lock);

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

    ret = modem_send_cmd(MODEM_CMD_CEER, reply, &len, 1);
    if (ret != MODEM_RET_OK)
        return ret;

    sret = sscanf(reply, "+CEER: %d,%d,%d\r\n", loc, reason, &unused);
    if (sret == EOF || sret != 3)
        return MODEM_RET_PARSER;

    return MODEM_RET_OK;
}

modem_ret_t modem_send_raw(const char *data, size_t len)
{
    int ret;

    ret = write(__modem.fd, data, len);
    if (ret == -1 || (unsigned int)ret < len)
        return MODEM_RET_IO;

    return MODEM_RET_OK;
}

modem_ret_t modem_get_reply(char *data, ssize_t *len, int *result)
{
    char *ptrc, *ptrr;
    int res;
    unsigned int delim = 0;

    *len = res = -1;
    *data = '\0';
    if (result != NULL) *result = -1;

    pthread_mutex_lock(&__modem.lock);

    dbg("Looking for command: ");
    __print_output((uint8_t *)__cmd_buf, 0, __cmd_buf_len);

    dbg("RX buffer(%d): ", __rx_ind);
    __print_output(__rx_buf, 0, __rx_ind);

    /* Check if command echo is in buffer */
    ptrc = strstr((char *)__rx_buf, __cmd_buf);
    if (!ptrc) {
        pthread_mutex_unlock(&__modem.lock);
        return MODEM_RET_PARSER;
    }

    ptrr = ptrc + __cmd_buf_len;

    do {
        /* If we found delimiter, skip \r\n */
        if (delim) ptrr += 2;
        /* Check result code for AT command. <CODE>\r: <CODE> is at maximum 2
           digit sequence */
        if ((ptrr[1] == '\r' && isdigit(ptrr[0])) ||
            (ptrr[2] == '\r' && isdigit(ptrr[1]) && isdigit(ptrr[0]))) {
            res = atoi(ptrr); /* TODO: use strtol with LONG_MIN/MAX detection */
        }
        /* If result code found, copy reply data to buffer */
        if (res != -1) {
            if (delim) {
                *len = ptrr - ptrc - __cmd_buf_len - 4;
                if (result != NULL) *result = res;
                memcpy(data, ptrc + __cmd_buf_len + 2, *len);
            }
            break;
        }

        /* Looking for delimiter */
        ptrr = strstr(ptrr, "\r\n");
        delim = (ptrr != NULL) ? 1 : 0;
    } while (delim);

    pthread_mutex_unlock(&__modem.lock);

    return (res != -1) ? MODEM_RET_OK : MODEM_RET_PARSER;
}

modem_ret_t modem_send_cmd(modem_cmd_id_t id, char *reply, ssize_t *sz,
                           unsigned int delay, ...)
{
    va_list           ap;
    int               try;
    modem_ret_t       ret;
    char              *arg, *ptr_d;
    const char        *ptr_s;
    const modem_cmd_t *cmd;
    int               args;

    try   = 0;
    cmd   = &modem_cmd[id];
    args  = cmd->args_num;
    ptr_s = cmd->cmd;

    pthread_mutex_lock(&__modem.lock);

    ptr_d = __cmd_buf;
    __cmd_buf_len = 0;

    if (args == 0) {
        /* If theres no arguments to a command, just copy it in cmd buffer */
        __cmd_buf_len = strlen(cmd->cmd);
        memcpy(__cmd_buf, cmd->cmd, __cmd_buf_len);
    } else {
        /* Format cmd buffer according to modem_cmd_id_t entry and args
           supplied */
        va_start(ap, delay);

        while (args) {
            if (*ptr_s != '#') {
                /* If its not an arg markup, just byte copy */
                *ptr_d ++ = *ptr_s;
                __cmd_buf_len ++;
            } else {
                /* Arg markup, fill it with supplied data */
                arg = va_arg(ap, char *);
                memcpy(ptr_d, arg, strlen(arg));
                ptr_d += strlen(arg);
                __cmd_buf_len += strlen(arg);
                args --;
            }

            ptr_s++;
        }

        va_end(ap);
    }

    /* Set <LN>.  Terminate with '\0' for debug purposes. */
    __cmd_buf[__cmd_buf_len ++] = '\r';
    __cmd_buf[__cmd_buf_len]    = '\0';

//    dbg("Sending: ");
//    __print_output((unsigned char *)__cmd_buf, 0, __cmd_buf_len);

    ret = modem_send_raw(__cmd_buf, __cmd_buf_len);
    if (ret != MODEM_RET_OK) {
        __modem.status |= MODEM_STATUS_ERR;
        __modem.err    |= MODEM_ERR_IO;
        pthread_mutex_unlock(&__modem.lock);
        return ret;
    }

    pthread_mutex_unlock(&__modem.lock);

    if (delay != 0)
        GRACE_TIME(AT_TIMEOUT_REPLY_WAIT);

    /* We dont need any result code or reply */
    if (!reply)
        return MODEM_RET_OK;

    *sz = -1;
    if (reply) {
    __get_reply_retry:
        if (try > MODEM_WAIT_REPLY_TRIES)
            return MODEM_RET_TIMEOUT;
        ret = modem_get_reply(reply, sz, NULL);
        if (ret != MODEM_RET_OK) {
            GRACE_TIME(MODEM_WAIT_REPLY_SLEEP);
            try ++;
            goto __get_reply_retry;
        }
    }

    return ret;
}

void modem_flush(unsigned int delay)
{
    /* Wait while modem thread will empty the device RX buffer */
    if (delay == 0)
        GRACE_TIME(MODEM_WAIT_FLUSH_SLEEP);
    else
        GRACE_TIME(delay);

    pthread_mutex_lock(&__modem.lock);
    /* Set RX buffer contents and index to 0 */
    memset(__rx_buf, 0, sizeof(__rx_buf));
    __rx_ind = 0;
    pthread_mutex_unlock(&__modem.lock);
}

modem_ret_t modem_conn_start(unsigned int prof)
{
    char    reply[128];
    char    sprof[2];
    ssize_t sz;

    if (prof > 9)
        return MODEM_RET_PARAM;

    sprof[0] = (char)(48 + prof);
    sprof[1] = '\0';

    return modem_send_cmd(MODEM_CMD_CONN_START, NULL, NULL, 0, sprof);
}

modem_ret_t modem_conn_stop(unsigned int prof)
{
    char    reply[128];
    char    sprof[2];
    ssize_t sz;

    if (prof > 9)
        return MODEM_RET_PARAM;

    sprof[0] = (char)(48 + prof);
    sprof[1] = '\0';

    return modem_send_cmd(MODEM_CMD_CONN_STOP, reply, &sz, 1, sprof);
}

modem_ret_t modem_configure(void)
{
    char reply[64];
    ssize_t sz;

    /* Base configuration, set baud rate and commands response format */
    modem_send_cmd(MODEM_CMD_RESCODE_FMT, NULL, NULL, 1, "0");
    modem_send_cmd(MODEM_CMD_BAUD_SET,    NULL, NULL, 1, "115200");
    /* SICS setup */
    modem_send_cmd(MODEM_CMD_SICS, NULL, NULL, 1, "0", "CONTYPE", "GPRS0");
    modem_send_cmd(MODEM_CMD_SICS, NULL, NULL, 1, "0", "DNS1", "81.18.113.2");
    modem_send_cmd(MODEM_CMD_SICS, NULL, NULL, 1, "0", "DNS2", "81.18.112.50");
    modem_send_cmd(MODEM_CMD_SICS, NULL, NULL, 1, "0", "PASSWD", "none");
    modem_send_cmd(MODEM_CMD_SICS, NULL, NULL, 1, "0", "USER", "none");
    modem_send_cmd(MODEM_CMD_SICS, NULL, NULL, 1, "0", "APN", "inet.bwc.ru");
    /* SISS setup */
    modem_send_cmd(MODEM_CMD_SISS, NULL, NULL, 1, "0", "SRVTYPE", "Socket");
    modem_send_cmd(MODEM_CMD_SISS, NULL, NULL, 1, "0", "CONID", "0");
    modem_send_cmd(MODEM_CMD_SISS, reply, &sz, 1, "0", "ADDRESS",
                   "socktcp://46.254.241.6:48026;disnagle=1");
    /* Flush everything from the rx buffer */
    modem_flush(0);

    return MODEM_RET_OK;
}

modem_ret_t modem_set_urcmode(uint8_t sw)
{
    modem_ret_t ret;
//    modem_status_t status;

    dbg("Setting URC mode. Mode=%d\n", sw);

    if (sw == 0) { /* Turn URC mode off */
        ret = modem_send_cmd(MODEM_CMD_SCFG, NULL, NULL, 1,
                             "Tcp/WithURCs", "off");
        if (ret != MODEM_RET_OK)
            goto __set_urcmode_err;
        ret = modem_send_cmd(MODEM_CMD_CREG_SET, NULL, NULL, 1, "0");
        if (ret != MODEM_RET_OK)
            goto __set_urcmode_err;
    } else { /* Turn URC mode on */
        ret = modem_send_cmd(MODEM_CMD_SCFG, NULL, NULL, 1,
                             "Tcp/WithURCs", "on");
        if (ret != MODEM_RET_OK)
            goto __set_urcmode_err;
        ret = modem_send_cmd(MODEM_CMD_CREG_SET, NULL, NULL, 1, "2");
        if (ret != MODEM_RET_OK)
            goto __set_urcmode_err;
    }

    modem_send_cmd(MODEM_CMD_FLUSH, NULL, NULL, 1);

    pthread_mutex_lock(&__modem.lock);
    if (sw == 0) __modem.status &= ~MODEM_STATUS_URCMODE;
    else         __modem.status |=  MODEM_STATUS_URCMODE;
    /* Reset rx buffer contents and states for all modes */
    __reset_RX();
    pthread_mutex_unlock(&__modem.lock);

__set_urcmode_err:

    dbg("Setting URC mode. Result=%d\n", ret);

    return ret;
}

modem_ret_t modem_send_packet(char *data, size_t len)
{
//    modem_ret_t ret;
    char        sz_str[5];
    char        ps[2];
    uint16_t    len_no;

    if ((len + 2) & 0x1FFFF0000)
        return MODEM_RET_PARAM;

    len_no = htons(len);
    memcpy(ps, &len_no, 2);

    snprintf(sz_str, 5, "%d", (uint16_t)(len + 2));
    CHECK_RET(modem_send_cmd(MODEM_CMD_PACKET_SEND1, NULL, NULL,1,"1", sz_str));
    CHECK_RET(modem_send_raw(ps, 2));
    CHECK_RET(modem_send_raw(data, len));
    CHECK_RET(modem_send_cmd(MODEM_CMD_PACKET_SEND2,NULL,NULL,1,"1", "0", "0"));
    modem_flush(0);

    return MODEM_RET_OK;
}

static inline void __reset_RX(void)
{
    __rx_ind  = 0;
    *__rx_buf = '\0';
}

static void *__modem_thread(void *arg)
{
    ssize_t       sz;
    int           ret, timeout;
    struct pollfd fds[POLL_FDNUM];

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

                if ((__rx_ind + MODEM_READ_BYTES) > MODEM_RXBUF_SZ) {
                    __modem.status |= MODEM_STATUS_BUFOVR;
                    __reset_RX();
                }

                sz = read(fds[0].fd, __rx_buf + __rx_ind, MODEM_READ_BYTES);
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

                if (__modem.status & MODEM_STATUS_URCMODE) {
                    __process_URC_mode(__rx_buf, sz);
                } else { /* Command mode */
                    __rx_ind += sz;
                    __rx_buf[__rx_ind] = '\0';
                }

                pthread_mutex_unlock(&__modem.lock);
            } while (sz > 0);
        }
    }

    return NULL;
}

static void __process_URC_mode(const uint8_t *buf, size_t sz)
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
        reg        = strtol(__urcp.buf + 9, NULL, 10);
        net_lac    = strtol(__urcp.buf + 12, NULL, 16);
        net_cellid = strtol(__urcp.buf + 19, NULL, 16);
    } else if (strlen(__urcp.buf) > 10) { /* CREG event in 2nd mode while
                                             registered */
        reg        = strtol(__urcp.buf + 7, NULL, 10);
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

    if (prof == 0 && urcCode == 1) {
        __modem.status |= MODEM_STATUS_CONN;
    }
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

static void __parse_URC(void)
{
    dbg("URC: ");
    __print_output((uint8_t *)__urcp.buf, 0, __urcp.ind);

    if (!memcmp(__urcp.buf, "+CREG:", 6)) {
        __parse_URC_CREG();
    } else if (!memcmp(__urcp.buf, "^SISW:", 6)) {
        __parse_URC_SISW();
    }
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

#if 0
static void __rx_buf_put(uint8_t *input, size_t sz)
{
    unsigned int i;

    for (i = 0; i < sz; i++) {
        __rx_buf.buf[__rx_buf.end] = input[i];
        __rx_buf.end = (__rx_buf.end + 1) % RX_BUF_SZ;
        if (__rx_buf.end == __rx_buf.start)
            __rx_buf.start = (__rx_buf.start + 1) % RX_BUF_SZ;
    }
}

static char __rx_buf_get(void)
{
    char ch;

    ch = __rx_buf.buf[__rx_buf.start];
    __rx_buf.start = (__rx_buf.start + 1) % RX_BUF_SZ;

    return ch;
}
#endif
