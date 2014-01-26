#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#include <arpa/inet.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <pthread.h>

#include <errno.h>

#include "modem.h"

#define MODEM_CMDBUF_SZ  256
#define MODEM_RXBUF_SZ   1024
#define MODEM_READ_BYTES 128

static modem_dev_t __modem;
static conn_state_t __conn;

static uint8_t __rx_buf[MODEM_RXBUF_SZ];
static char __cmd_buf[MODEM_CMDBUF_SZ];

static off_t __rx_ind       = 0;
static size_t __cmd_buf_len = 0;

/* Default reply timeout */
#define AT_TIMEOUT_REPLY_WAIT 100000

modem_cmd_t modem_cmd[] = {
    {MODEM_CMD_ECHO_SET,      "ATE#",                    1},
    {MODEM_CMD_QUALITY_GET,   "AT+CSQ",                  0},
    {MODEM_CMD_IMEI_GET,      "AT+GSN",                  0},
    {MODEM_CMD_PIN_AUTH,      "AT+CPIN=#",               1},
    {MODEM_CMD_CREG_CHECK,    "AT+CREG?",                0},
    {MODEM_CMD_CREG_SET,      "AT+CREG=#",               1},
    {MODEM_CMD_AT,            "AT",                      0},
    {MODEM_CMD_SICS_CONTYPE,  "AT^SICS=#,CONTYPE,#",     2},
    {MODEM_CMD_SICS_DNS1,     "AT^SICS=#,DNS1,#",        2},
    {MODEM_CMD_SICS_DNS2,     "AT^SICS=#,DNS2,#",        2},
/*    {MODEM_CMD_SICS_AUTHMODE, "AT^SICS=#,AUTHMODE,#",    2}, */
    {MODEM_CMD_SICS_PASSWD,   "AT^SICS=#,PASSWD,#",      2},
    {MODEM_CMD_SICS_USER,     "AT^SICS=#,USER,#",        2},
    {MODEM_CMD_SICS_APN,      "AT^SICS=#,APN,#",         2},
    {MODEM_CMD_SICS_INACTTO,  "AT^SICS=#,INACTTO,#",     2},
    {MODEM_CMD_SISS_SRVTYPE,  "AT^SISS=#,SRVTYPE,#",     2},
    {MODEM_CMD_SISS_CONNID,   "AT^SISS=#,CONID,#",       2},
    {MODEM_CMD_SISS_ADDR,     "AT^SISS=#,ADDRESS,#",     2},
    {MODEM_CMD_PACKET_SEND1,  "AT^SISW=#,#",             2},
    {MODEM_CMD_PACKET_SEND2,  "AT^SISW=#,#,#",           3},
    {MODEM_CMD_CONN_START,    "AT^SISO=#",               1},
    {MODEM_CMD_CONN_STOP,     "AT^SISC=#",               1},
    {MODEM_CMD_CONN_CHECK,    "AT^SISI=#",               1},
    {MODEM_CMD_CFG_URC,       "AT^SCFG=tcp/withurcs,#",  1},
    {MODEM_CMD_ERR_CERR,      "AT+CEER",                 0},
    {MODEM_CMD_SISS_SETUP,    "AT^SISS?",                0},
    {MODEM_CMD_SICS_SETUP,    "AT^SICS?",                0},
    {MODEM_CMD_ADC_TMP,       "AT^SBV",                  0},
    {MODEM_CMD_CLOCK_GET,     "AT+CCLK?",                0},
    {MODEM_CMD_CUSD,          "AT+CUSD=1,#",             1},
    {MODEM_CMD_RESCODE_FMT,   "ATV#",                    1},
    {-1, NULL, -1},
};

static int __modem_configure(void);
static void *__modem_thread(void *arg);
unsigned int __scan_common_URC(const uint8_t *buf);

int modem_send_raw(const char *data, size_t len)
{
    int ret;

    ret = write(__modem.fd, data, len);
    if (ret == -1)
        return -errno;
    else if ((unsigned int)ret < len) {
        return -EIO;
    }

    return ret;
}

int modem_send_cmd(modem_cmd_id_t id, char *reply, ssize_t *sz, ...)
{
    va_list ap;
    int ret, try = 0;
    char *arg, *ptr_d;
    const char *ptr_s;
    const modem_cmd_t *cmd;
    int args;

    cmd  = &modem_cmd[id];
    args = cmd->args_num;

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
        va_start(ap, sz);

        while (args) {
            if (*ptr_s != '#') {
                /* If its not a arg markup, just byte copy */
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

    /* Set <LN> and terminate command with null symbol for the sake of debug. */
    __cmd_buf[__cmd_buf_len ++] = '\r';
    __cmd_buf[__cmd_buf_len]    = '\0';

    ret = modem_send_raw(__cmd_buf, __cmd_buf_len);
    if (ret < 0 || ret != (int)__cmd_buf_len) {
        __modem.status |= MODEM_STATUS_ERR;
        __modem.err    |= MODEM_ERR_IO;
        pthread_mutex_unlock(&__modem.lock);
        return -1;
    }

    pthread_mutex_unlock(&__modem.lock);

    GRACE_TIME(AT_TIMEOUT_REPLY_WAIT);

    /* We dont need any result code or reply */
    if (!reply)
        return 0;

    *sz = -1;
    if (reply) {
    __get_reply_retry:
        if (try > 100)
            return -1;
        ret = modem_get_reply(reply, sz);
        if (ret < 0) {
            GRACE_TIME(200000);
            try ++;
            goto __get_reply_retry;
        }
    }

    return ret;
}

int modem_init(const char *path)
{
    int ret;
    struct termios term;
    char c;

    memset(&__modem, 0, sizeof(__modem));
    memset(&__conn,  0, sizeof(__conn));
    memset(__rx_buf, 0, sizeof(__rx_buf));
    memset(&term,    0, sizeof(term));

    __rx_ind = __cmd_buf_len = 0;

    /* We dont want to hang on read call, better use nonblocking approach. */
    __modem.fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (__modem.fd < 0)
        return -errno;

    term.c_cflag    = CREAD | CS8;
    term.c_cc[VMIN] = 1;

    cfsetispeed(&term, B115200);
    cfsetospeed(&term, B115200);

    tcsetattr(__modem.fd, TCSANOW, &term);

    /* Flush buffer */
    while (read(__modem.fd, &c, 1) != -1);
    if (errno != EAGAIN) {
        close(__modem.fd);
        return -errno;
    }

    ret = pthread_mutex_init(&__modem.lock, NULL);
    if (ret != 0) {
        close(__modem.fd);
        return -ret;
    }

    /* Start up modem parser thread */
    ret = pthread_create(&__modem.tid, NULL, __modem_thread, NULL);
    if (ret != 0) {
        close(__modem.fd);
        pthread_mutex_destroy(&__modem.lock);
        return -ret;
    }
    /* Do the startup configuration for modem */
    ret = __modem_configure();
    if (ret < 0) {
        pthread_detach(__modem.tid);
        pthread_cancel(__modem.tid);
        pthread_mutex_destroy(&__modem.lock);
        close(__modem.fd);
        return -ret;
    }

    /* Wait some time for modem to handle new configuration */
    GRACE_TIME(100000);

    /* Modem is online and ready */
    __modem.status |= MODEM_STATUS_ONLINE;

    return 0;
}

int modem_get_reply(char *data, ssize_t *len)
{
    char *ptrc, *ptrr;
    int res;
    unsigned int delim = 0;

    *len = res = -1;
    *data = '\0';

    pthread_mutex_lock(&__modem.lock);
#if 0
    printf("Looking for command: ");
    modem_print_output((uint8_t *)__cmd_buf, 0, __cmd_buf_len);
#endif
#if 0
    printf("RX buffer: ");
    modem_print_output(__rx_buf, 0, __rx_ind);
#endif
    /* Check if command echo is in buffer */
    ptrc = strstr((char *)__rx_buf, __cmd_buf);
    if (!ptrc) {
        pthread_mutex_unlock(&__modem.lock);
        return -1;
    }

    ptrr = ptrc + __cmd_buf_len;

    do {
        /* If we found delimiter, skip \r\n */
        if (delim) ptrr += 2;

        /* Check result code for AT command. <CODE>\r: <CODE> is maximum 2
           digit sequence */
        if ((ptrr[1] == '\r' && isdigit(ptrr[0])) ||
            (ptrr[2] == '\r' && isdigit(ptrr[1]) && isdigit(ptrr[0]))) {
            res = atoi(ptrr);
        }

        /* If result code found, copy reply data to buffer */
        if (res != -1) {
            if (delim) {
                *len = ptrr - ptrc - __cmd_buf_len;
                memcpy(data, ptrc + __cmd_buf_len, *len);
            }
            break;
        }

        /* Looking for delimiter */
        ptrr = strstr(ptrr, "\r\n");
        delim = (ptrr != NULL) ? 1 : 0;
    } while (delim);

    pthread_mutex_unlock(&__modem.lock);

    return res;
}

void modem_flush(unsigned int delay)
{
    /* Wait while modem thread will empty the device RX buffer */
    if (delay == 0)
        GRACE_TIME(100000);
    else
        GRACE_TIME(delay);

    pthread_mutex_lock(&__modem.lock);
    /* Set RX buffer contents and index to 0 */
    memset(__rx_buf, 0, sizeof(__rx_buf));
    __rx_ind = 0;
    pthread_mutex_unlock(&__modem.lock);
}

inline void modem_status(modem_status_t *status, modem_err_t *err)
{
    pthread_mutex_lock(&__modem.lock);
    *status = __modem.status;
    *err    = __modem.err;
    pthread_mutex_unlock(&__modem.lock);
}

inline void modem_status_reset(void)
{
    pthread_mutex_lock(&__modem.lock);
    __modem.status &= ~(MODEM_STATUS_URC|MODEM_STATUS_BUFOVR|MODEM_STATUS_ERR);
    __modem.err    = 0;
    pthread_mutex_unlock(&__modem.lock);
}

int modem_check_reg(void)
{
    int ret;
    ssize_t sz;
    unsigned int urc_mode, creg;
    char reply[128];

    ret = modem_send_cmd(MODEM_CMD_CREG_CHECK, reply, &sz);
    if (ret < 0 || sz == -1)
        return ret;

    /* Flush RX buffer */
    modem_flush(0);
    sscanf(reply, "\r\n+CREG: %d,%d\r\n", &urc_mode, &creg);

    /* If we are not registered just return current registration status */
    if (creg != MODEM_AT_REG_OK &&
        creg != MODEM_AT_REG_ROAMING)
        return creg;

    pthread_mutex_lock(&__modem.lock);

    /* Set registration flag up */
    __modem.status |= MODEM_STATUS_REG;
    if ((__modem.status & MODEM_STATUS_ROAMING) == 0 &&
        creg == MODEM_AT_REG_ROAMING)
        /* if Registration is in roaming state and flag is not set, set it up */
        __modem.status |= MODEM_STATUS_ROAMING;
    else if (__modem.status & MODEM_STATUS_ROAMING)
        /* Remove flag if it is up */
        __modem.status &= ~MODEM_STATUS_ROAMING;

    pthread_mutex_unlock(&__modem.lock);

    return creg;
}

int modem_check_conn(unsigned int profile)
{
    int ret;
    ssize_t sz;
    char reply[256];

    (void)profile;

    ret = modem_send_cmd(MODEM_CMD_CONN_CHECK, reply, &sz, "1");
    if (ret < 0)
        return ret;

    /* FLush RX buffer */
    modem_flush(0);
    sscanf(reply, "\r\n^SISI: %d,%d,%d,%d,%d,%d\r\n",
           &__conn.prof_id, &__conn.state,
           &__conn.rx, &__conn.tx,
           &__conn.ack, &__conn.unack);

    pthread_mutex_lock(&__modem.lock);
    if (__conn.state != MODEM_AT_CONN_UP &&
        __modem.status & MODEM_STATUS_CONNUP)
        __modem.status &= ~MODEM_STATUS_CONNUP;
    pthread_mutex_unlock(&__modem.lock);

    return __conn.state;
}

int modem_send_packet(char *data, size_t len)
{
    char sz_str[5];
    char ps[2];
    uint16_t len_no;

    if ((len + 4) & 0x1FFFF0000)
        return -EINVAL;

    len_no = htons(len);
    memcpy(ps, &len_no, 2);

    snprintf(sz_str, 5, "%d", (uint16_t)(len + 4));
    modem_send_cmd(MODEM_CMD_PACKET_SEND1, NULL, NULL, "1", sz_str);
    modem_send_raw(ps, 2);
    modem_send_raw(data, len);
    modem_flush(0);
    modem_send_cmd(MODEM_CMD_PACKET_SEND2, NULL, NULL, "1", "0", "0");

    return 0;
}

int modem_conn_start(unsigned int profile)
{
    char reply[128];
    ssize_t sz;

    (void)profile;

    return modem_send_cmd(MODEM_CMD_CONN_START, reply, &sz, "1");;
}

int modem_conn_stop(unsigned int profile)
{
    char reply[128];
    ssize_t sz;

    (void)profile;

    return modem_send_cmd(MODEM_CMD_CONN_STOP, reply, &sz, "1");
}

void modem_print_output(const uint8_t *buf, int start, int end)
{
    int i;

    for (i = start; i < end; i++) {
        if (buf[i] == '\r') {
            putchar('\\');
            putchar('r');
        } else if (buf[i] == '\n') {
            putchar('\\');
            putchar('n');
        } else
            putchar(buf[i]);
    }

    putchar('\n');
}

static int __modem_configure(void)
{
    char reply[64];
    int ret;
    ssize_t sz;

    modem_send_cmd(MODEM_CMD_RESCODE_FMT, NULL, NULL, "0");

//    modem_send_cmd(MODEM_CMD_SICS_SETUP);
    modem_send_cmd(MODEM_CMD_SICS_CONTYPE, NULL, NULL, "0", "GPRS0");
    modem_send_cmd(MODEM_CMD_SICS_DNS1, NULL, NULL, "0", "81.18.113.2");
    modem_send_cmd(MODEM_CMD_SICS_DNS2, NULL, NULL, "0", "81.18.112.50");
    modem_send_cmd(MODEM_CMD_SICS_PASSWD, NULL, NULL, "0", "gdata");
    modem_send_cmd(MODEM_CMD_SICS_USER, NULL, NULL, "0", "gdata");
    modem_send_cmd(MODEM_CMD_SICS_APN, NULL, NULL, "0", "internet");
    modem_send_cmd(MODEM_CMD_SISS_SRVTYPE, NULL, NULL, "1", "Socket");
    modem_send_cmd(MODEM_CMD_SISS_CONNID, NULL, NULL, "1", "0");

    /* MODEM_CMD_SISS_ADDR may fail if we have some harware/software problems */
    modem_flush(0);
    ret = modem_send_cmd(MODEM_CMD_SISS_ADDR, reply, &sz,
                         "1", "socktcp://46.254.241.6:48025;disnagle=1");

    return ret;
}

static void *__modem_thread(void *arg)
{
    ssize_t sz;
    int ret;

    (void)arg;

    for (;;) {

        pthread_mutex_lock(&__modem.lock);

        /* If we are outside RX buffer boundaries, set up overflow flag and
           reset RX buffer */
        if ((__rx_ind + MODEM_READ_BYTES) > MODEM_RXBUF_SZ) {
            __modem.status |= MODEM_STATUS_BUFOVR;
            __rx_ind = 0;
        }

        sz = read(__modem.fd, __rx_buf + __rx_ind, MODEM_READ_BYTES);
        if (sz == -1) {
            if (errno == EAGAIN) {
                /* No data */
                pthread_mutex_unlock(&__modem.lock);
                continue;
            }  else {
                /* Some error */
                __modem.status |= MODEM_STATUS_ERR;
                __modem.err    |= MODEM_ERR_IO;
                pthread_mutex_unlock(&__modem.lock);
                continue;
            }
        } else if (sz == 0) {
            /* FD/Pipe closed? */
            __modem.status |= MODEM_STATUS_ERR;
            __modem.err    |= MODEM_ERR_EOF;
            pthread_mutex_unlock(&__modem.lock);
            continue;
        }

        __rx_ind += sz;
        __rx_buf[__rx_ind] = '\0';

        /* TODO: Optimize function */
        /* Scan for common URC messages. We easily can get undervoltage, wich
           means hardware isn't functional at the moment */
        ret = __scan_common_URC(__rx_buf);
        if (ret) {
            __modem.status |= MODEM_STATUS_URC;
            __modem.err    |= ret;
        }
#if 0
        printf("Buffer(%03lu): ", __rx_ind);
        __modem_print_output(__rx_buf, 0, __rx_ind);
#endif

        pthread_mutex_unlock(&__modem.lock);
    }

    return NULL;
}


unsigned int __scan_common_URC(const uint8_t *buf)
{
    char *ptr;

    /* Check if theres common URC signature in buffer */
    ptr = strstr((char *)buf, "^SBC: ");
    if (!ptr)
        return 0;

    /* Looking for overvoltage or undervolatege now */
    if (!memcmp(ptr + 6, "Overvoltage", 11))
        return MODEM_ERR_URC_OVRFLW;
    if (!memcmp(ptr + 6, "Undervolatege", 13))
        return MODEM_ERR_URC_UNDRFLW;

    /* In case we couldn't find over/under voltage, it may mean that we
       haven't received full string yet, so dont alert usert for now */

    return 0;
}
