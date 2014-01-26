#ifndef __MODEM_H
#define __MODEM_H

/* Page 277 of manual */
#define MODEM_AT_CONN_ERROR     -1 /* Software error */
#define MODEM_AT_CONN_ALLOCATED  2 /* Profile resource allocated */
#define MODEM_AT_CONN_CONNECTING 3 /* State after at^siso was issued */
#define MODEM_AT_CONN_UP         4 /* Data transfer is ready */
#define MODEM_AT_CONN_CLOSING    5 /* Connection is closing */
#define MODEM_AT_CONN_DOWN       6 /* - Service is finished
                                      - Remote conn reset
                                      - IP connection was closed
                                      because of error
                                   */
#define MODEM_AT_CONN_ALERTING   7 /* Client tries to connect with
                                      transparent TCP listener
                                      service
                                   */
#define MODEM_AT_CONN_CONNECTED  8 /* Client is connected with
                                      transparent TCP listener service
                                   */
#define MODEM_AT_CONN_RELEASED   9 /* Client disconnected from
                                      transparent TCP listener service
                                      but theres data to read
                                   */

/* Page 196 of manual */
#define MODEM_AT_REG_NOREG     0 /* Modem not registered and not
                                    searching for network.
                                    Technical problem. Possible reasons:
                                    1. No SIM
                                    2. No PIN
                                    3. No valid home PLMN on SIM */
#define MODEM_AT_REG_OK        1 /* Registered to home network */
#define MODEM_AT_REG_SEARCHING 2 /* ME searching for network. If
                                    minute or more passed and theres
                                    no registration, there might be some
                                    technical problem */
#define MODEM_AT_REG_DENIED    3 /* Registration denied */
#define MODEM_AT_REG_UNKNOWN   4 /* Not used */
#define MODEM_AT_REG_ROAMING   5 /* ME is on foreign network */

typedef enum {
    OK            = 0,
    CONNECT       = 1,
    RING          = 2,
    NO_CARRIER    = 3,
    ERROR         = 4,
    NO_DIALTONE   = 6,
    BUSY          = 7,
    NO_ANSWER     = 8,
    CONNECT_2400  = 47,
    CONNECT_4800  = 48,
    CONNECT_9600  = 49,
    CONNECT_14400 = 50,
} at_result_code_t;

typedef enum {
    MODEM_CMD_ECHO_SET = 0,
    MODEM_CMD_QUALITY_GET,
    MODEM_CMD_IMEI_GET,
    MODEM_CMD_PIN_AUTH,
    MODEM_CMD_CREG_CHECK,
    MODEM_CMD_CREG_SET,
    MODEM_CMD_AT,
    MODEM_CMD_SICS_CONTYPE,
    MODEM_CMD_SICS_DNS1,
    MODEM_CMD_SICS_DNS2,
/*    MODEM_CMD_SICS_AUTHMODE, */
    MODEM_CMD_SICS_PASSWD,
    MODEM_CMD_SICS_USER,
    MODEM_CMD_SICS_APN,
    MODEM_CMD_SICS_INACTTO,
    MODEM_CMD_SISS_SRVTYPE,
    MODEM_CMD_SISS_CONNID,
    MODEM_CMD_SISS_ADDR,
    MODEM_CMD_PACKET_SEND1,
    MODEM_CMD_PACKET_SEND2,
    MODEM_CMD_CONN_START,
    MODEM_CMD_CONN_STOP,
    MODEM_CMD_CONN_CHECK,
    MODEM_CMD_CFG_URC,
    MODEM_CMD_ERR_CERR,
    MODEM_CMD_SISS_SETUP,
    MODEM_CMD_SICS_SETUP,
    MODEM_CMD_ADC_TMP,
    MODEM_CMD_CLOCK_GET,
    MODEM_CMD_CUSD,
    MODEM_CMD_RESCODE_FMT,
} modem_cmd_id_t;

typedef enum {
    MODEM_STATUS_ONLINE  = 1 << 0,
    MODEM_STATUS_REG     = 1 << 1,
    MODEM_STATUS_CONNUP  = 1 << 2,
    MODEM_STATUS_ROAMING = 1 << 3,
    MODEM_STATUS_URC     = 1 << 4,
    MODEM_STATUS_BUFOVR  = 1 << 5,
    MODEM_STATUS_ERR     = 1 << 6,
} modem_status_t;

typedef enum {
    MODEM_ERR_IO          = 1 << 0,
    MODEM_ERR_EOF         = 1 << 1,
    MODEM_ERR_URC_OVRFLW  = 1 << 2,
    MODEM_ERR_URC_UNDRFLW = 1 << 3,
} modem_err_t;

typedef struct __modem_cmd
{
    modem_cmd_id_t id;
    const char     *cmd;
    int            args_num;
} modem_cmd_t;

typedef struct __modem_dev
{
    int             fd;
    pthread_mutex_t lock;
    pthread_t       tid;
    modem_status_t  status; /* Modem status bitset, for connection status see
                               conn_state_t */
    modem_err_t     err;    /* Modem error bitset */
} modem_dev_t;

/* If connection is down rx,tx,ack,unack are last known */
typedef struct __conn_state
{
    unsigned int rx;      /* Bytes received since last SISO */
    unsigned int tx;      /* Bytes sent since last SISO */
    unsigned int ack;     /* Bytes already sent and acknowledged */
    unsigned int unack;   /* Bytes sent but not acknowledged */
    unsigned int prof_id; /* Profile id */
    unsigned int state;   /* Connection state */
} conn_state_t;

#define GRACE_TIME(time) \
    do {                 \
        if (time != 0)   \
        usleep(time);    \
    } while (0)

int modem_init(const char *path);
int modem_conn_start(unsigned int profile);
int modem_conn_stop(unsigned int profile);

int modem_send_cmd(modem_cmd_id_t id, char *reply, ssize_t *sz, ...);
int modem_send_raw(const char *data, size_t len);

int modem_check_reg(void);
int modem_check_conn(unsigned int profile);

void modem_flush(unsigned int delay);

int modem_send_packet(char *data, size_t len);
int modem_get_reply(char *data, ssize_t *len);

inline void modem_status_reset(void);
inline void modem_status(modem_status_t *status, modem_err_t *err);

void modem_print_output(const uint8_t *buf, int start, int end);

#endif
