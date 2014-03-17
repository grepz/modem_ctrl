#ifndef __MODEM_H
#define __MODEM_H

#define CMD_PARSER_BUF_SZ 1024
#define URC_PARSER_BUF_SZ 256
#define MODEM_CMDBUF_SZ   256

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


#define AT_RESULT_CODE_OK            0
#define AT_RESULT_CODE_CONNECT       1
#define AT_RESULT_CODE_RING          2
#define AT_RESULT_CODE_NO_CARRIER    3
#define AT_RESULT_CODE_ERROR         4
#define AT_RESULT_CODE_NO_DIALTONE   6
#define AT_RESULT_CODE_BUSY          7
#define AT_RESULT_CODE_NO_ANSWER     8
#define AT_RESULT_CODE_CONNECT_2400  47
#define AT_RESULT_CODE_CONNECT_4800  48
#define AT_RESULT_CODE_CONNECT_9600  49
#define AT_RESULT_CODE_CONNECT_14400 50

typedef enum {
    MODEM_CMD_ECHO_SET = 0,
    MODEM_CMD_QUALITY_GET,
    MODEM_CMD_IMEI_GET,
    MODEM_CMD_PIN_AUTH,
    MODEM_CMD_CREG_GET,
    MODEM_CMD_CREG_SET,
    MODEM_CMD_AT,
    MODEM_CMD_SICS,
    MODEM_CMD_SISS,
    MODEM_CMD_PACKET_SEND1,
    MODEM_CMD_PACKET_SEND2,
    MODEM_CMD_CONN_START,
    MODEM_CMD_CONN_STOP,
    MODEM_CMD_CONN_CHECK,
    MODEM_CMD_CEER,
    MODEM_CMD_SISS_SETUP,
    MODEM_CMD_SICS_SETUP,
    MODEM_CMD_ADC_TMP,
    MODEM_CMD_CLOCK_GET,
    MODEM_CMD_CUSD,
    MODEM_CMD_CFUN,
    MODEM_CMD_SISE,
    MODEM_CMD_BAUD_SET,
    MODEM_CMD_SCFG,
    MODEM_CMD_RESCODE_FMT,
    MODEM_CMD_FLUSH,
} modem_cmd_id_t;

typedef enum {
    MODEM_STATUS_ONLINE   = 1 << 0,  /* Modem is initialized              */
    MODEM_STATUS_REG      = 1 << 1,  /* Modem registered in network       */
    MODEM_STATUS_CONN     = 1 << 2,  /* Modem connected to server         */
    MODEM_STATUS_WREADY   = 1 << 3,  /* Ready to send actual data         */
    MODEM_STATUS_RREADY   = 1 << 4,  /* There is data to read             */
    MODEM_STATUS_URCMODE  = 1 << 5,  /* URC mode enabled                  */
    MODEM_STATUS_SHUTDOWN = 1 << 6,  /* URC message received              */
    MODEM_STATUS_BUFOVR   = 1 << 7,  /* Buffer overflow, buffer was reset */
    MODEM_STATUS_ERR      = 1 << 8,  /* Error, see modem_err_t            */
    MODEM_STATUS_CMDCHECK = 1 << 9,  /* Check for command reply           */
    MODEM_STATUS_REPLY    = 1 << 10, /* Reply received                    */
} modem_status_t;

typedef enum {
    MODEM_ERR_IO           = 1 << 0, /* I/O error        */
    MODEM_ERR_EOF          = 1 << 1, /* Device closed?   */
    MODEM_ERR_URC_OVRVOLT  = 1 << 2, /* Overvoltage      */
    MODEM_ERR_URC_UNDVOLT  = 1 << 3, /* Undervoltage     */
    MODEM_ERR_URC_SYSSTART = 1 << 4, /* System restarted */
} modem_err_t;

typedef enum {
    MODEM_RET_OK = 0,
    MODEM_RET_PARSER,
    MODEM_RET_PARAM,
    MODEM_RET_IO,
    MODEM_RET_MEM,
    MODEM_RET_SYS,
    MODEM_RET_AT,
    MODEM_RET_TIMEOUT,
    MODEM_RET_UNKN,
} modem_ret_t;

typedef enum {
    URC_PARSER_NONE = 0,
    URC_PARSER_CMD_CHECK,
    URC_PARSER_DATA_CHECK,
    URC_PARSER_DATA_ENDCHECK,
} urc_parser_state_t;

typedef enum {
    CMD_PARSER_NONE = 0,
    CMD_PARSER_REPLY,
    CMD_PARSER_DELIM,
    CMD_PARSER_ENDCHECK,
} cmd_parser_state_t;

typedef struct __at_cmd
{
    char         buf[MODEM_CMDBUF_SZ];
    unsigned int ind;
    size_t       len;
} at_cmd_t;

typedef struct __modem_cmd
{
    modem_cmd_id_t id;
    const char     *cmd;
    int            args_num;
} modem_cmd_t;

/* If connection is down rx,tx,ack,unack are last known */
typedef struct __conn_state
{
    unsigned int rx;      /* Bytes received since last SISO */
    unsigned int tx;      /* Bytes sent since last SISO */
    unsigned int ack;     /* Bytes already sent and acknowledged */
    unsigned int unack;   /* Bytes sent but not acknowledged */
    unsigned int prof_id; /* Profile id */
    int          state;   /* Connection state */
} conn_state_t;

typedef struct __modem_dev
{
    int             fd;
    pthread_mutex_t lock;
    pthread_t       tid;
    modem_status_t  status; /* Modem status bitset, for connection status see
                               conn_state_t */
    modem_err_t     err;    /* Modem error bitset */
    conn_state_t    conn;   /* Connection state and parameters */
} modem_dev_t;

typedef struct __urc_parser
{
    urc_parser_state_t urc_state; /* Parser state */
    char               buf[URC_PARSER_BUF_SZ];
    char               *cmd_end;  /* If format is '<CMD>:', points to ':' */
    unsigned int       ind;       /* Index to save data in buffer */
} urc_parser_t;

typedef struct __cmd_parser
{
    cmd_parser_state_t cmd_state;          /* Parser state */
    char               *resptr;            /* Pointer to a command
                                            * result(numeric) */
    char               buf[CMD_PARSER_BUF_SZ];
    unsigned int       ind;                /* Index to save data in buffer */
} cmd_parser_t;

#define GRACE_TIME(time) \
    do {                 \
        if (time != 0)   \
        usleep(time);    \
    } while (0)

#define TCS_SERV_PROF 0
#define TCU_SERV_PROF 1

/**
 * Initialize modem, run modem polling thread
 *
 * @param path Path to a modem device
 *
 * @return see modem_ret_t for codes
 */
modem_ret_t modem_init(const char *path);
/**
 * Stops modem polling thread, closes modem device for R/W
 *
 */
void modem_destroy(void);
/**
 * Get modem status and error bitset
 *
 * @param status Pointer to allocated variable
 * @param err Pointer to allocated variable
 */
void modem_status_get(modem_status_t *status, modem_err_t *err);
/**
 * Clear error states
 * TODO:
 */
void modem_err_clear(void);
/**
 * Send buffer data directly to a modem device
 *
 * @param data Data to send
 * @param len Data length
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_send_raw(const uint8_t *data, size_t len);
/**
 * Send preformatted command to a modem device
 *
 * @param id Command ID(modem_cmd_id_t)
 * @param reply If not NULL look for reply if command was successfully sent to
 *              modem
 * @param sz if reply is not NULL stores reply length
 * @param res If reply and res not NULL return command result
 * @param delay If non-zero, sleep for AT_TIMEOUT_REPLY_WAIT
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_send_cmd(modem_cmd_id_t id, char *reply, ssize_t *sz,
                           int *res, unsigned int delay, ...);
/**
 * Get previous command reply
 *
 * @param data Buffer to save to
 * @param len Reply length is stored here
 * @param result If not NULL, save AT result code
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_get_reply(char *data, ssize_t *len, int *result);
/**
 * Starts already configured socket connections
 *
 * @param profile Profile to start
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_conn_start(unsigned int profile);
/**
 * Stops established socket connection
 *
 * @param profile Profile to stop
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_conn_stop(unsigned int profile);
/**
 * Configure modem device
 *
 *
 * @return Only MODEM_RET_OK for now
 */
modem_ret_t modem_configure(void);
/**
 * Send data over tcp socket.
 *
 * @param data Data to send
 * @param len Data length to send
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_send_packet(const uint8_t *data, size_t len);
/**
 * Send AT+CEER command and receive extended error report
 *
 * @param loc Error location
 * @param reason Error reasin
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_get_err(int *loc, int *reason);

#endif
