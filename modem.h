#ifndef __MODEM_H
#define __MODEM_H

#define GSM_CONN_PROF         0 /* Default connection profile */

#define TCS_SERVICE_PROF      0 /* TCS service profile number */
#define TUS_SERVICE_PROF      1 /* TUS service profile number */
#define BP_SERVICE_PROF       2 /* TUS service profile number */

#define REPLY_DEFAULT_TIMEOUT 30  /* Default reply timeout */
#define REPLY_REG_TIMEOUT     300 /* GPRS service registration timeout. It
                                     can take up to 5 minutes to register
                                     in providers network */
#define MODEM_BITRATE         115200 /* BGS2-W-R2 with factory settings works on
                                     autobauding which means some URC messages
                                     are skip, so we setup bitrate as we see
                                     fit */

#define MODEM_RXBUF_MAXLEN    2048 /* Receive buffer max length */
#define MODEM_CMDBUF_SZ       256  /* Max cmd len */

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
#define MODEM_AT_REG_NOREG       0 /* Modem not registered and not
                                      searching for network.
                                      Technical problem. Possible reasons:
                                      1. No SIM
                                      2. No PIN
                                      3. No valid home PLMN on SIM */
#define MODEM_AT_REG_OK          1 /* Registered to home network */
#define MODEM_AT_REG_SEARCHING   2 /* ME searching for network. If
                                      minute or more passed and theres
                                      no registration, there might be some
                                      technical problem */
#define MODEM_AT_REG_DENIED      3 /* Registration denied */
#define MODEM_AT_REG_UNKNOWN     4 /* Not used */
#define MODEM_AT_REG_ROAMING     5 /* ME is on foreign network */

/**** URC codes begin ****/
/* See at_cmd_format.org */
/*************************/

#define AT_URC_SISW_WREADY  1
#define AT_URC_SISW_WCLOSED 2

#define AT_URC_SISR_RPEND   1
#define AT_URC_SISR_RCLOSED 2

/***** URC codes end *****/

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
    URC_INFOID_SOCK_BADADDR     = 3,
    URC_INFOID_SOCK_NETUNAVAIL  = 13,
    URC_INFOID_SOCK_CONNABORT   = 14,
    URC_INFOID_SOCK_CONNRESET   = 15,
    URC_INFOID_SOCK_NOBUF       = 16,
    URC_INFOID_SOCK_CONNTIMEOUT = 20,
    URC_INFOID_SOCK_CONNREJECT  = 21,
    URC_INFOID_SOCK_HOSTUNREACH = 22,
    URC_INFOID_SOCK_UNEXPERR    = 23,
    URC_INFOID_DNS_NOHOST       = 24,
    URC_INFOID_DNS_UNRECERR     = 26,
    URC_INFOID_UNKNERR          = 46,
    URC_INFOID_SOCK_PEERCLOSE   = 48,
    URC_INFOID_NOMEM            = 49,
    URC_INFOID_INTERR           = 50,
    URC_INFOID_HTTP_CLIENTERR   = 201,
} urc_infoid_t;

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
    MODEM_CMD_DATA_READ,
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
    MODEM_CMD_SAVE_PROFILE,
    MODEM_CMD_GPRS_REG,
    MODEM_CMD_FLUSH,
} modem_cmd_id_t;

typedef enum {
    MODEM_STATUS_ONLINE    = 1 << 0,  /* Modem is initialized              */
    MODEM_STATUS_REG       = 1 << 1,  /* Modem registered in network       */
    MODEM_STATUS_CONN      = 1 << 2,  /* Modem connected to server         */
    MODEM_STATUS_WREADY    = 1 << 3,  /* Ready to send actual data         */
    MODEM_STATUS_RPEND     = 1 << 4,  /* There is data to read             */
    MODEM_STATUS_URCMODE   = 1 << 5,  /* URC mode enabled                  */
    MODEM_STATUS_SHUTDOWN  = 1 << 6,  /* URC message received              */
    MODEM_STATUS_BUFOVR    = 1 << 7,  /* Buffer overflow, buffer was reset */
    MODEM_STATUS_ERR       = 1 << 8,  /* Error, see modem_err_t            */
    MODEM_STATUS_CMDCHECK  = 1 << 9,  /* Check for command reply           */
    MODEM_STATUS_DATACHECK = 1 << 10, /* Check for data reply              */
    MODEM_STATUS_REPLY     = 1 << 11, /* Reply received                    */
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
    REPLY_PARSER_NONE = 0,
    REPLY_PARSER_SISR,
    REPLY_PARSER_DATA,
    REPLY_PARSER_REPLY,
    REPLY_PARSER_DELIM,
    REPLY_PARSER_ENDCHECK,
} reply_parser_state_t;

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
    unsigned int rx;      /* Bytes received since last SISO      */
    unsigned int tx;      /* Bytes sent since last SISO          */
    unsigned int ack;     /* Bytes already sent and acknowledged */
    unsigned int unack;   /* Bytes sent but not acknowledged     */
    unsigned int prof_id; /* Profile id                          */
    int          state;   /* Connection state                    */
} conn_state_t;

typedef struct __modem_dev
{
    int             fd;
    pthread_mutex_t lock;
    pthread_t       tid;
    modem_status_t  status; /* Modem status bitset, for connection status
                             * see conn_state_t                           */
    modem_err_t     err;    /* Modem error bitset                         */
    conn_state_t    conn;   /* Connection state and parameters            */
} modem_dev_t;

typedef struct __urc_parser
{
    urc_parser_state_t state;    /* Parser state                         */
    char               *cmd_end; /* If format is '<CMD>:', points to ':' */
    unsigned int       ind;      /* Index to save data in buffer         */
} urc_parser_t;

typedef struct __reply_parser
{
    reply_parser_state_t state; /* Parser state                 */
    uint8_t              *resp; /* ptr to a cmd result(numeric) */
    ssize_t              rlen;  /* Actual reply data length     */
    unsigned int         ind;   /* Index to save data in buffer */
} reply_parser_t;

typedef struct sics_prof
{
    char *id;
    char *dns1;
    char *dns2;
    char *contype;
    char *apn;
    char *user;
    char *passwd;
} sics_prof_t;

typedef struct siss_prof
{
    char *stype;
    char *id;
    char *sp_id;
    char *addr;
} sisss_prof_t;

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
 *              modem. Free reply var in case it was successfully found.
 * @param sz if reply is not NULL stores reply length
 * @param res If reply and res not NULL return command result here
 * @param delay If zero wait for reply for MODEM_WAIT_REPLY_SLEEP, else use
 *              delay value
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_send_cmd(modem_cmd_id_t id, uint8_t **reply, ssize_t *sz,
                           int *res, unsigned int delay, ...);
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
 * Basic modem configuration. Output format, bitrate, etc.
 *
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_base_config(void);
/**
 * Configure modem service profile
 *
 * @param id Service profile ID
 * @param type Service profile type
 * @param dns1 DNS1 setting
 * @param dns2 DNS2 setting
 * @param apn APN setting
 * @param user user settting
 * @param passwd password setting
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_prof_config(const char *id, const char *type,
                              const char *dns1, const char *dns2,
                              const char *apn, const char *user,
                              const  char *passwd);
/*
 * Configure modem socket connection service
 *
 * @param id Socket service ID
 * @param sics_id Modem profile ID
 * @param addr Address setting
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_sock_config(const char *id, const char *sics_id,
                              const char *addr);
/**
 * Configure modem http connection service
 *
 * @param id Http service ID
 * @param sics_id Modem profile ID
 * @param addr Address setting
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_http_config(const char *id, const char *sics_id,
                              const char *addr);

/**
 * Send data over tcp socket.
 *
 * @param prof Profile to use
 * @param data Data to send
 * @param len Data length to send
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_send_packet(unsigned int prof,
                              const uint8_t *data, size_t len);
/**
 * Send SISR command and process its output
 *
 * @param data Data buffer to save to
 * @param len Resulting data buffer length
 *
 * @return see modem_ret_t
 */
modem_ret_t modem_get_data(uint8_t **data, ssize_t *len, ...);
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
