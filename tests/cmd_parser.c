#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define PARSER_BUF_SZ   1024
#define MODEM_CMDBUF_SZ 256

typedef struct __at_cmd
{
    char         buf[MODEM_CMDBUF_SZ];
    unsigned int ind;
    size_t       len;
} at_cmd_t;

typedef enum {
    CMD_PARSER_NONE = 0,
    CMD_PARSER_REPLY,
    CMD_PARSER_DELIM,
    CMD_PARSER_ENDCHECK,
} cmd_parser_state_t;

typedef struct __cmd_parser
{
    cmd_parser_state_t cmd_state;
    uint8_t            *resptr;
    uint8_t            buf[PARSER_BUF_SZ];
    unsigned int       ind;
} cmd_parser_t;

cmd_parser_t __cmdp;
at_cmd_t  __atcmd = {
    .buf = "AT^SISS?",
    .len = 8,
    .ind = 0
};

void __reset_cmd_parser()
{
    __cmdp.cmd_state = CMD_PARSER_NONE;
    __cmdp.ind       = 0;
    __cmdp.resptr    = NULL;
}

int __process_CMD(const char *in, size_t sz)
{
    unsigned int i;

    for (i = 0; i < sz; i++) {
        if (__cmdp.ind == PARSER_BUF_SZ) {
            __reset_cmd_parser();
            return -1;
        }
        switch (__cmdp.cmd_state) {
        case CMD_PARSER_NONE: /* Start by looking for command echo */
            if (__atcmd.buf[__atcmd.ind] == in[i])
                __atcmd.ind ++;
            else
                __atcmd.ind = 0;

            /* Command echo match */
            if (__atcmd.ind == __atcmd.len) {
                __atcmd.ind    = 0;
                __cmdp.cmd_state = CMD_PARSER_REPLY;
            }
            break;
        case CMD_PARSER_REPLY:
            __cmdp.buf[__cmdp.ind++] = in[i];
            /* Looking for \r as a sign of next line or endof reply */
            if (in[i] == '\r')
                __cmdp.cmd_state = CMD_PARSER_DELIM;
            break;
        case CMD_PARSER_DELIM:
            __cmdp.buf[__cmdp.ind] = in[i];
            if (isdigit(in[i])) { /* if next char == \r, reply is succ found  */
                __cmdp.resptr = __cmdp.buf + __cmdp.ind;
                __cmdp.cmd_state = CMD_PARSER_ENDCHECK;
            } else if (in[i] != '\n' && in[i] != '\r') /* Next line in reply */
                __cmdp.cmd_state = CMD_PARSER_REPLY;

            __cmdp.ind ++;
            break;
        case CMD_PARSER_ENDCHECK:
            __cmdp.buf[__cmdp.ind++] = in[i];
            if (in[i] == '\r') { /* Done */
                printf("Answer\n");
                __cmdp.cmd_state = CMD_PARSER_NONE;
                __cmdp.ind   = 0;
                return 1;
            } else { /* Continue looking for an end */
                __cmdp.resptr    = NULL;
                __cmdp.cmd_state = CMD_PARSER_REPLY;
            }
            break;
        }
    }
    printf("\n");

    return 0;
}

int main()
{
    char input0[] =
        "ATV0\r0\r"
        "AT+IPR=115200\r0\r"
        "AT^SICS=0,CONTYPE,GPRS0\r\r\n0\r"
        "AT^SICS=0,DNS1,81.18.113.2\r\r\n0\r"
        "AT^SICS=0,DNS2,81.18.112.50\r\r\n0\r"
        "AT^SICS=0,PASSWD,none\r\r\n0\r"
        "AT^SISS?\r"
        "\r\n"
        "^SISS: 0,\"srvType\",\"Socket\"\r\n"
        "^SISS: 0,\"conId\",\"0\"\r\n"
        "^SISS: 0,\"alphabet\",\"0\"\r\n"
        "^SISS: 0,\"address\",\"\"\r\n";
    char input1[] =
        "^SISS: 0,\"tcpMR\",\"10\"\r\n"
        "^SISS: 0,\"tcpOT\",\"6000\"\r\n"
        "^SISS: 0,\"secOpt\",\"\"\r\n"
        "^SISS: 1,\"srvType\",\"\"\r\n"
        "^SISS: 2,\"srvType\",\"\"\r\n"
        "^SISS: 3,\"srvType\",\"\"\r\n"
        "^SISS: 4,\"srvType\",\"\"\r\n"
        "^SISS: 5,\"srvType\",\"\"\r\n"
        "^SISS: 6,\"srvType\",\"\"\r\n"
        "^SISS: 7,\"srvType\",\"\"\r\n"
        "^SISS: 8,\"srvType\",\"\"\r\n"
        "^SISS: 9,\"srvType\",\"\"\r\n"
        "0\r"
        "AT^SICS=0,USER,none\r\r\n0\r"
        "AT^SICS=0,APN,inet.bwc.ru\r\r\n0\r"
        "AT^SISS=0,SRVTYPE,Socket\r\r\n0\r"
        "AT^SISS=0,CONID,0\r\r\n0\r";

    memset(&__cmdp, 0, sizeof(__cmdp));

    int ret1 = __process_CMD(input0, strlen(input0));
    int ret2 =__process_CMD(input1, strlen(input1));

    printf("Result: %d:%d\n%s\n", ret1, ret2, __cmdp.buf);

    return 0;
}
