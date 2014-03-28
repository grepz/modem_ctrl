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
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "modem.h"

#include "bson/bson.h"

#define DEV_NOAUTH   0
#define DEV_AUTH     1
#define DEV_AUTHWAIT 2

#define MAX_DOWNLOAD_TRIES 5
#define AUTH_MAX_TRIES     15

static unsigned int __auth       = DEV_NOAUTH;
static unsigned int __auth_tries = 0;

static int __client_auth(modem_status_t status);
static int __get_IMEI(char *IMEI);
//static bson __update_form_req(void);
static bson __auth_form_req(void);
static modem_ret_t __get_bin(modem_status_t status);
static int __check_auth_reply(void);
static int __modem_configure(void);

int main(int argc, char *argv[])
{
    char           IMEI[15];
    modem_status_t status;
    modem_err_t    err;
    modem_ret_t    ret;

    (void)argv;
    (void)argc;

//    if (argc < 2) {
//        printf("Set device to operate.\n");
//        return EXIT_FAILURE;
//    }

    printf("Started, device '%s' used\n", argv[1]);

__modem_start:

    ret = modem_init("/dev/ttyUSB0");
    if (ret != MODEM_RET_OK) {
        printf("Error initializing modem=%d\n", ret);
        return EXIT_FAILURE;
    }

    ret = __modem_configure();
    if (ret != 0) {
        printf("Error configuring modem=%d\n", ret);
        return EXIT_FAILURE;
    }

    ret = __get_IMEI(IMEI);
    if (ret == 0)
        printf("IMEI> %s\n", IMEI);
    else {
        printf("No IMEI received: %d\n", ret);
        return EXIT_FAILURE;
    }

#if 0
    for (;;) {
        modem_get_status(&status, &err);
        printf("Status=%04X, error=%04X, auth=%d\n", status, err, __auth);
        if ((status & MODEM_STATUS_ONLINE) == 0) { /* Full restart */
            modem_destroy();
            goto __modem_start;
        }
        if ((status & MODEM_STATUS_REG) == 0) { /* No network registration */
            modem_send_cmd(MODEM_CMD_CREG_GET, NULL, NULL, NULL, 1);
            continue;
        }

       ret = modem_conn_start(BP_SERVICE_PROF);
       if (ret != MODEM_RET_OK) {
           ret = modem_conn_stop(BP_SERVICE_PROF);
           continue;
       }

       sleep(10);

        __get_bin(status);
    }
#endif

    for (;;) {
        sleep(1);

        modem_get_status(&status, &err);
        printf("Status=%04X, error=%04X, auth=%d\n", status, err, __auth);

        if ((status & MODEM_STATUS_ONLINE) == 0) { /* Full restart */
            modem_destroy();
            goto __modem_start;
        }
        if ((status & MODEM_STATUS_REG) == 0) { /* No network registration */
            modem_send_cmd(MODEM_CMD_CREG_GET, NULL, NULL, NULL, 1);
            continue;
        }
        if ((status & MODEM_STATUS_CONN) == 0) {
            ret = modem_conn_start(TCS_SERVICE_PROF);
            if (ret != MODEM_RET_OK) {
                ret = modem_conn_stop(TCS_SERVICE_PROF);
            }
            continue;
        }

        __client_auth(status);
    }

    return EXIT_SUCCESS;
}

static modem_ret_t __get_bin(modem_status_t status)
{
    int          fd, res, tries;
    modem_ret_t  ret;
    ssize_t      len;
    uint8_t      *data;
    mode_t       mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    conn_state_t cs;

    fd = open("/tmp/file.bin", O_RDWR | O_CREAT | O_TRUNC, mode);
    if (fd == -1)
        return MODEM_RET_IO;

    tries = 0;

    for (;;) {
        if (tries == MAX_DOWNLOAD_TRIES)
            return MODEM_RET_TIMEOUT;

//        if (modem_get_connstate(BP_SERVICE_PROF, &cs) != MODEM_RET_OK)
//            continue;
//        printf("Connection status=%d, RX=%d, TX=%d\n",
//               cs.state, cs.rx, cs.tx);
//        if (cs.state != MODEM_AT_CONN_UP)
//            return MODEM_RET_CONN;

        ret = modem_send_cmd(MODEM_CMD_DATA_READ,&data,&len,&res,0,"2","1500");
        printf("Reading, fret=%d, result=%d, len=%ld\n", ret, res, len);
        if (ret == MODEM_RET_TIMEOUT) {
            tries ++;
            continue;
        } else if (ret != MODEM_RET_OK)
            return ret;

        if (len == -2)
            exit(EXIT_SUCCESS);

        tries = 0;

        if (len > 0) {
            printf("Writing data of length=%lu\n", len);
            write(fd, data, len);
            free(data);
        }
    }

    printf("Finished getting binary!\n");

    close(fd);

    return 0;
}

static int __client_auth(modem_status_t status)
{
    bson        req;
    modem_ret_t ret;

    (void)status;


    switch (__auth) {
    case DEV_AUTH:     /* Already authenticated */
        return 0;
    case DEV_NOAUTH:   /* No auth, no request sent */
        printf("Sending authentication request.\n");

        req = __auth_form_req();
        if (req.err != BSON_VALID)
            return -1;

        ret = modem_send_packet(TCS_SERVICE_PROF,
                                (uint8_t *)req.data, bson_size(&req));
        bson_destroy(&req);
        printf("Auth request sent=%d\n", ret);
        if (ret != MODEM_RET_OK)
            return -1;

        __auth      = DEV_AUTHWAIT;
        __auth_tries = 0;
        break;
    case DEV_AUTHWAIT: /* No auth, request sent */
        if (__auth_tries > AUTH_MAX_TRIES) { /* Reply wait limit exceeded */
            __auth = DEV_NOAUTH;
            return -1;
        }

        if (__check_auth_reply() == 0) {
            __auth = DEV_AUTH;
            return 0;
        }

        __auth_tries ++;
        break;
    }

    return 1;
}

static int __check_auth_reply(void)
{
    int         res;
    modem_ret_t ret;
    ssize_t     len;
    uint8_t     *data;
    bson        b;

    ret = modem_get_packet(TCS_SERVICE_PROF, &data, &len);
    if (ret != MODEM_RET_OK) {
        printf("Error getting server packet=%d\n", ret);
        return -1;
    }

    printf("Decoding BSON data of size=%ld\n", len);

    bson_init_unfinished_data(&b, (char *)data + 2, len - 2, 0);
    bson_print(&b);

    bson_destroy(&b);
    free(data);

    return 0;
}

static bson __auth_form_req(void)
{
    bson broot;
//    char IMEI[15];

    bson_init(&broot);

    bson_append_long(&broot,   "login",  7);
    bson_append_string(&broot, "passwd", "PASS");
    bson_append_string(&broot, "imei",   "1234567890");
    bson_append_long(&broot,   "ver",    1111);

    bson_finish(&broot);

    return broot;
}
#if 0
static bson __update_form_req(void)
{
    bson broot;

    bson_init(&broot);

    bson_append_long(&broot, "mj", 789);
    bson_append_long(&broot, "mi", 234);
    bson_append_long(&broot, "rv", 12312);
    bson_append_long(&broot, "bd", 5454);

    bson_finish(&broot);

    return broot;
}
#endif

static int __get_IMEI(char *IMEI)
{
    int     ret, res;
    uint8_t *buf;
    ssize_t len;

    ret = modem_send_cmd(MODEM_CMD_IMEI_GET, &buf, &len, &res, 0);
    if (ret != MODEM_RET_OK)
        return -ret;
    if (res != AT_RESULT_CODE_OK) {
        free(buf);
        return MODEM_RET_AT;
    }

    if (!buf)
        return MODEM_RET_PARSER;

    memcpy(IMEI, buf + 1, 15);
    free(buf);

    return 0;
}

static int __modem_configure(void)
{
    if (modem_base_config() != MODEM_RET_OK ||
        modem_prof_config("0", "GPRS0", "81.18.113.2", "81.18.112.50",
                          "inet.bwc.ru", "bwc", "bwc") != MODEM_RET_OK)
        return -1;

    if (modem_sock_config("0", "0",
            "socktcp://46.254.241.6:48026;disnagle=1") != MODEM_RET_OK ||
        modem_sock_config("1", "0",
            "socktcp://46.254.241.6:48026;disnagle=1") != MODEM_RET_OK ||
        modem_http_config("2", "0",
            "https://46.254.241.6/TR1-1-1.bin") != MODEM_RET_OK)
        return -2;

    return 0;
}
