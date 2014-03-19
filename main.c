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

#include "modem.h"

#include "bson/bson.h"

#define DEV_NOAUTH   0
#define DEV_AUTH     1
#define DEV_AUTHWAIT 2

#define AUTH_MAX_TRIES 30

static unsigned int __auth       = DEV_NOAUTH;
static unsigned int __auth_tries = 0;

static int __client_auth(modem_status_t status);
static int __get_IMEI(char *IMEI);
static bson __update_form_req(void);
static bson __auth_form_req(void);

int main(int argc, char *argv[])
{
    char           IMEI[15];
    bson           req;
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

    ret = modem_configure();
    if (ret != MODEM_RET_OK) {
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

    for (;;) {
        sleep(1);
        modem_status_get(&status, &err);
        printf("Status=%04X, error=%04X, auth=%d\n", status, err, auth);

        if ((status & MODEM_STATUS_ONLINE) == 0) { /* Full restart */
            modem_destroy();
            goto __modem_start;
        }
        if ((status & MODEM_STATUS_REG) == 0) { /* No network registration */
            modem_send_cmd(MODEM_CMD_CREG_GET, NULL, NULL, NULL, 1);
            continue;
        }
        if ((status & MODEM_STATUS_CONN) == 0) {
            ret = modem_conn_start(TCS_SERV_PROF);
            if (ret != MODEM_RET_OK) {
                ret = modem_conn_stop(TCS_SERV_PROF);
            }
            continue;
        }

        __client_auth(status);

        /* TODO: Send packet */
    }

    return EXIT_SUCCESS;
}

static int __client_auth(modem_status_t status)
{
    bson        req;
    ssize_t     sz;
    int         res;
    uint8_t     rbuf[1024];
    modem_ret_t ret;

    if (__auth == DEV_AUTH) /* Already authenticated */
        return 0;

    if (__auth == DEV_NOAUTH) { /* No auth, no request sent */
        printf("Sending authentication request.\n");

        req = auth_form_req();
        if (req.err != BSON_VALID)
            return -1;

        ret = modem_send_packet(TCS_SERVICE_PROF,
                                (uint8_t *)req.data, bson_size(&req));
        printf("Auth request sent=%d\n", ret);
        if (ret != MODEM_RET_OK)
            return -1;

        __auth      = DEV_AUTHWAIT;
        __auth_tries = 0;
    } else if (__auth == DEV_AUTHWAIT) { /* No auth, request sent */
        if (__auth_tries > AUTH_MAX_TRIES) { /* Reply wait limit exceeded */
            __auth = DEV_NOAUTH;
            /* TODO: Close connection */
            return -1;
        }

        ret = modem_get_packet(TCS_SERVICE_PROF, rbuf, &sz);
        if (ret == MODEM_RET_OK) {
            /* TODO: Check reply */
        }

        __auth_tries ++;
    }
}

static bson __auth_form_req(void)
{
    bson broot;
//    char IMEI[15];

    bson_init(&broot);

    bson_append_long(&broot, "login", 7);
    bson_append_string(&broot, "passwd", "PASS");
    bson_append_string(&broot, "imei", "1234567890");
    bson_append_long(&broot, "ver", 1111);

    bson_finish(&broot);

    return broot;
}

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

static int __get_IMEI(char *IMEI)
{
    int ret, res;
    char buf[256];
    ssize_t len;

    ret = modem_send_cmd(MODEM_CMD_IMEI_GET, buf, &len, &res, 0);
    if (ret != MODEM_RET_OK)
        return -ret;
    if (len != 15 || res != 0)
        return MODEM_RET_PARSER;

    memcpy(IMEI, buf, 15);

    return 0;
}
