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

#if 0
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
#endif

static int __get_IMEI(char *IMEI)
{
    int ret;
    char buf[256];
    ssize_t len;

    ret = modem_send_cmd(MODEM_CMD_IMEI_GET, buf, &len, NULL, 1);
    if (ret != MODEM_RET_OK || len != 15)
        return -1;

    memcpy(IMEI, buf, 15);

    return 0;
}

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

    __get_IMEI(IMEI);
    printf("IMEI> %s\n", IMEI);

    for (;;) {
        sleep(1);
        modem_status_get(&status, &err);
        printf("Status=%04X, Error=%04X\n", status, err);
        if ((status & MODEM_STATUS_REG) == 0) { /* No network registration */
            modem_send_cmd(MODEM_CMD_CREG_GET, NULL, NULL, NULL, 1);
            continue;
        }

        if ((status & MODEM_STATUS_CONN) == 0) {
            ret = modem_conn_start(TCS_SERV_PROF);
            printf("Starting connection=%d\n", ret);
        }
    }

#if 0
    modem_status_get(&status, &err);
    if ((status & MODEM_STATUS_ONLINE) == 0)
        return -1;
    printf("Modem initialized.\n");

    modem_flush(0);

    ret = modem_configure();
    if (ret < 0) {
        printf("Error configuring modem=%d\n", ret);
        return EXIT_FAILURE;
    }

    for (i = 0;; i++) {
        usleep(100000);
        printf("Cycle=%d\n", i);

        modem_status_get(&status, &err);
        printf("Status: %X; Error: %X\n", status, err);
        if (err & MODEM_ERR_URC_SYSSTART) {
            modem_status_reset(0);
            modem_configure();
            continue;
        } if (err & MODEM_ERR_IO) {
            printf("I/O error!!!\n");
            modem_status_reset(0);
            modem_send_cmd(MODEM_CMD_CFUN, NULL, NULL, "0", "1");
            sleep(5);
            continue;
        }

        if (status & MODEM_STATUS_URC) {
            printf("URC received: %s\n",
                   (err & MODEM_ERR_URC_OVRFLW) ? "Overvoltage":"Undervoltage");
        } else if (status & MODEM_STATUS_ERR) {
            printf("Error: %04X\n", err);
        }

        modem_flush(0);
        ret = modem_check_reg();
        if (ret == -1)
            continue;
        else if (ret != MODEM_AT_REG_OK &&
                 ret != MODEM_AT_REG_ROAMING) {
            modem_status_reset(MODEM_STATUS_AUTH|MODEM_STATUS_REG|
                               MODEM_STATUS_CONNUP);
            continue;
        }

        modem_flush(0);
        ret = modem_check_conn(1);
        if (ret == -1)
            continue;
        else if (ret != MODEM_AT_CONN_UP) {
            modem_status_reset(MODEM_STATUS_AUTH|MODEM_STATUS_CONNUP);
            if (ret == MODEM_AT_CONN_ALLOCATED) {
                modem_status_reset(MODEM_STATUS_AUTH|MODEM_STATUS_CONNUP);
                modem_conn_start(1);
            } else if (ret == MODEM_AT_CONN_DOWN) {
                modem_conn_stop(1);
                modem_conn_start(1);
            } else if (ret == MODEM_AT_CONN_CLOSING) {
                modem_conn_stop(1);
            }
        }

        bson b_auth = __auth_form_req();
        if (b_auth.err != BSON_VALID) {
            bson_destroy(&b_auth);
            continue;
        }

        if ((status & MODEM_STATUS_AUTH) == 0) {
            ret = modem_send_packet(b_auth.data, bson_size(&b_auth));
            if (ret) {
                printf("Failed.");
                continue;
            }
            modem_status_set(MODEM_STATUS_AUTH);
        }

        bson_destroy(&b_auth);

        bson b_upd = __update_form_req();
        if (b_upd.err != BSON_VALID) {
            bson_destroy(&b_auth);
            printf("b_upd failed.\n");
            continue;
        }

        printf("Sending update request of size %d\n", bson_size(&b_upd));
        ret = modem_send_packet(b_upd.data, bson_size(&b_upd));
        if (ret) {
            bson_destroy(&b_upd);
            printf("Failed upd.");
            continue;
        }

        bson_destroy(&b_upd);

        packets++;

        if (packets == 10) {
            modem_send_cmd(MODEM_CMD_CFUN, NULL, NULL, "0", "1");
            packets = 0;
            sleep(5);
        }

        printf("Req sent.\n");
    }
#endif
    return EXIT_SUCCESS;
}
