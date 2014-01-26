#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "modem.h"

int main(int argc, char *argv[])
{
    int ret;
    modem_status_t status;
    modem_err_t err;

    if (argc < 2)
        return EXIT_FAILURE;

    sleep(5);

    ret = modem_init(argv[1]);
    if (ret) {
        printf("Error: %d\n", ret);
        return EXIT_FAILURE;
    }

    for (;;) {
        modem_status(&status, &err);
        printf("Status: %X; Error: %X\n", status, err);
        if (status & MODEM_STATUS_URC) {
            printf("URC received: %s\n",
                   (err&MODEM_ERR_URC_OVRFLW) ? "Overvoltage" : "Undervoltage");
        } else if (status & MODEM_STATUS_ERR) {
            printf("Error: %04X\n", err);
        }

        modem_flush(0);
        ret = modem_check_reg();
        switch (ret) {
        case MODEM_AT_REG_SEARCHING:
            continue;
        case MODEM_AT_REG_NOREG:
        case MODEM_AT_REG_DENIED:
        case MODEM_AT_REG_UNKNOWN:
            printf("No registration or errors on reg.\n");
            continue;
            break;
        case MODEM_AT_REG_OK:
        case MODEM_AT_REG_ROAMING:
            break;
        default:
            printf("Unknown state: %d\n", ret);
            continue;
        }

        modem_flush(0);
        ret = modem_check_conn(1);
        switch (ret) {
        case MODEM_AT_CONN_ERROR:
        case MODEM_AT_CONN_CONNECTING:
        case MODEM_AT_CONN_CLOSING:
            printf("Propagated connection state.\n");
            continue;
        case MODEM_AT_CONN_UP:
            printf("Connection is UP.\n");
            break;
        case MODEM_AT_CONN_ALLOCATED:
            modem_conn_start(1);
            continue;
        case MODEM_AT_CONN_DOWN:
            printf("Connection is DOWN.\n");
            modem_conn_stop(1);
            modem_conn_start(1);
            continue;
        default:
            printf("Unknown network state.\n");
            continue;
        }

        modem_send_packet("data", 4);
    }

    return EXIT_SUCCESS;
}
