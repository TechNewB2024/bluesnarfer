FILE *bt_rfcomm(int sock, char *str_bdaddr, int channel) {
    struct sockaddr_rc addr = {0};
    int status;

    addr.rc_family = AF_BLUETOOTH;
    addr.rc_channel = (uint8_t)channel;
    str2ba(str_bdaddr, &addr.rc_bdaddr);

    // Connect to the target device
    status = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (status < 0) {
        perror("bluesnarfer: connect");
        return NULL;
    }

    // Open a file stream for the socket
    FILE *fd = fdopen(sock, "r+");
    if (!fd) {
        perror("bluesnarfer: fdopen");
        close(sock);
        return NULL;
    }

    return fd;
}