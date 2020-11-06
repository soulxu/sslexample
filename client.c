#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <memory.h>
#include <unistd.h>

#define SERVER_PORT 23333
#define SERVER_ADDR "127.0.0.1"
#define BUF_SIZE 1024


int main(int argc, char **argv) {
    int err = 0;
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    int sock = -1;
    struct sockaddr_in server_addr;

    BIO *sbio;
    char *wbuf = "Hellow world!";

    fd_set read_set;
    fd_set write_set;
    struct timeval timeout;
    int ret = 0;
    char readbuf[BUF_SIZE];
    int connected = 0;
    int ready_to_send = 0;

    if (!SSL_library_init()) {
        printf("SSL lib init failed\n");
        return -1;
    }
    SSL_load_error_strings();
    //meth = TLSv1_method();
    // The version of TLS/SSL by neogtiate when handshake
    meth = SSLv23_method();

    ctx = SSL_CTX_new(meth);

    // load CA, the client use CA to verify server cert
    if (!SSL_CTX_load_verify_locations(ctx, "./cert/ca.pem", NULL)) {
        printf("load ca failed\n");
        return -1;
    }

    // setup what we need to verrify in handshank, the SSL_VERIFY_NONE only verify server certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    ssl = SSL_new(ctx);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(SERVER_PORT);       /* Server Port number */
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR); /* Server IP */

    FD_ZERO(&read_set);
    FD_SET(0, &read_set);
    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);
    timeout.tv_sec = 3000;
    timeout.tv_usec = 0;

    err = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (err < 0) {
        printf("Failed to connect\n");
        return -1;
    }

    sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    while (1) {
        ret = select(sock + 1, &read_set, &write_set, NULL, &timeout);
        if (ret < 0) {
            printf("select failed\n");
            break;
        }
        if (ret == 0) {
            printf("select timeout\n");
            FD_ZERO(&read_set);
            FD_SET(0, &read_set);
            FD_ZERO(&write_set);
            FD_SET(sock, &write_set);
            continue;
        }

        if (FD_ISSET(0, &read_set)) {
            printf("the read is ready\n");
            ret = read(0, &readbuf, BUF_SIZE);
            if (ret < 0) {
                printf("read failed\n");
                break;
            }
            ready_to_send = ret;
            FD_ZERO(&write_set);
            FD_SET(sock, &write_set);
            FD_ZERO(&read_set);
            FD_SET(0, &read_set);
            continue;
        }

        if (FD_ISSET(sock, &write_set)) {
            printf("the write is ready\n");
            if (!connected) {
                err = SSL_connect(ssl);
                if (err < 0) {
                    printf("ssl handshake failed\n");
                    ERR_print_errors_fp(stderr);
                    return -1;
                }
                printf("SSL handshake successful\n");
                connected = 1;
                FD_ZERO(&write_set);
                FD_ZERO(&read_set);
                FD_SET(0, &read_set);
                continue;
            }
            if (ready_to_send > 0) {
                ret = SSL_write(ssl, readbuf, ready_to_send);
                ready_to_send -= ret;
                if (ready_to_send <= 0) {
                    FD_ZERO(&write_set);
                    FD_ZERO(&read_set);
                    FD_SET(0, &read_set);
                }
            }
            else {
                FD_ZERO(&write_set);
                FD_ZERO(&read_set);
                FD_SET(0, &read_set);
            }
        }
    }

    close(sock);
    return 0;
}