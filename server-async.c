#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <memory.h>
#include <unistd.h>

#define LISTEN_PORT 23333

int main(int argc, char **argv) {
    int err = 0;
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    int listen_sock = -1;
    int client_sock = -1;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;

    BIO *sbio = NULL;
    char rbuf[1024];
    int connected = 0;

    fd_set read_set;
    struct timeval timeout;
    int ret = 0;

    memset(&rbuf, 0, sizeof(rbuf));
    if (!SSL_library_init()) {
        printf("SSL lib init failed\n");
        return -1;
    }
    SSL_load_error_strings();

    // meth = TLSv1_method();
    meth = SSLv23_method();
    ctx = SSL_CTX_new(meth);

    // load the server cert, when will send to the client
    if (!SSL_CTX_use_certificate_file(ctx, "cert/sslserver.pem", SSL_FILETYPE_PEM)) {
        printf("can't load cert file\n");
        return -1;
    };
    // load the private key, which is used to unencript the data which encript with public key in the server cert by the client.
    if (!SSL_CTX_use_PrivateKey_file(ctx, "cert/sslserver-key.pem", SSL_FILETYPE_PEM)) {
        printf("can't load private key file\n");
        return -1;
    };

    // SSL_VERIFY_NONE means the server doesn't verify the client cert, only the client verify the server cert
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    ssl = SSL_new(ctx);

    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (listen_sock < 0) {
        printf("create socket failed\n");
        return -1;
    }

    memset(&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons(LISTEN_PORT);      /* Server Port number */

    err = bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv));

    if (err < 0) {
        printf("Bind failed\n");
        return -1;
    }

    err = listen(listen_sock, 20);
    if (err < 0) {
        printf("listen failed\n");
        return -1;
    }

    socklen_t sa_cli_size = sizeof(sa_cli);
    client_sock = accept(listen_sock, (struct sockaddr *)&sa_cli, &sa_cli_size);
    printf("Accept connect from %x, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);

    FD_ZERO(&read_set);
    FD_SET(client_sock, &read_set);
    timeout.tv_sec = 3000;
    timeout.tv_usec = 0;

    sbio = BIO_new_socket(client_sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    while (1) {
        printf("waiting on select\n");

        ret = select(client_sock + 1, &read_set, NULL, NULL, &timeout);

        if (ret < 0) {
            printf("selected failed\n");
            break;
        }
        if (ret == 0) {
            printf("select timeout\n");
            timeout.tv_sec = 10;
            timeout.tv_usec - 0;
            FD_SET(client_sock, &read_set);
            continue;
        }

        if (FD_ISSET(client_sock, &read_set)) {
            printf("the client socket is readable\n");

            if (!connected) {
                err = SSL_accept(ssl);
                if (err < 0) {
                    printf("ssl handshake failed\n");
                    ERR_print_errors_fp(stderr);
                    return -1;
                }

                printf("SSL handshake successful\n");
                connected = 1;
                continue;
            }

            ret = SSL_read(ssl, rbuf, sizeof(rbuf) - 1);
            if (ret <= 0) {
                ret = SSL_get_error(ssl, ret);
                if (ret == SSL_ERROR_ZERO_RETURN) {
                    printf("the connection is closed\n");
                }
                break;
            }
            rbuf[ret + 1] = '\0';
            printf("recv: %s\n", rbuf);
        }
    }

    close(client_sock);
    close(listen_sock);
    return 0;
}