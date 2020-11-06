#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <memory.h>
#include <unistd.h>

#define SERVER_PORT 23333
#define SERVER_ADDR "127.0.0.1"
#define BUF_SIZE 1024

int verify_callback(X509_STORE_CTX *ctx,void *args) {
    printf("the verify callback is invoked, and pause job\n");
    ASYNC_pause_job();
    printf("resume_job\n");
    return 1;
}


int main(int argc, char **argv) {
    int err = 0;
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    int sock = -1;
    struct sockaddr_in server_addr;

    BIO *sbio;

    fd_set read_set;
    fd_set write_set;
    struct timeval timeout;
    int maxfd = 0;
    int ret = 0;
    char readbuf[BUF_SIZE];
    int connected = 0;
    int ready_to_send = 0;

    ENGINE *ssl_client_engine = NULL;

    size_t numfds = 0;
    OSSL_ASYNC_FD *async_fds = NULL;

    if (!SSL_library_init()) {
        printf("SSL lib init failed\n");
        return -1;
    }

    if (CONF_modules_load_file(NULL, NULL, 0) <= 0) {
        printf("failed to load config\n");
        return -1;
    }

    SSL_load_error_strings();
    //meth = TLSv1_method();
    // The version of TLS/SSL by neogtiate when handshake
    meth = SSLv23_method();

    ssl_client_engine = ENGINE_by_id("dasync");

    ctx = SSL_CTX_new(meth);


    if (!ENGINE_set_default(ssl_client_engine, ENGINE_METHOD_ALL)) {
        printf("failed to set default engine\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /*
    if (!SSL_CTX_set_client_cert_engine(ctx, ssl_client_engine)) {
        printf("failed to set engine\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    */
   /*
    if (!SSL_CTX_config(ctx, "/etc/openssl.cnf")) {
        printf("failed to load config\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    */
    // load CA, the client use CA to verify server cert
    if (!SSL_CTX_load_verify_locations(ctx, "./cert/ca.pem", NULL)) {
        printf("load ca failed\n");
        return -1;
    }

    // setup what we need to verrify in handshank, the SSL_VERIFY_NONE only verify server certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_mode(ctx, SSL_MODE_ASYNC);
    // SSL_CTX_set_cert_verify_callback(ctx, verify_callback, NULL);

    ssl = SSL_new(ctx);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(SERVER_PORT);       /* Server Port number */
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR); /* Server IP */

    // needn't to ready stdin first
    FD_ZERO(&read_set);
    // FD_SET(0, &read_set);
    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);
    maxfd = sock;
    timeout.tv_sec = 3000;
    timeout.tv_usec = 0;

    err = connect(maxfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (err < 0) {
        printf("Failed to connect\n");
        return -1;
    }

    sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    while (1) {
        ret = select(maxfd + 1, &read_set, &write_set, NULL, &timeout);

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
        for (int i = 0; i < maxfd + 1; i++) {
            if (FD_ISSET(i, &read_set)) {
                if (i == 0) {
                    printf("the read is ready\n");
                    ret = read(0, &readbuf, BUF_SIZE);
                    if (ret < 0) {
                        printf("read failed\n");
                        break;
                    }
                    ready_to_send = ret;
                    FD_ZERO(&write_set);
                    FD_SET(sock, &write_set);
                    // disable read stdin, we want to write next round;
                    FD_ZERO(&read_set);
                    maxfd = sock;
                    continue;
                }
            }

            if (FD_ISSET(i, &write_set)) {
                if (!connected) {
                    printf("the write is ready, and ready to connect\n"); 
                    if (i == sock) {
                        printf("the sock is writable\n");
                    }
                    for (int j = 0; j < numfds; j++) {
                        if (async_fds[j] == i) {
                            printf("the async fd is ready\n");
                        }
                    }
                    err = SSL_connect(ssl);
                    if (err < 0) {
                        err = SSL_get_error(ssl, err);
                        if (err == SSL_ERROR_WANT_ASYNC) {
                            printf("ssl async handshake\n");
                            if (!SSL_get_all_async_fds(ssl, NULL, &numfds)) {
                                printf("get all async fds failed\n");
                                return -1;
                            }
                            if (numfds == 0) {
                                continue;
                            }
                            printf("get %ld async fds\n", numfds);
                            if (async_fds != NULL) {
                                free(async_fds);
                            }
                            async_fds = malloc(sizeof(OSSL_ASYNC_FD) & numfds);
                            if (!SSL_get_all_async_fds(ssl, async_fds, &numfds)) {
                                printf("get all async fds failed\n");
                                free(async_fds);
                                async_fds = NULL;
                                return -1;
                            }
                            // disable read stdin, we want to finish the handshake
                            FD_ZERO(&read_set);
                            FD_ZERO(&write_set);
                            for (int j = 0; j < numfds; j++) {
                                if (async_fds[j] > maxfd)
                                    maxfd = async_fds[j];
                                FD_SET(async_fds[j], &write_set);
                            }
                            FD_SET(sock, &write_set);
                            if (sock > maxfd) {
                                maxfd = sock;
                            }
                            printf("set all async fds\n");
                            continue;
                        }
                        printf("ssl handshake failed\n");
                        ERR_print_errors_fp(stderr);
                        return -1;
                    }
                    printf("SSL handshake successful\n");
                    connected = 1;
                    FD_ZERO(&write_set);
                    FD_ZERO(&read_set);
                    FD_SET(0, &read_set);
                    maxfd = 0;
                    // cleanup the async fds;
                    free(async_fds);
                    async_fds = NULL;
                    numfds = 0;
                    continue;
                }
                printf("already connected, and ready to write\n");
                if (ready_to_send > 0) {
                    ret = SSL_write(ssl, readbuf, ready_to_send);
                    if (ret < 0) {
                        ret = SSL_get_error(ssl, ret);
                        if (err == SSL_ERROR_WANT_ASYNC) {
                            printf("ssl async write\n");
                            FD_ZERO(&write_set);
                            FD_SET(sock, &write_set);
                            continue;
                        }
                    }
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
    }

    close(sock);
    return 0;
}