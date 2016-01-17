#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

static int delay = 0;

static void usage(void)
{
    fprintf(stderr, "Usage: clientserver {client ipv4-server-addr|server}\n");
    exit(1);
}

static int server(int argc, char **argv)
{
    int one = 1, rc, s;
    struct sockaddr_in sin = {0};

    if (argc != 2) {
        usage();
    }

    sin.sin_family = AF_INET;
    sin.sin_port = 10000;

    s = socket(AF_INET, SOCK_STREAM, 0);
    assert(s >= 0);

    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(int));
    assert(rc == 0);

    rc = bind(s, (struct sockaddr *)&sin, sizeof(sin));
    assert(rc == 0);
    
    rc = listen(s, 5);
    assert(rc == 0);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        char buf[8192];
        size_t read_total = 0, written_total = 0;
        int client, rc;

        client = accept(s, (struct sockaddr *)&client_addr, &addrlen);
        assert(client >= 0);

        /* first, read exactly 2345 bytes */
        while (read_total < 2345) {
            if (delay) {
                usleep(rand() % 10000);
            }
            rc = read(client, buf, sizeof(buf));
            if (rc < 0) {
                perror("read");
                break;
            }
            if (rc == 0) {
                fprintf(stderr, "unexpected EOF from client\n");
                rc = -1;
            }
            read_total += rc;
        }
        
        while (rc >= 0 && written_total < 98765) {
            /* we don't care if we write *exactly* the desired total amount */
            if (delay) {
                usleep(rand() % 10000);
            }
            rc = write(client, buf, sizeof(buf));
            if (rc < 0) {
                perror("write");
                break;
            }
            written_total += rc;
        }
        close(client);
    }
    return 0;
}

static int client(int argc, char **argv)
{
    int rc, s;
    struct sockaddr_in sin = {0};
    size_t total_read = 0, to_write = 2345;

    if (argc != 3) {
        usage();
    }

    sin.sin_family = AF_INET;
    sin.sin_port = 10000;
    rc = inet_pton(AF_INET, argv[2], &sin.sin_addr);
    if (rc != 1) {
        usage();
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    assert(s >= 0);

    rc = connect(s, (struct sockaddr *)&sin, sizeof(sin));
    if (rc < 0) {
        perror("connect");
        exit(1);
    }

    while (to_write > 0) {
        if (delay) {
            usleep(rand() % 10000);
        }
        rc = write(s, "X", 1);
        if (rc < 0) {
            perror("write");
            exit(1);
        }
        to_write -= rc;
    }
    
    while (1) {
        char buf[2048];

        if (delay) {
            usleep(rand() % 10000);
        }
        rc = read(s, buf, sizeof(buf));
        if (rc < 0) {
            perror("read");
            exit(1);
        }
        if (rc == 0) {
            break;
        }
        total_read += rc;
    }
    printf("total read: %ld\n", (long)total_read);
    return 0;
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);

    if (argc < 2) {
        usage();
    }

    if (!strcasecmp(argv[1], "client")) {
        return client(argc, argv);
    }
    if (!strcasecmp(argv[1], "server")) {
        return server(argc, argv);
    }
    usage();
    /* unreached */
    exit(1);
}

