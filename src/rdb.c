/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *   Mupen64plus-ui-console - rdb.c                                        *
 *   Mupen64Plus homepage: https://mupen64plus.org/                        *
 *   Copyright (C) 2018 glank                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.          *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifdef _WIN32
# include <Winsock2.h>
# include <ws2tcpip.h>
# define ioctl ioctlsocket
# define close closesocket
typedef int socklen_t;
#else
# include <netdb.h>
# include <sys/ioctl.h>
# include <sys/socket.h>
# include <termios.h>
# include <unistd.h>
# if defined(__FreeBSD__) || defined(__OpenBSD__)
#  include <libutil.h>
# elif defined(__APPLE__)
#  include <util.h>
# else
#  include <pty.h>
# endif
#endif

#include <errno.h>
#include <inttypes.h>
#include <SDL.h>
#include <SDL_thread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "core_interface.h"

#ifndef SIGTRAP
#define SIGTRAP 5
#endif

#ifdef _WIN32
static SOCKET           sock        = INVALID_SOCKET;
static SOCKET           cl          = INVALID_SOCKET;
#else
static char            *pty_link    = NULL;
static int              pty_s       = -1;
static int              sock        = -1;
static int              cl          = -1;
#endif
static char            *cl_addr     = NULL;
static char            *rdb_ipkt    = NULL;
static char            *rdb_opkt    = NULL;
static m64p_breakpoint  rdb_bkp_list[BREAKPOINTS_MAX_NUMBER];

static int              cl_if;
struct sockaddr         cl_sockaddr;
socklen_t               cl_socklen;
static m64p_error       m64p_errno;

static int              rdb_detach;
static _Bool            rdb_running;
static _Bool            cpu_stopped;

static SDL_Thread      *rdb_thread;
static jmp_buf          rdb_jmp;
static _Bool            rdb_noack;
static int              rdb_stopcode;

static char             rdb_ibuf[2048];
static int              rdb_ibuf_size;
static int              rdb_ibuf_pos;
static char             rdb_obuf[2048];
static int              rdb_obuf_size;

static void cleanup(void)
{
#ifdef _WIN32
    if (cl != INVALID_SOCKET) {
        closesocket(cl);
        cl = INVALID_SOCKET;
    }
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
#else
    if (pty_link) {
        unlink(pty_link);
        pty_link = NULL;
    }
    if (pty_s != -1) {
        close(pty_s);
        pty_s = -1;
    }
    if (cl != -1) {
        close(cl);
        cl = -1;
    }
    if (sock != -1) {
        close(sock);
        sock = -1;
    }
#endif
    if (cl_addr) {
        free(cl_addr);
        cl_addr = NULL;
    }
    if (rdb_ipkt) {
        free(rdb_ipkt);
        rdb_ipkt = NULL;
    }
    if (rdb_opkt) {
        free(rdb_opkt);
        rdb_opkt = NULL;
    }
    for (int i = 0; i < BREAKPOINTS_MAX_NUMBER; ++i) {
        if (rdb_bkp_list[i].flags != 0) {
            (*DebugBreakpointCommand)(M64P_BKP_CMD_REMOVE_IDX, i, NULL);
            memset(&rdb_bkp_list[i], 0, sizeof(rdb_bkp_list[i]));
        }
    }
    (*DebugSetCallbacks)(NULL, NULL, NULL);
    (*DebugSetRunState)(M64P_DBG_RUNSTATE_RUNNING);
    (*DebugStep)();
}

static void die(const char *note, int errtype)
{
#ifdef _WIN32
    char s[1024];
#endif
    switch (errtype) {
        case 0: /* generic error */
            fprintf(stderr, "%s\n", note);
            break;
        case 1: /* posix error */
            fprintf(stderr, "%s: %s\n", note, strerror(errno));
            break;
        case 2: /* getaddrinfo error */
            fprintf(stderr, "%s: %s\n", note, gai_strerror(errno));
            break;
        case 3: /* windows error */
#ifdef _WIN32
            if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
                              GetLastError(), 0, s, sizeof(s), NULL))
            {
                fprintf(stderr, "%s: %s\n", note, s);
            }
#endif
            break;
        case 4: /* socket error */
#ifdef _WIN32
            if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
                              WSAGetLastError(), 0, s, sizeof(s), NULL))
            {
                fprintf(stderr, "%s: %s\n", note, s);
            }
#else
            fprintf(stderr, "%s: %s\n", note, strerror(errno));
#endif
            break;
        case 5: /* mupen64plus error */
            fprintf(stderr, "%s: %s\n", note, CoreErrorMessage(m64p_errno));
            break;
    }
    cleanup();
    longjmp(rdb_jmp, -1);
}

#ifndef _WIN32
static int makeraw(int fd)
{
    struct termios t;
    if (tcgetattr(fd, &t) == -1)
        return -1;
    t.c_iflag = 0;
    t.c_oflag = 0;
    t.c_lflag = 0;
    t.c_cflag = CS8;
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSAFLUSH, &t) == -1)
        return -1;
    return 0;
}
#endif

static int hex_char(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static char hex_int(int d)
{
    if (d >= 0x0 && d <= 0x9)
        return d + '0';
    if (d >= 0xA && d <= 0xF)
        return d + 'a' - 10;
    return ' ';
}

static _Bool rdb_peek(void)
{
    if (rdb_ibuf_pos != rdb_ibuf_size)
        return 1;
#ifndef _WIN32
    int nread;
#else
    u_long nread;
#endif
    if (ioctl(cl, FIONREAD, &nread))
        die("ioctl()", 4);
    return nread != 0;
}

static void rdb_flush(void)
{
    if (rdb_obuf_size != 0) {
        int size = rdb_obuf_size;
        int n;
#ifndef _WIN32
        if (cl_if == 1)
            n = write(cl, rdb_obuf, size);
        else
            n = sendto(cl, rdb_obuf, size, 0, &cl_sockaddr, cl_socklen);
#else
        n = sendto(cl, rdb_obuf, size, 0, &cl_sockaddr, cl_socklen);
#endif
        rdb_obuf_size = 0;
        if (n != size)
            die("write()", 4);
    }
}

static char rdb_getc(void)
{
    while (rdb_ibuf_pos == rdb_ibuf_size) {
        int n;
#ifndef _WIN32
        if (cl_if == 1)
            n = read(cl, rdb_ibuf, sizeof(rdb_ibuf));
        else {
            n = recvfrom(cl, rdb_ibuf, sizeof(rdb_ibuf), 0,
                         &cl_sockaddr, &cl_socklen);
        }
#else
        n = recvfrom(cl, rdb_ibuf, sizeof(rdb_ibuf), 0,
                     &cl_sockaddr, &cl_socklen);
#endif
        if (n == -1)
            die("read()", 4);
        rdb_ibuf_size = n;
        rdb_ibuf_pos = 0;
    }
    return rdb_ibuf[rdb_ibuf_pos++];
}

static void rdb_putc(char c)
{
    if (rdb_obuf_size == sizeof(rdb_obuf))
        rdb_flush();
    rdb_obuf[rdb_obuf_size++] = c;
}

static char *rdb_getpkt(_Bool notification)
{
    const int bufsize = 128;

    /* get packet, retry on checksum error */
    _Bool retry;
    do {
        retry = 0;
        int pkt_size = 0;
        int pkt_cap = bufsize;
        if (rdb_ipkt)
            free(rdb_ipkt);
        rdb_ipkt = malloc(pkt_cap + 1);
        if (!rdb_ipkt) {
            errno = ENOMEM;
            die("malloc()", 1);
        }
        int tx_csum = -1;
        uint8_t rx_csum = 0;

        /* receive packet data */
        while (1) {
            char c = rdb_getc();

            /* check for packet terminator */
            if (c == '#') {
                int ci1 = hex_char(rdb_getc());
                int ci2 = hex_char(rdb_getc());
                if (ci1 != -1 && ci2 != -1)
                    tx_csum = ci1 * 0x10 + ci2;
                break;
            }
            rx_csum += c;
            int rl = 1;

            /* check for escape sequence */
            if (c == '}') {
                c = rdb_getc();
                rx_csum += c;
                c ^= ' ';
            }
            /* check for rle sequence */
            else if (c == '*' && pkt_size > 0) {
                c = rdb_getc();
                rx_csum += c;
                rl = c - '\x1D';
                c = rdb_ipkt[pkt_size - 1];
            }

            /* allocate and insert packet data */
            if (pkt_size + rl > pkt_cap) {
                if (pkt_size + rl > pkt_cap + bufsize)
                    pkt_cap = pkt_size + rl;
                else
                    pkt_cap += bufsize;
                char *new_pkt = realloc(rdb_ipkt, pkt_cap + 1);
                if (!new_pkt) {
                    errno = ENOMEM;
                    die("realloc()", 1);
                }
                rdb_ipkt = new_pkt;
            }
            memset(&rdb_ipkt[pkt_size], c, rl);
            pkt_size += rl;
        }
        rdb_ipkt[pkt_size] = 0;

        if (tx_csum == rx_csum) {
            /* checksum ok; acknowledge */
            if (!rdb_noack && !notification) {
                rdb_putc('+');
                rdb_flush();
            }
        }
        else {
            /* checksum failed; drop packet if it's a notification.
             * otherwise, request a retransmission.
             */
            if (!rdb_noack && !notification) {
                rdb_putc('-');
                rdb_flush();
            }
            /* wait for retransmission */
            while (1) {
                if (rdb_getc() == '$')
                    break;
            }
            /* start over */
            free(rdb_ipkt);
            retry = 1;
        }

    } while (retry);

    return rdb_ipkt;
}

static int rdb_putpkt(_Bool notification, const char *fmt, ...)
{
    /* allocate and format package */
    va_list ap;
    va_start(ap, fmt);
    int pkt_size = vsnprintf(NULL, 0, fmt, ap) + 1;
    va_end(ap);

    if (rdb_opkt)
        free(rdb_opkt);
    rdb_opkt = malloc(pkt_size);
    if (!rdb_opkt) {
        errno = ENOMEM;
        die("malloc()", 1);
    }
    va_start(ap, fmt);
    vsnprintf(rdb_opkt, pkt_size, fmt, ap);
    va_end(ap);

    /* send packet, retry on checksum error */
    _Bool retry;
    do {
        retry = 0;
        char *p = rdb_opkt;
        uint8_t csum = 0;

        /* send packet intro */
        rdb_putc(notification ? '%' : '$');

        /* send packet data */
        while (*p) {
            char c = *p++;

            /* escape bad characters */
            if (c == '#' || c == '$' || c == '*' || c == '}') {
                rdb_putc('}');
                csum += '}';
                c ^= ' ';
            }

            rdb_putc(c);
            csum += c;
        }

        /* send terminator and checksum */
        rdb_putc('#');
        rdb_putc(hex_int(csum / 0x10));
        rdb_putc(hex_int(csum % 0x10));
        rdb_flush();

        /* check ack */
        if (!rdb_noack && !notification) {
            char c = rdb_getc();
            if (c == '-')
                retry = 1;
            else if (c != '+') {
                /* malformed ack */
                goto err;
            }
        }

    } while (retry);

    free(rdb_opkt);
    rdb_opkt = NULL;
    return 0;

err:
    if (rdb_opkt) {
        free(rdb_opkt);
        rdb_opkt = NULL;
    }
    return -1;
}

static uint64_t rdb_get_reg(int reg_idx)
{
    if (reg_idx >= 0 && reg_idx < 32) {
        uint64_t *gp = (*DebugGetCPUDataPtr)(M64P_CPU_REG_REG);
        return gp[reg_idx - 0];
    }
    else if (reg_idx == 32) {
        uint32_t *c0 = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP0);
        return c0[12];
    }
    else if (reg_idx == 33) {
        uint64_t *lo = (*DebugGetCPUDataPtr)(M64P_CPU_REG_LO);
        return lo[0];
    }
    else if (reg_idx == 34) {
        uint64_t *hi = (*DebugGetCPUDataPtr)(M64P_CPU_REG_HI);
        return hi[0];
    }
    else if (reg_idx == 35) {
        uint32_t *c0 = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP0);
        return c0[8];
    }
    else if (reg_idx == 36) {
        uint32_t *c0 = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP0);
        return c0[13];
    }
    else if (reg_idx == 37) {
        uint32_t *pc = (*DebugGetCPUDataPtr)(M64P_CPU_PC);
        return pc[0];
    }
    else if (reg_idx >= 38 && reg_idx < 70) {
        uint64_t *fp = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP1_DOUBLE_PTR);
        return fp[reg_idx - 38];
    }
    else if (reg_idx == 70) {
        uint64_t *fc = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP1_FGR_64);
        return fc[31];
    }
    else if (reg_idx == 71) {
        uint64_t *fc = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP1_FGR_64);
        return fc[0];
    }
    else
        return 0;
}

static void rdb_set_reg(int reg_idx, uint64_t value)
{
    if (reg_idx >= 0 && reg_idx < 32) {
        uint64_t *gp = (*DebugGetCPUDataPtr)(M64P_CPU_REG_REG);
        gp[reg_idx - 0] = value;
    }
    else if (reg_idx == 32) {
        uint32_t *c0 = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP0);
        c0[12] = (uint32_t)value;
    }
    else if (reg_idx == 33) {
        uint64_t *lo = (*DebugGetCPUDataPtr)(M64P_CPU_REG_LO);
        lo[0] = value;
    }
    else if (reg_idx == 34) {
        uint64_t *hi = (*DebugGetCPUDataPtr)(M64P_CPU_REG_HI);
        hi[0] = value;
    }
    else if (reg_idx == 35) {
        uint32_t *c0 = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP0);
        c0[8] = (uint32_t)value;
    }
    else if (reg_idx == 36) {
        uint32_t *c0 = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP0);
        c0[13] = (uint32_t)value;
    }
    else if (reg_idx == 37) {
        uint32_t *pc = (*DebugGetCPUDataPtr)(M64P_CPU_PC);
        pc[0] = (uint32_t)value;
    }
    else if (reg_idx >= 38 && reg_idx < 70) {
        uint64_t *fp = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP1_DOUBLE_PTR);
        fp[reg_idx - 38] = value;
    }
    else if (reg_idx == 70) {
        uint64_t *fc = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP1_FGR_64);
        fc[31] = value;
    }
    else if (reg_idx == 71) {
        uint64_t *fc = (*DebugGetCPUDataPtr)(M64P_CPU_REG_COP1_FGR_64);
        fc[0] = value;
    }
}

static void frontend_init(void)
{
}

static void frontend_update(unsigned int pc)
{
    if (rdb_running)
        cpu_stopped = 1;
}

static void frontend_vi(void)
{
}

static int rdb_main(void *arg)
{
    if (setjmp(rdb_jmp))
        return -1;

    rdb_running = 0;
    cpu_stopped = 0;
    m64p_errno = (*DebugSetCallbacks)(frontend_init, frontend_update,
                                      frontend_vi);
    if (m64p_errno)
        die("DebugSetCallbacks()", 5);

    rdb_noack = 0;
    rdb_stopcode = SIGTRAP;
    rdb_ibuf_size = 0;
    rdb_ibuf_pos = 0;
    rdb_obuf_size = 0;

    char *c_arg = arg;
    if (strncmp(c_arg, "pty:", 4) == 0)
        cl_if = 1;
    else if (strncmp(c_arg, "tcp:", 4) == 0)
        cl_if = 2;
    else if (strncmp(c_arg, "udp:", 4) == 0)
        cl_if = 3;
    else
        die("unknown client interface", 0);
    cl_addr = malloc(strlen(&c_arg[4]) + 1);
    if (!cl_addr) {
        errno = ENOMEM;
        die("malloc()", 1);
    }
    strcpy(cl_addr, &c_arg[4]);

    cl_socklen = sizeof(cl_sockaddr);
    memset(&cl_sockaddr, 0, cl_socklen);

    if (cl_if == 1) {
#ifdef _WIN32
        die("this platform does not support pseudoterminals", 0);
#else
        char cl_name[1024];
        if (openpty(&cl, &pty_s, cl_name, NULL, NULL))
            die("openpty()", 1);
        if (makeraw(cl))
            die("makeraw()", 1);

        unlink(cl_addr);
        if (symlink(cl_name, cl_addr))
            die("symlink()", 1);
        pty_link = cl_addr;

        fprintf(stderr, "RDB PTY opened on %s, linked at %s\n",
                cl_name, cl_addr);
#endif
    }
    else {
        /* parse address */
        char *host = cl_addr;
        char *port = strchr(host, ':');
        if (!port)
            die("no port specified", 0);
        if (host == port)
            host = NULL;
        *port++ = 0;
        /* resolve address */
#ifdef _WIN32
        WSADATA wsadata;
        if (WSAStartup(MAKEWORD(2, 2), &wsadata))
            die("WSAStartup()", 4);
#endif
        struct addrinfo hints;
        struct addrinfo *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = (cl_if == 2 ? SOCK_STREAM : SOCK_DGRAM);
        hints.ai_flags = 0;
        hints.ai_protocol = 0;
        errno = getaddrinfo(host, port, &hints, &res);
        if (errno) {
#ifdef _WIN32
            die("getaddrinfo()", 2);
#else
            if (errno == EAI_SYSTEM)
                die("getaddrinfo()", 1);
            else
                die("getaddrinfo()", 2);
#endif
        }
        /* create socket and bind */
        for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
            sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sock == -1)
                continue;
            if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0)
                break;
            close(sock);
            sock = -1;
        }
        if (res)
            freeaddrinfo(res);
        if (sock == -1)
            die("bind()", 4);
        /* wait for connection (tcp) */
        if (cl_if == 2) {
            if (listen(sock, 1))
                die("listen()", 4);
            fprintf(stderr, "RDB listening on %s:%s\n",
                    host ? host : cl_addr, port);
            cl = accept(sock, &cl_sockaddr, &cl_socklen);
            if (cl == -1)
                die("accept()", 4);
            close(sock);
            fprintf(stderr, "RDB connected\n");
        }
        else {
            cl = sock;
            fprintf(stderr, "RDB bound to %s:%s\n",
                    host ? host : cl_addr, port);
        }
        sock = -1;
    }

    while (!rdb_detach) {
        if (rdb_running && cpu_stopped) {
            rdb_running = 0;
            cpu_stopped = 0;
            uint32_t *pc = (*DebugGetCPUDataPtr)(M64P_CPU_PC);
            rdb_putpkt(0, "T%02x25:%016x;", rdb_stopcode, pc[0]);
        }

        char *pkt = NULL;
        _Bool notification;

        if (rdb_peek()) {
            char c = rdb_getc();

            if (c == '\x03') {
                /* ctrl-c interrupt */
                rdb_stopcode = SIGINT;
                m64p_errno = (*DebugSetRunState)(M64P_DBG_RUNSTATE_PAUSED);
                if (m64p_errno)
                    die("DebugSetRunState(M64P_DBG_RUNSTATE_PAUSED)", 5);
            }
            else if (!rdb_running) {
                if (c == '$') {
                    /* normal packet */
                    pkt = rdb_getpkt(0);
                    notification = 0;
                }
                else if (c == '%') {
                    /* notification packet */
                    pkt = rdb_getpkt(1);
                    notification = 1;
                }
            }
        }

        if (!pkt)
            continue;
        if (notification)
            continue;

        char cmd;
        char type;
        unsigned int addr;
        unsigned int length;
        int64_t value;
        int n;

        /* feature control */
        if (strncmp(pkt, "qSupported", 10) == 0)
            rdb_putpkt(0, "QStartNoAckMode+");
        else if (strcmp(pkt, "QStartNoAckMode") == 0) {
            rdb_putpkt(0, "OK");
            rdb_noack = 1;
        }
        /* queries */
        else if (strcmp(pkt, "qAttached") == 0)
            rdb_putpkt(0, "1");
        else if (strcmp(pkt, "?") == 0)
            rdb_putpkt(0, "T%02x", rdb_stopcode);
        /* state control */
        else if (strcmp(pkt, "g") == 0) {
            char s[0x49 * 0x10 + 1];
            char *p = s;
            for (int i = 0; i < 0x48; ++i)
                p += sprintf(p, "%016" PRIx64, rdb_get_reg(i));
            rdb_putpkt(0, "%s", s);
        }
        else if (strncmp(pkt, "G", 1) == 0) {
            char *p = &pkt[1];
            for (int i = 0; i < 0x48; ++i) {
                if (sscanf(p, "%16" SCNx64 "%n", &value, &n) == 1) {
                    rdb_set_reg(i, value);
                    p += n;
                }
                else
                    break;
            }
            rdb_putpkt(0, "OK");
        }
        else if (sscanf(pkt, "p%x%n", &addr, &n) == 1
                 && pkt[n] == 0)
        {
            rdb_putpkt(0, "%016" PRIx64, rdb_get_reg(addr));
        }
        else if (sscanf(pkt, "P%x=%16" SCNx64 "%n",
                        &addr, &value, &n) == 2
                 && pkt[n] == 0)
        {
            rdb_set_reg(addr, value);
            rdb_putpkt(0, "OK");
        }
        else if (sscanf(pkt, "m%x,%x%n", &addr, &length, &n) == 2
                 && pkt[n] == 0)
        {
            if (length > 1024)
                rdb_putpkt(0, "E00");
            else {
                char o_pkt[1024 * 2 + 1];;
                char *p = o_pkt;
                *p = 0;
                for (unsigned int i = 0; i < length; ++i) {
                    if ((*DebugMemGetMemInfo)(M64P_DBG_MEM_TYPE, addr))
                        p += sprintf(p, "%02x", (*DebugMemRead8)(addr++));
                    else
                        break;
                }
                rdb_putpkt(0, o_pkt);
            }
        }
        else if (sscanf(pkt, "M%x,%x%n", &addr, &length, &n) == 2
                 && pkt[n] == ':')
        {
            char *p = &pkt[n + 1];
            unsigned int i;
            for (i = 0; i < length; ++i) {
                unsigned int v;
                if ((*DebugMemGetMemInfo)(M64P_DBG_MEM_TYPE, addr)
                    && sscanf(p, "%2x%n", &v, &n) == 1 && n == 2)
                {
                    (*DebugMemWrite8)(addr++, v);
                    p += n;
                }
                else
                    break;
            }
            if (i == length && *p == 0)
                rdb_putpkt(0, "OK");
            else
                rdb_putpkt(0, "E00");
        }
        /* execution control */
        else if (strcmp(pkt, "c") == 0 ||
                 (sscanf(pkt, "C%x%n", &addr, &n) == 1 && pkt[n] == 0))
        {
            rdb_stopcode = SIGTRAP;
            rdb_running = 1;
            m64p_errno = (*DebugSetRunState)(M64P_DBG_RUNSTATE_RUNNING);
            if (m64p_errno)
                die("DebugSetRunState(M64P_DBG_RUNSTATE_RUNNING)", 5);
            m64p_errno = (*DebugStep)();
            if (m64p_errno)
                die("DebugStep()", 5);
        }
        else if (strcmp(pkt, "s") == 0 ||
                 (sscanf(pkt, "S%x%n", &addr, &n) == 1 && pkt[n] == 0))
        {
            rdb_stopcode = SIGTRAP;
            rdb_running = 1;
            m64p_errno = (*DebugSetRunState)(M64P_DBG_RUNSTATE_PAUSED);
            if (m64p_errno)
                die("DebugSetRunState(M64P_DBG_RUNSTATE_PAUSED)", 5);
            m64p_errno = (*DebugStep)();
            if (m64p_errno)
                die("DebugStep()", 5);
        }
        else if (sscanf(pkt, "%1[zZ]%c,%x,%x%n",
                        &cmd, &type, &addr, &length, &n) == 4
                 && pkt[n] == 0)
        {
            m64p_breakpoint b;
            b.address = addr;
            b.endaddr = addr + length;
            b.flags = 0;
            if (type == '0' || type == '1')
                b.flags = M64P_BKP_FLAG_EXEC;
            else if (type == '2')
                b.flags = M64P_BKP_FLAG_WRITE;
            else if (type == '3')
                b.flags = M64P_BKP_FLAG_READ;
            else if (type == '4')
                b.flags = M64P_BKP_FLAG_WRITE | M64P_BKP_FLAG_READ;
            if (b.flags == 0)
                rdb_putpkt(0, "");
            else {
                b.flags |= M64P_BKP_FLAG_ENABLED;
                int b_idx = -1;
                for (int i = 0; i < BREAKPOINTS_MAX_NUMBER; ++i) {
                    if (rdb_bkp_list[i].address == b.address &&
                        rdb_bkp_list[i].endaddr == b.endaddr &&
                        rdb_bkp_list[i].flags == b.flags)
                    {
                        b_idx = i;
                        break;
                    }
                }
                if (cmd == 'Z' && b_idx == -1) {
                    b_idx = (*DebugBreakpointCommand)(M64P_BKP_CMD_ADD_STRUCT,
                                                      0, &b);
                    if (b_idx != -1) {
                        rdb_bkp_list[b_idx] = b;
                        rdb_putpkt(0, "OK");
                    }
                    else
                        rdb_putpkt(0, "E00");
                }
                else if (cmd == 'z' && b_idx != -1) {
                    (*DebugBreakpointCommand)(M64P_BKP_CMD_REMOVE_IDX,
                                              b_idx, NULL);
                    memset(&rdb_bkp_list[b_idx], 0,
                           sizeof(rdb_bkp_list[b_idx]));
                    rdb_putpkt(0, "OK");
                }
                else
                    rdb_putpkt(0, "OK");
            }
        }
        else if (strcmp(pkt, "D") == 0)
            rdb_detach = 1;
        else if (strcmp(pkt, "r") == 0)
            (*CoreDoCommand)(M64CMD_RESET, 0, NULL);
        else if (strcmp(pkt, "k") == 0)
            (*CoreDoCommand)(M64CMD_STOP, 0, NULL);
        else
            rdb_putpkt(0, "");
    }

    if (rdb_detach == 1)
        rdb_putpkt(0, "OK");
    else if (rdb_detach == 2)
        rdb_putpkt(0, "X0F");

    cleanup();

    return 0;
}

int rdb_start(const char *addr)
{
    if (rdb_thread)
        return -1;
    rdb_detach = 0;
#if SDL_VERSION_ATLEAST(2,0,0)
    rdb_thread = SDL_CreateThread(rdb_main, "rdb", (void*)addr);
#else
    rdb_thread = SDL_CreateThread(rdb_main, (void*)addr);
#endif
    if (!rdb_thread)
        return -1;
    return 0;
}

int rdb_stop(void)
{
    if (!rdb_thread)
        return -1;
    int status;
    rdb_detach = 2;
    SDL_WaitThread(rdb_thread, &status);
    rdb_thread = NULL;
    return status;
}
