/*
 **
 **  sfcontrol.c
 **
 **  Copyright (C) 2002-2012 Sourcefire, Inc.
 **  Author(s):  Ron Dempster <rdempster@sourcefire.com>
 **
 **  NOTES
 **  5.16.11 - Initial Source Code. Dempster
 **
 **  This program is free software; you can redistribute it and/or modify
 **  it under the terms of the GNU General Public License Version 2 as
 **  published by the Free Software Foundation.  You may not use, modify or
 **  distribute this program under any other version of the GNU General
 **  Public License.
 **
 **  This program is distributed in the hope that it will be useful,
 **  but WITHOUT ANY WARRANTY; without even the implied warranty of
 **  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 **  GNU General Public License for more details.
 **
 **  You should have received a copy of the GNU General Public License
 **  along with this program; if not, write to the Free Software
 **  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 **
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <ctype.h>

#include "snort.h"
#include "sfcontrol_funcs.h"
#include "sfcontrol.h"

#ifdef CONTROL_SOCKET

#ifndef WIN32
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#endif

static char config_unix_socket_fn[PATH_MAX];
static int config_unix_socket;
static volatile int stop_processing = 0;

#pragma pack(1)
typedef struct _CS_RESPONSE_MESSAGE
{
    CSMessageHeader hdr;
    CSMessageDataHeader msg_hdr;
    char msg[1024];
} CSResponseMessage;
#pragma pack()

typedef struct _CS_MESSAGE
{
    CSMessageHeader hdr;
    uint8_t *data;
} CSMessage;

typedef struct _CS_MESSAGE_HANDLER
{
    struct _CS_MESSAGE_HANDLER *next;
    uint32_t type;
    OOBPreControlFunc oobpre;
    IBControlFunc ibcontrol;
    OOBPostControlFunc oobpost;
    pthread_mutex_t mutex;
    void *new_context;
    void *old_context;
    volatile int handled;
    volatile int ib_rval;
} CSMessageHandler;

#define CS_MAX_WORK 3
#define CS_MAX_IDLE_WORK    10

static unsigned s_work_to_do = 0;
static unsigned s_work_done = 0;

static pthread_mutex_t work_mutex = PTHREAD_MUTEX_INITIALIZER;
static CSMessageHandler *work_queue;
static CSMessageHandler *work_queue_tail;

static CSMessageHandler *msg_handlers[CS_TYPE_MAX];
static pthread_mutex_t msg_handler_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct _THREAD_ELEMENT
{
    struct _THREAD_ELEMENT *next;
    int socket_fd;
    volatile int stop_processing;
} ThreadElement;

static ThreadElement *thread_list;
static pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t thread_id;
static pthread_t *p_thread_id;

void ControlSocketConfigureDirectory(const char *optarg)
{
    const char *sep;
    ssize_t len;

    if (!optarg || config_unix_socket_fn[0])
        return;

    len = strlen(optarg);
    if (len && optarg[len - 1] == '/')
        sep = "";
    else
        sep = "/";
    snprintf(config_unix_socket_fn, sizeof(config_unix_socket_fn), "%s%s%s", optarg, sep, CONTROL_FILE);
}

int ControlSocketRegisterHandler(uint16_t type, OOBPreControlFunc oobpre, IBControlFunc ib,
                                 OOBPostControlFunc oobpost)
{
    if (type > CS_TYPE_MAX)
        return -1;
    pthread_mutex_lock(&msg_handler_mutex);
    if (msg_handlers[type])
    {
        pthread_mutex_unlock(&msg_handler_mutex);
        return -1;
    }
    if ((msg_handlers[type] = calloc(1, sizeof(*msg_handlers[type]))) == NULL)
    {
        pthread_mutex_unlock(&msg_handler_mutex);
        return -1;
    }
    pthread_mutex_init(&msg_handlers[type]->mutex, NULL);
    msg_handlers[type]->type = type;
    msg_handlers[type]->oobpre = oobpre;
    msg_handlers[type]->ibcontrol = ib;
    msg_handlers[type]->oobpost = oobpost;
    pthread_mutex_unlock(&msg_handler_mutex);
    return 0;
}

static void SendResponse(ThreadElement *t, const CSResponseMessage *resp, uint32_t len)
{
    ssize_t numsent;
    unsigned total_len = sizeof(resp->hdr) + len;
    unsigned total = 0;

    do
    {
        numsent = write(t->socket_fd, (*(uint8_t **)&resp) + total, total_len - total);
        if (!numsent)
            return;
        else if (numsent > 0)
            total += numsent;
        else if (errno != EINTR && errno != EAGAIN)
            return;
    } while (total < total_len && !t->stop_processing);
}

static void SendErrorResponse(ThreadElement *t, const char * const msg)
{
    CSResponseMessage response;
    uint32_t len;

    response.hdr.version = htons(CS_HEADER_VERSION);
    response.hdr.type = htons(CS_HEADER_ERROR);
    response.msg_hdr.code = -1;
    len = snprintf(response.msg, sizeof(response.msg), "%s", msg);
    response.msg_hdr.length = htons(len);
    len += sizeof(response.msg_hdr);
    response.hdr.length = htonl(len);
    SendResponse(t, &response, len);
}

static int ReadHeader(ThreadElement *t, CSMessageHeader *hdr)
{
    ssize_t numread;
    unsigned total = 0;

    do
    {
        numread = read(t->socket_fd, (*(uint8_t **)&hdr) + total, sizeof(*hdr) - total);
        if (!numread)
            return 0;
        else if (numread > 0)
            total += numread;
        else if (errno != EINTR && errno != EAGAIN)
            return -1;
    } while (total < sizeof(*hdr) && !t->stop_processing);

    if (total < sizeof(*hdr))
        return 0;

    hdr->length = ntohl(hdr->length);
    hdr->type = ntohs(hdr->type);
    hdr->version = ntohs(hdr->version);
    return 1;
}

static int ReadData(ThreadElement *t, uint8_t *buffer, uint32_t length)
{
    ssize_t numread;
    unsigned total = 0;

    do
    {
        numread = read(t->socket_fd, buffer + total, length - total);
        if (!numread)
            return 0;
        else if (numread > 0)
            total += numread;
        else if (errno != EINTR && errno != EAGAIN)
            return -1;
    } while (total < length && !t->stop_processing);

    if (total < length)
        return 0;

    return 1;
}

static void *ControlSocketProcessThread(void *arg)
{
    CSResponseMessage response;
    ThreadElement *t = (ThreadElement *)arg;
    int fd;
    pthread_t tid = pthread_self();
    CSMessageHeader hdr;
    CSMessageDataHeader *msg_hdr = NULL;
    uint32_t len, rlen;
    uint8_t *data = NULL;
    ThreadElement **it;
    int rval;

    if (t == NULL)
    {
        ErrorMessage("Control Socket: Invalid process thread parameter\n");
        return NULL;
    }
    if ((fd = t->socket_fd) == -1)
    {
        ErrorMessage("Control Socket: Invalid process thread socket\n");
        return NULL;
    }

    response.hdr.version = htons(CS_HEADER_VERSION);
    while (!t->stop_processing)
    {
        if ((rval = ReadHeader(t, &hdr)) == 0)
            goto done;
        else if (rval < 0)
            goto done;

        if (hdr.version != CS_HEADER_VERSION)
        {
            static const char * const bad_version = "Bad message header version";

            response.hdr.type = htons(CS_HEADER_ERROR);
            response.msg_hdr.code = -1;
            len = snprintf(response.msg, sizeof(response.msg), "%s", bad_version);
            response.msg_hdr.length = htons(len);
            len += sizeof(response.msg_hdr);
            response.hdr.length = htonl(len);
            SendResponse(t, &response, len);
            goto done;
        }

        if (hdr.length > 4096)
        {
            static const char * const bad_data = "Bad message data";

            SendErrorResponse(t, bad_data);
            goto done;
        }

        if (hdr.length && hdr.length < sizeof(*msg_hdr))
        {
            static const char * const bad_len = 
                "Bad message header length";

            SendErrorResponse(t, bad_len);
            goto done;
        }
        else if (hdr.length >= sizeof(*msg_hdr))
        {
            if ((data = malloc(hdr.length)) == NULL)
                goto done;

            if ((rval = ReadData(t, data, hdr.length)) == 0)
                goto done;
            else if (rval < 0)
                goto done;

            msg_hdr = (CSMessageDataHeader *)data;
            msg_hdr->code = ntohl(msg_hdr->code);
            msg_hdr->length = ntohs(msg_hdr->length);
            data += sizeof(*msg_hdr);
            rlen = msg_hdr->length;
        }
        else
        {
            /* We got no extra data */
            rlen = 0;
        }

        if (hdr.type > CS_TYPE_MAX)
        {
            static const char invalid_type[] = "Invalid type. Must be 0-2047 inclusive.";

            SendErrorResponse(t, invalid_type);
        }
        else
        {
            CSMessageHandler *handler;

            pthread_mutex_lock(&msg_handler_mutex);
            handler = msg_handlers[hdr.type];
            pthread_mutex_unlock(&msg_handler_mutex);
            if (handler)
            {
                static const char failed[] = "Failed to process the command.";

                pthread_mutex_lock(&handler->mutex);

                handler->handled = 0;
                handler->new_context = NULL;
                handler->old_context = NULL;
                handler->next = NULL;
                response.msg[0] = '\0';
                if (handler->oobpre && (rval = handler->oobpre(hdr.type, data, rlen,
                    &handler->new_context, response.msg, sizeof(response.msg))))
                {
                    response.hdr.type = htons(CS_HEADER_ERROR);
                    response.msg_hdr.code = -1;
                    if (!response.msg[0])
                    {
                        len = snprintf(response.msg, sizeof(response.msg), "%s", failed);
                    }
                    else
                    {
                        len = strlen(response.msg);
                    }
                    response.msg_hdr.length = htons(len);
                    len += sizeof(response.msg_hdr);
                    response.hdr.length = htonl(len);
                    SendResponse(t, &response, len);
                    pthread_mutex_unlock(&handler->mutex);
                    goto next;
                }
                if (response.msg[0])
                {
                    response.hdr.type = htons(CS_HEADER_DATA);
                    response.msg_hdr.code = 0;
                    len = strlen(response.msg);
                    response.msg_hdr.length = htons(len);
                    len += sizeof(response.msg_hdr);
                    response.hdr.length = htonl(len);
                    SendResponse(t, &response, len);
                }

                if (handler->ibcontrol)
                {
                    pthread_mutex_lock(&work_mutex);
                    if (work_queue_tail)
                        work_queue_tail->next = handler;
                    work_queue_tail = handler;
                    if (!work_queue)
                        work_queue = handler;
                    s_work_to_do++;
                    pthread_mutex_unlock(&work_mutex);
                    while (!handler->handled && !t->stop_processing)
                        usleep(100000);
                    if (handler->ib_rval || !handler->handled)
                    {
                        if (handler->oobpost && handler->new_context)
                            handler->oobpost(hdr.type, handler->new_context);
                        SendErrorResponse(t, failed);

                        pthread_mutex_unlock(&handler->mutex);
                        goto next;
                    }
                }
                if (handler->oobpost)
                    handler->oobpost(hdr.type, handler->old_context);

                pthread_mutex_unlock(&handler->mutex);

                response.hdr.type = htons(CS_HEADER_SUCCESS);
                response.hdr.length = 0;
                SendResponse(t, &response, 0);
            }
            else
            {
                static const char no_handler[] = "No handler for the command.";

                SendErrorResponse(t, no_handler);
            }
        }
next:;
        if (msg_hdr)
            free(msg_hdr);
        msg_hdr = NULL;
    }

done:;
    if (msg_hdr)
        free(msg_hdr);
    msg_hdr = NULL;

    close(fd);
    pthread_mutex_lock(&thread_mutex);
    for (it=&thread_list; *it; it=&(*it)->next)
    {
        if (t == *it)
        {
            *it = t->next;
            free(t);
            break;
        }
    }
    pthread_mutex_unlock(&thread_mutex);
    pthread_detach(tid);
    return NULL;
}

static void *ControlSocketThread(void *arg)
{
    ThreadElement *t;
    fd_set rfds;
    int rval;
    struct timeval to;
    int socket;
    struct sockaddr_un sunaddr;
    socklen_t addrlen = sizeof(sunaddr);
    pthread_t tid;

    if (config_unix_socket < 0)
    {
        ErrorMessage("Control Socket: Invalid socket in thread - %d\n", config_unix_socket);
        goto bail;
    }
    nice(2);

    while (!stop_processing)
    {
        to.tv_sec = 2;
        to.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(config_unix_socket, &rfds);
        rval = select(config_unix_socket + 1, &rfds, NULL, NULL, &to);
        if (rval > 0)
        {
            memset(&sunaddr, 0, sizeof(sunaddr));
            if ((socket = accept(config_unix_socket, (struct sockaddr *)&sunaddr, &addrlen)) == -1)
            {
                if (errno != EINTR)
                {
                    ErrorMessage("Control Socket: Accept failed: %s\n", strerror(errno));
                    goto bail;
                }
            }
            else
            {
                DEBUG_WRAP( DebugMessage(DEBUG_INIT, "Control Socket: Creating a processing thread for %d\n",
                                         socket););
                if ((t = calloc(1, sizeof(*t))) == NULL)
                {
                    close(socket);
                    ErrorMessage("Control Socket: Failed to allocate a thread struct");
                    goto bail;
                }
                t->socket_fd = socket;
                if ((rval = pthread_create(&tid, NULL, &ControlSocketProcessThread, (void *)t)) != 0)
                {
                    close(socket);
                    ErrorMessage("Control Socket: Unable to create a processing thread: %s", strerror(rval));
                    goto bail;
                }
                pthread_mutex_lock(&thread_mutex);
                t->next = thread_list;
                thread_list = t;
                pthread_mutex_unlock(&thread_mutex);
            }
        }
        else if (rval < 0)
        {
            if (errno != EINTR)
            {
                ErrorMessage("Control Socket: Select failed: %s\n", strerror(errno));
                goto bail;
            }
        }
    }

bail:;
    close(config_unix_socket);
    DEBUG_WRAP( DebugMessage(DEBUG_INIT, "Control Socket: Thread exiting\n"););
    return NULL;
}

static void SetupUnixSocket(const char * const name, int * const psock, const int listen_backlog)
{
    struct sockaddr_un sunaddr;
    int sock = -1;
    int yes = 1;
    int rval;

    memset(&sunaddr, 0, sizeof(sunaddr));

    rval = snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path), "%s", name);
    if (rval < 0 || (size_t)rval >= sizeof(sunaddr.sun_path))
        FatalError("Control Socket: Socket name '%s' is too long\n", name);

    sunaddr.sun_family = AF_UNIX;

    unlink(name);   /* remove existing file */

    /* open the socket */
    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
        FatalError("Control Socket: Error opening socket %s: %s\n", name, strerror(errno));
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
    {
        WarningMessage("Control Socket: setsockopt failed for %s: %s", name, strerror(errno));
    }

    if (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1)
    {
        rval = errno;
        close(sock);
        FatalError("Control Socket: Unable to bind to %s: %s\n", name, strerror(rval));
    }

    if (chmod(name, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP))
    {
        rval = errno;
        close(sock);
        FatalError("Control Socket: Error changing the mode for socket %s: %s", name, strerror(rval));
    }

    /* listen on the socket */
    if (listen(sock, listen_backlog) == -1)
    {
        rval = errno;
        close(sock);
        FatalError("Control Socket: Unable to listen on UNIX socket %s: %s\n", name, strerror(rval));
    }

    *psock = sock;
}

void ControlSocketInit(void)
{
    int rval;
    sigset_t mask;

    if (!config_unix_socket_fn[0])
        return;

    SetupUnixSocket(config_unix_socket_fn, &config_unix_socket, 10);

    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGQUIT);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGNAL_SNORT_RELOAD);
    sigaddset(&mask, SIGNAL_SNORT_DUMP_STATS);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGNAL_SNORT_ROTATE_STATS);
    sigaddset(&mask, SIGNAL_SNORT_CHILD_READY);
#ifdef TARGET_BASED
    sigaddset(&mask, SIGNAL_SNORT_READ_ATTR_TBL);
    sigaddset(&mask, SIGVTALRM);
#endif
    pthread_sigmask(SIG_SETMASK, &mask, NULL);

    if((rval=pthread_create(&thread_id, NULL, &ControlSocketThread, NULL)) != 0)
    {
        sigemptyset(&mask);
        pthread_sigmask(SIG_SETMASK, &mask, NULL);
        FatalError("Control Socket: Unable to create thread: %s\n", strerror(rval));
    }
    p_thread_id = &thread_id;
    sigemptyset(&mask);
    pthread_sigmask(SIG_SETMASK, &mask, NULL);
}

void ControlSocketCleanUp(void)
{
    ThreadElement *t;
    int rval;
    int done = 0;

    if (p_thread_id != NULL)
    {
        stop_processing = 1;

        if ((rval=pthread_join(*p_thread_id, NULL)) != 0)
            WarningMessage("Thread termination returned an error: %s\n", strerror(rval));
    }

    if (config_unix_socket_fn[0])
        unlink(config_unix_socket_fn);

    for (t = thread_list; t; t = t->next)
        t->stop_processing = 1;

    rval = 50;
    do
    {
        pthread_mutex_lock(&thread_mutex);
        done = thread_list ? 0:1;
        pthread_mutex_unlock(&thread_mutex);
        if (!done)
        {
            usleep(100000);
            rval--;
        }
    } while (!done && rval > 0);

    pthread_mutex_lock(&work_mutex);
    if (work_queue)
        WarningMessage("%s\n", "Work queue is not emtpy during termination");
    pthread_mutex_unlock(&work_mutex);
}

void ControlSocketDoWork(int idle)
{
    unsigned max_work;
    CSMessageHandler *handler;

    if ( s_work_done == s_work_to_do )
        return;

    max_work = idle ? CS_MAX_IDLE_WORK : CS_MAX_WORK;
    pthread_mutex_lock(&work_mutex);

    for (; work_queue && max_work; max_work--)
    {
        handler = work_queue;
        work_queue = handler->next;
        if (!work_queue)
            work_queue_tail = NULL;
        handler->ib_rval = handler->ibcontrol(handler->type, handler->new_context, &handler->old_context);
        handler->handled = 1;
        s_work_done++;
    }

    pthread_mutex_unlock(&work_mutex);
}

#else

void ControlSocketConfigureDirectory(const char *optarg)
{
    FatalError("%s\n", "Control socket is not available.");
}

int ControlSocketRegisterHandler(uint16_t type, OOBPreControlFunc oobpre, IBControlFunc ib,
                                 OOBPostControlFunc oobpost)
{
    return 0;
}

void ControlSocketInit(void)
{
}

void ControlSocketCleanUp(void)
{
}

#endif

