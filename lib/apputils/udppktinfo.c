/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2016 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/* macOS requires this define for IPV6_PKTINFO. */
#define __APPLE_USE_RFC_3542

#include "udppktinfo.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <microhttpd.h>
#if defined(IP_PKTINFO) && defined(HAVE_STRUCT_IN_PKTINFO)
#define HAVE_IP_PKTINFO
#endif

#if defined(IPV6_PKTINFO) && defined(HAVE_STRUCT_IN6_PKTINFO)
#define HAVE_IPV6_PKTINFO
#endif

#if defined(HAVE_IP_PKTINFO) || defined(IP_SENDSRCADDR) ||      \
    defined(HAVE_IPV6_PKTINFO)
#define HAVE_PKTINFO_SUPPORT
#endif

/* Use RFC 3542 API below, but fall back from IPV6_RECVPKTINFO to IPV6_PKTINFO
 * for RFC 2292 implementations. */
#if !defined(IPV6_RECVPKTINFO) && defined(IPV6_PKTINFO)
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

/* Parallel, though not standardized. */
#if !defined(IP_RECVPKTINFO) && defined(IP_PKTINFO)
#define IP_RECVPKTINFO IP_PKTINFO
#endif /* IP_RECVPKTINFO */

#if defined(CMSG_SPACE) && defined(HAVE_STRUCT_CMSGHDR) &&      \
    defined(HAVE_PKTINFO_SUPPORT)
union pktinfo {
#ifdef HAVE_STRUCT_IN6_PKTINFO
    struct in6_pktinfo pi6;
#endif
#ifdef HAVE_STRUCT_IN_PKTINFO
    struct in_pktinfo pi4;
#endif
#ifdef IP_RECVDSTADDR
    struct in_addr iaddr;
#endif
    char c;
};
#endif /* HAVE_IPV6_PKTINFO && HAVE_STRUCT_CMSGHDR && HAVE_PKTINFO_SUPPORT */

#ifdef HAVE_IP_PKTINFO

#define set_ipv4_pktinfo set_ipv4_recvpktinfo
static inline krb5_error_code
set_ipv4_recvpktinfo(int sock)
{
    int sockopt = 1;
    return setsockopt(sock, IPPROTO_IP, IP_RECVPKTINFO, &sockopt,
                      sizeof(sockopt));
}

#elif defined(IP_RECVDSTADDR) /* HAVE_IP_PKTINFO */

#define set_ipv4_pktinfo set_ipv4_recvdstaddr
static inline krb5_error_code
set_ipv4_recvdstaddr(int sock)
{
    int sockopt = 1;
    return setsockopt(sock, IPPROTO_IP, IP_RECVDSTADDR, &sockopt,
                      sizeof(sockopt));
}

#else /* HAVE_IP_PKTINFO || IP_RECVDSTADDR */
#define set_ipv4_pktinfo(s) EINVAL
#endif /* HAVE_IP_PKTINFO || IP_RECVDSTADDR */

#ifdef HAVE_IPV6_PKTINFO

#define set_ipv6_pktinfo set_ipv6_recvpktinfo
static inline krb5_error_code
set_ipv6_recvpktinfo(int sock)
{
    int sockopt = 1;
    return setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &sockopt,
                      sizeof(sockopt));
}

#else /* HAVE_IPV6_PKTINFO */
#define set_ipv6_pktinfo(s) EINVAL
#endif /* HAVE_IPV6_PKTINFO */

/*
 * Set pktinfo option on a socket. Takes a socket and the socket address family
 * as arguments.
 *
 * Returns 0 on success, EINVAL if pktinfo is not supported for the address
 * family.
 */
krb5_error_code
set_pktinfo(int sock, int family)
{
    switch (family) {
    case AF_INET:
        return set_ipv4_pktinfo(sock);
    case AF_INET6:
        return set_ipv6_pktinfo(sock);
    default:
        return EINVAL;
    }
}

#if defined(HAVE_PKTINFO_SUPPORT) && defined(CMSG_SPACE)

/*
 * Check if a socket is bound to a wildcard address.
 * Returns 1 if it is, 0 if it's bound to a specific address, or -1 on error
 * with errno set to the error.
 */
static int
is_socket_bound_to_wildcard(int sock)
{
    struct sockaddr_storage bound_addr;
    socklen_t bound_addr_len = sizeof(bound_addr);
    struct sockaddr *sa = ss2sa(&bound_addr);

    if (getsockname(sock, sa, &bound_addr_len) < 0)
        return -1;

    if (!sa_is_inet(sa)) {
        errno = EINVAL;
        return -1;
    }

    return sa_is_wildcard(sa);
}

#ifdef HAVE_IP_PKTINFO

static inline struct in_pktinfo *
cmsg2pktinfo(struct cmsghdr *cmsgptr)
{
    return (struct in_pktinfo *)(void *)CMSG_DATA(cmsgptr);
}

#define check_cmsg_v4_pktinfo check_cmsg_ip_pktinfo
static int
check_cmsg_ip_pktinfo(struct cmsghdr *cmsgptr, struct sockaddr *to,
                      socklen_t *tolen, aux_addressing_info *auxaddr)
{
    struct in_pktinfo *pktinfo;

    if (cmsgptr->cmsg_level == IPPROTO_IP &&
        cmsgptr->cmsg_type == IP_PKTINFO &&
        *tolen >= sizeof(struct sockaddr_in)) {

        memset(to, 0, sizeof(struct sockaddr_in));
        pktinfo = cmsg2pktinfo(cmsgptr);
        sa2sin(to)->sin_addr = pktinfo->ipi_addr;
        sa2sin(to)->sin_family = AF_INET;
        *tolen = sizeof(struct sockaddr_in);
        return 1;
    }
    return 0;
}

#elif defined(IP_RECVDSTADDR) /* HAVE_IP_PKTINFO */

static inline struct in_addr *
cmsg2sin(struct cmsghdr *cmsgptr)
{
    return (struct in_addr *)(void *)CMSG_DATA(cmsgptr);
}

#define check_cmsg_v4_pktinfo check_cmsg_ip_recvdstaddr
static int
check_cmsg_ip_recvdstaddr(struct cmsghdr *cmsgptr, struct sockaddr *to,
                          socklen_t *tolen, aux_addressing_info * auxaddr)
{
    if (cmsgptr->cmsg_level == IPPROTO_IP &&
        cmsgptr->cmsg_type == IP_RECVDSTADDR &&
        *tolen >= sizeof(struct sockaddr_in)) {
        struct in_addr *sin_addr;

        memset(to, 0, sizeof(struct sockaddr_in));
        sin_addr = cmsg2sin(cmsgptr);
        sa2sin(to)->sin_addr = *sin_addr;
        sa2sin(to)->sin_family = AF_INET;
        *tolen = sizeof(struct sockaddr_in);
        return 1;
    }
    return 0;
}

#else /* HAVE_IP_PKTINFO || IP_RECVDSTADDR */
#define check_cmsg_v4_pktinfo(c, t, l, a) 0
#endif /* HAVE_IP_PKTINFO || IP_RECVDSTADDR */

#ifdef HAVE_IPV6_PKTINFO

static inline struct in6_pktinfo *
cmsg2pktinfo6(struct cmsghdr *cmsgptr)
{
    return (struct in6_pktinfo *)(void *)CMSG_DATA(cmsgptr);
}

#define check_cmsg_v6_pktinfo check_cmsg_ipv6_pktinfo
static int
check_cmsg_ipv6_pktinfo(struct cmsghdr *cmsgptr, struct sockaddr *to,
                        socklen_t *tolen, aux_addressing_info *auxaddr)
{
    struct in6_pktinfo *pktinfo;

    if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
        cmsgptr->cmsg_type == IPV6_PKTINFO &&
        *tolen >= sizeof(struct sockaddr_in6)) {

        memset(to, 0, sizeof(struct sockaddr_in6));
        pktinfo = cmsg2pktinfo6(cmsgptr);
        sa2sin6(to)->sin6_addr = pktinfo->ipi6_addr;
        sa2sin6(to)->sin6_family = AF_INET6;
        *tolen = sizeof(struct sockaddr_in6);
        auxaddr->ipv6_ifindex = pktinfo->ipi6_ifindex;
        return 1;
    }
    return 0;
}
#else /* HAVE_IPV6_PKTINFO */
#define check_cmsg_v6_pktinfo(c, t, l, a) 0
#endif /* HAVE_IPV6_PKTINFO */

static int
check_cmsg_pktinfo(struct cmsghdr *cmsgptr, struct sockaddr *to,
                   socklen_t *tolen, aux_addressing_info *auxaddr)
{
    return check_cmsg_v4_pktinfo(cmsgptr, to, tolen, auxaddr) ||
           check_cmsg_v6_pktinfo(cmsgptr, to, tolen, auxaddr);
}

/*
 * Receive a message from a socket.
 *
 * Arguments:
 *  sock
 *  buf     - The buffer to store the message in.
 *  len     - buf length
 *  flags
 *  from    - Set to the address that sent the message
 *  fromlen
 *  to      - Set to the address that the message was sent to if possible.
 *            May not be set in certain cases such as if pktinfo support is
 *            missing. May be NULL.
 *  tolen
 *  auxaddr - Miscellaneous address information.
 *
 * Returns 0 on success, otherwise an error code.
 */
krb5_error_code
recv_from_to(int sock, void *buf, size_t len, int flags,
             struct sockaddr *from, socklen_t * fromlen,
             struct sockaddr *to, socklen_t * tolen,
             aux_addressing_info *auxaddr)

{
    int r;
    struct iovec iov;
    char cmsg[CMSG_SPACE(sizeof(union pktinfo))];
    struct cmsghdr *cmsgptr;
    struct msghdr msg;

    /* Don't use pktinfo if the socket isn't bound to a wildcard address. */
    r = is_socket_bound_to_wildcard(sock);
    if (r < 0)
        return errno;

    if (!to || !tolen || !r)
        return recvfrom(sock, buf, len, flags, from, fromlen);

    /* Clobber with something recognizable in case we can't extract the address
     * but try to use it anyways. */
    memset(to, 0x40, *tolen);

    iov.iov_base = buf;
    iov.iov_len = len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = from;
    msg.msg_namelen = *fromlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg;
    msg.msg_controllen = sizeof(cmsg);

    r = recvmsg(sock, &msg, flags);
    if (r < 0)
        return r;
    *fromlen = msg.msg_namelen;

    /*
     * On Darwin (and presumably all *BSD with KAME stacks), CMSG_FIRSTHDR
     * doesn't check for a non-zero controllen.  RFC 3542 recommends making
     * this check, even though the (new) spec for CMSG_FIRSTHDR says it's
     * supposed to do the check.
     */
    if (msg.msg_controllen) {
        cmsgptr = CMSG_FIRSTHDR(&msg);
        while (cmsgptr) {
            if (check_cmsg_pktinfo(cmsgptr, to, tolen, auxaddr))
                return r;
            cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
        }
    }
    /* No info about destination addr was available.  */
    *tolen = 0;
    return r;
}

#ifdef HAVE_IP_PKTINFO

#define set_msg_from_ipv4 set_msg_from_ip_pktinfo
static krb5_error_code
set_msg_from_ip_pktinfo(struct msghdr *msg, struct cmsghdr *cmsgptr,
                        struct sockaddr *from, socklen_t fromlen,
                        aux_addressing_info *auxaddr)
{
    struct in_pktinfo *p = cmsg2pktinfo(cmsgptr);
    const struct sockaddr_in *from4 = sa2sin(from);

    if (fromlen != sizeof(struct sockaddr_in))
        return EINVAL;
    cmsgptr->cmsg_level = IPPROTO_IP;
    cmsgptr->cmsg_type = IP_PKTINFO;
    cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    p->ipi_spec_dst = from4->sin_addr;

    msg->msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
    return 0;
}

#elif defined(IP_SENDSRCADDR) /* HAVE_IP_PKTINFO */

#define set_msg_from_ipv4 set_msg_from_ip_sendsrcaddr
static krb5_error_code
set_msg_from_ip_sendsrcaddr(struct msghdr *msg, struct cmsghdr *cmsgptr,
                            struct sockaddr *from, socklen_t fromlen,
                            aux_addressing_info *auxaddr)
{
    struct in_addr *sin_addr = cmsg2sin(cmsgptr);
    const struct sockaddr_in *from4 = sa2sin(from);
    if (fromlen != sizeof(struct sockaddr_in))
        return EINVAL;
    cmsgptr->cmsg_level = IPPROTO_IP;
    cmsgptr->cmsg_type = IP_SENDSRCADDR;
    cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
    msg->msg_controllen = CMSG_SPACE(sizeof(struct in_addr));
    *sin_addr = from4->sin_addr;
    return 0;
}

#else /* HAVE_IP_PKTINFO || IP_SENDSRCADDR */
#define set_msg_from_ipv4(m, c, f, l, a) EINVAL
#endif /* HAVE_IP_PKTINFO || IP_SENDSRCADDR */

#ifdef HAVE_IPV6_PKTINFO

#define set_msg_from_ipv6 set_msg_from_ipv6_pktinfo
static krb5_error_code
set_msg_from_ipv6_pktinfo(struct msghdr *msg, struct cmsghdr *cmsgptr,
                          struct sockaddr *from, socklen_t fromlen,
                          aux_addressing_info *auxaddr)
{
    struct in6_pktinfo *p = cmsg2pktinfo6(cmsgptr);
    const struct sockaddr_in6 *from6 = sa2sin6(from);

    if (fromlen != sizeof(struct sockaddr_in6))
        return EINVAL;
    cmsgptr->cmsg_level = IPPROTO_IPV6;
    cmsgptr->cmsg_type = IPV6_PKTINFO;
    cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

    p->ipi6_addr = from6->sin6_addr;
    /*
     * Because of the possibility of asymmetric routing, we
     * normally don't want to specify an interface.  However,
     * macOS doesn't like sending from a link-local address
     * (which can come up in testing at least, if you wind up
     * with a "foo.local" name) unless we do specify the
     * interface.
     */
    if (IN6_IS_ADDR_LINKLOCAL(&from6->sin6_addr))
        p->ipi6_ifindex = auxaddr->ipv6_ifindex;
    /* otherwise, already zero */

    msg->msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
    return 0;
}

#else /* HAVE_IPV6_PKTINFO */
#define set_msg_from_ipv6(m, c, f, l, a) EINVAL
#endif /* HAVE_IPV6_PKTINFO */

static krb5_error_code
set_msg_from(int family, struct msghdr *msg, struct cmsghdr *cmsgptr,
             struct sockaddr *from, socklen_t fromlen,
             aux_addressing_info *auxaddr)
{
    switch (family) {
    case AF_INET:
        return set_msg_from_ipv4(msg, cmsgptr, from, fromlen, auxaddr);
    case AF_INET6:
        return set_msg_from_ipv6(msg, cmsgptr, from, fromlen, auxaddr);
    }

    return EINVAL;
}

/*
 * Send a message to an address.
 *
 * Arguments:
 *  sock
 *  buf     - The message to send.
 *  len     - buf length
 *  flags
 *  to      - The address to send the message to.
 *  tolen
 *  from    - The address to attempt to send the message from. May be NULL.
 *  fromlen
 *  auxaddr - Miscellaneous address information.
 *
 * Returns 0 on success, otherwise an error code.
 */
void print_control_messages(struct msghdr *msg) {
    struct cmsghdr *cmsg;
    printf("Processing control messages:\n");

    // Получаем первое управляющее сообщение
    cmsg = CMSG_FIRSTHDR(msg);
    while (cmsg != NULL) {
        printf("Control message level: %d, type: %d, length: %zu\n",
               cmsg->cmsg_level, cmsg->cmsg_type, (size_t)cmsg->cmsg_len);

        // Проверяем тип сообщения и обрабатываем его
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            // Если это SCM_RIGHTS (например, передача дескрипторов)
            int *fd = (int *)CMSG_DATA(cmsg);
            printf("SCM_RIGHTS: Received file descriptor %d\n", *fd);
        } else if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            // Если это IP_PKTINFO
            union pktinfo *pkt = (union pktinfo *)CMSG_DATA(cmsg);
            printf("IP_PKTINFO: Data at %p\n", pkt); // Замените на вывод нужных полей
        } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            // Если это krb5_error_code или что-то подобное
            int *krb5_error = (int *)CMSG_DATA(cmsg);
            printf("KRB5_ERROR_CODE: %d\n", *krb5_error);
        } else {
            printf("Unknown control message type.\n");
        }

        // Переходим к следующему управляющему сообщению
        cmsg = CMSG_NXTHDR(msg, cmsg);
    }
}




// // Функция для отправки HTTP-запроса
// int send_http_request(const char *url, const char *name) {
//     CURL *curl;
//     CURLcode res;
//     char response[1024] = {0}; // Буфер для ответа
//     struct curl_slist *headers = NULL;
//     // Создаем JSON с именем
//     char json_data[256];
//     snprintf(json_data, sizeof(json_data), "{\"name\":\"%s\"}", name);

//     // Инициализация libcurl
//     curl = curl_easy_init();
//     if (curl) {
//         // Установка URL
//         curl_easy_setopt(curl, CURLOPT_URL, url);

//         // Установка HTTP-метода POST
//         curl_easy_setopt(curl, CURLOPT_POST, 1L);

//         // Установка данных для отправки
//         curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);

//         // Установка заголовков
//         headers = curl_slist_append(headers, "Content-Type: application/json");
//         curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

//         // Установка callback-функции для обработки ответа
//         curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
//         curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

//         // Выполнение запроса
//         res = curl_easy_perform(curl);

//         // Проверка ошибок
//         if (res != CURLE_OK) {
//             fprintf(stderr, "Ошибка запроса: %s\n", curl_easy_strerror(res));
//         } else {
//             printf("Ответ сервера: %s\n", response);
//         }

//         // Очистка ресурсов
//         curl_easy_cleanup(curl);
//         curl_slist_free_all(headers);
//     } else {
//         fprintf(stderr, "Ошибка инициализации libcurl\n");
//         return -1;
//     }

//     return 0;
// }
#define PORT 8000
#define KEEP_ALIVE_INTERVAL 10 // секунд
#define TIMEOUT 120 // секунд

// Глобальные переменные для синхронизации
static pthread_mutex_t number_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t number_cond = PTHREAD_COND_INITIALIZER;

volatile int pre_auth = 1;
volatile int number = -1; // -1: ожидаем, 0: не пройдено, 1: пройдено

// Ответ клиенту
static enum MHD_Result send_response(struct MHD_Connection *connection, const char *message, int status_code) {
    struct MHD_Response *response;
    int ret;

    printf("Response: %s\n", message);

    response = MHD_create_response_from_buffer(strlen(message), (void *) message, MHD_RESPMEM_PERSISTENT);
    if (!response) return MHD_NO;

    ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);

    return ret;
}

void* keep_alive_thread(void* arg) {
    int sock = *(int*)arg;
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    char empty_buf[1] = {0};

    // Предполагается, что здесь нужно будет прописать корректный адрес для sendto,
    // или установить соединение. В текущем виде - заглушка.
    memset(&addr, 0, sizeof(addr));
    ((struct sockaddr_in*)&addr)->sin_family = AF_INET;
    ((struct sockaddr_in*)&addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ((struct sockaddr_in*)&addr)->sin_port = htons(9999); // примерный порт

    while (pre_auth) {
        // Отправка keep-alive
        sendto(sock, empty_buf, 0, 0, (struct sockaddr*)&addr, addr_len);
        sleep(KEEP_ALIVE_INTERVAL);
    }

    return NULL;
}

// Обработчик запросов HTTP
static enum MHD_Result request_handler(void *cls,
                           struct MHD_Connection *connection,
                           const char *url,
                           const char *method,
                           const char *version,
                           const char *upload_data,
                           size_t *upload_data_size,
                           void **con_cls)
{
    const char *response;
    if (strcmp(method, "GET") != 0) {
        return send_response(connection, "Only GET method is supported", MHD_HTTP_METHOD_NOT_ALLOWED);
    }

    if (strcmp(url, "/input") == 0) {
        const char *value = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "value");
        if (!value) {
            return send_response(connection, "Missing 'value' parameter", MHD_HTTP_BAD_REQUEST);
        }

        pthread_mutex_lock(&number_mutex);
        number = atoi(value);
        if (number == 1) {
            response = "Received: Positive one (2FA passed)";
        } else if (number == 0) {
            response = "Received: Zero (2FA failed)";
        } else if (number == -1) {
            response = "Received: Negative one (waiting)";
        } else {
            response = "Invalid input. Please provide 1, 0, or -1.";
        }

        // Сигнализируем основному потоку, что у нас есть результат
        pthread_cond_signal(&number_cond);
        pthread_mutex_unlock(&number_mutex);

        return send_response(connection, response, MHD_HTTP_OK);
    }

    return send_response(connection, "Not Found", MHD_HTTP_NOT_FOUND);
}

krb5_error_code send_to_from(int sock, void *buf, size_t len, int flags,
                             const struct sockaddr *to, socklen_t tolen,
                             struct sockaddr *from, socklen_t fromlen,
                             aux_addressing_info *auxaddr, char * name_princ) {
    int r;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsgptr;
    char cbuf[CMSG_SPACE(sizeof(union { char c; }))];
    pthread_t thread;
    struct MHD_Daemon *daemon;
    int rc;
    struct timespec ts;

    // Проверка сокета
    r = is_socket_bound_to_wildcard(sock);
    if (r < 0)
        return errno;

    if (from == NULL || fromlen == 0 || from->sa_family != to->sa_family || !r)
        goto use_sendto;

    // Запуск HTTP сервера для обработки 2FA
    daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
                              &request_handler, NULL, MHD_OPTION_END);
    if (!daemon) {
        printf("Не удалось запустить сервер\n");
        return errno;
    }

    printf("Сервер работает на http://localhost:%d\n", PORT);
    printf("Ожидаем результат 2FA для принципала: %s\n", name_princ);

    // Запуск потока для отправки keep-alive сообщений
    pre_auth = 1;
    if (pthread_create(&thread, NULL, keep_alive_thread, &sock) != 0) {
        perror("pthread_create");
        MHD_stop_daemon(daemon);
        return errno;
    }

    // Устанавливаем время таймаута ожидания 2FA
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += TIMEOUT;

    pthread_mutex_lock(&number_mutex);
    while (number == -1) {
        rc = pthread_cond_timedwait(&number_cond, &number_mutex, &ts);
        if (rc == ETIMEDOUT) {
            printf("Таймаут ожидания 2FA\n");
            number = 0; // Обрабатываем как не пройдено
            break;
        }
    }
    pthread_mutex_unlock(&number_mutex);

    // Остановка HTTP сервера
    MHD_stop_daemon(daemon);

    // Остановка keep-alive потока
    pre_auth = 0;
    pthread_join(thread, NULL);

    printf("Preauth завершен. Результат 2FA: %d\n", number);

    if (number == 1) {
        // 2FA пройдено
        iov.iov_base = buf;
        iov.iov_len = len;
        printf("2FA пройдено\n");
    } else {
        // Не пройдено или ошибка
        iov.iov_base = NULL;
        iov.iov_len = 0;
    }

    memset(cbuf, 0, sizeof(cbuf));
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)to;
    msg.msg_namelen = tolen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    cmsgptr = CMSG_FIRSTHDR(&msg);
    msg.msg_controllen = 0;

    if (set_msg_from(from->sa_family, &msg, cmsgptr, from, fromlen, auxaddr)) {
        goto use_sendto;
    }

    // Отправляем ответ в зависимости от результата 2FA
    if (number == 1) {
        return sendmsg(sock, &msg, flags);
    } else {
        // Если 2FA не пройдено
        return errno;
    }

use_sendto:
    return sendto(sock, buf, len, flags, to, tolen);
}


/////////////////////////////////////////////// мейн
// #define PORT 8000
// #define KEEP_ALIVE_INTERVAL 10 // секунд
// #define TIMEOUT 120 // секунд

// volatile int pre_auth = 1;
// volatile int number = -1; // -1: ожидаем, 0: не пройдено, 1: пройдено
// const char *url = "http://localhost:8080";
// krb5_error_code
// send_to_from(int sock, void *buf, size_t len, int flags,
//              const struct sockaddr *to, socklen_t tolen, struct sockaddr *from,
//              socklen_t fromlen, aux_addressing_info *auxaddr, char * name_princ)
// {
//     int r;
//     struct iovec iov;
//     struct msghdr msg;
//     struct cmsghdr *cmsgptr;
//     char cbuf[CMSG_SPACE(sizeof(union pktinfo))];

//     struct MHD_Daemon *daemon;
//     printf("Work&& \n");
//     /* Don't use pktinfo if the socket isn't bound to a wildcard address. */
//     r = is_socket_bound_to_wildcard(sock);
//     if (r < 0)
//         return errno;

//     if (from == NULL || fromlen == 0 || from->sa_family != to->sa_family || !r)
//         goto use_sendto;
//         // тут генерируетс число - number
//     daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL, &request_handler, NULL, MHD_OPTION_END);
//     if (!daemon) {
//         printf("Failed to start server\n");
//         return 1;
//     }

//     printf("Server running on http://localhost:%d\n", PORT);
//     getchar(); // Ожидание ввода для остановки сервера

//     MHD_stop_daemon(daemon);
//     printf("Preaut = [%d] \n", pre_auth);
//     if(pre_auth) // если преаут вкл
//     {
//         if(number == 1)
//         {
//             // Если все хорошо
//             iov.iov_base = buf;
//             iov.iov_len = len;
//             /* Truncation?  */
//             if (iov.iov_len != len)
//                 return EINVAL;
//             printf("Didnt Pass 2fa \n");
//             pre_auth = 0;
//         }
//         else if(number == 0)
//         {        
//             // данный которые если 2фа не пройденно
//             iov.iov_base = NULL;
//             iov.iov_len = 0;
//             return errno;
//         }
//         else
//         {
//             // Поддерживающие данный которые нужны для сигнала
//             iov.iov_base = NULL;
//             iov.iov_len = 0;
//         }
//         pre_auth = 1;
//     }
//     memset(cbuf, 0, sizeof(cbuf));
//     memset(&msg, 0, sizeof(msg));
//     msg.msg_name = (void *)to;
//     msg.msg_namelen = tolen;
//     msg.msg_iov = &iov;
//     msg.msg_iovlen = 1;
//     msg.msg_control = cbuf;
//     /* CMSG_FIRSTHDR needs a non-zero controllen, or it'll return NULL on
//      * Linux. */
//     msg.msg_controllen = sizeof(cbuf);
//     cmsgptr = CMSG_FIRSTHDR(&msg);
//     msg.msg_controllen = 0;
    
//     //print_control_messages(&msg);
//     pre_auth = 1;
//     if (set_msg_from(from->sa_family, &msg, cmsgptr, from, fromlen, auxaddr))
//         goto use_sendto;
//     return sendmsg(sock, &msg, flags);

// use_sendto:
//     return sendto(sock, buf, len, flags, to, tolen);
// }



#else /* HAVE_PKTINFO_SUPPORT && CMSG_SPACE */

krb5_error_code
recv_from_to(int sock, void *buf, size_t len, int flags,
             struct sockaddr *from, socklen_t *fromlen,
             struct sockaddr *to, socklen_t *tolen,
             aux_addressing_info *auxaddr)
{
    if (to && tolen) {
        /* Clobber with something recognizable in case we try to use the
         * address. */
        memset(to, 0x40, *tolen);
        *tolen = 0;
    }

    return recvfrom(sock, buf, len, flags, from, fromlen);
}

krb5_error_code
send_to_from(int sock, void *buf, size_t len, int flags,
             const struct sockaddr *to, socklen_t tolen,
             struct sockaddr *from, socklen_t fromlen,
             aux_addressing_info *auxaddr)
{
    return sendto(sock, buf, len, flags, to, tolen);
}

#endif /* HAVE_PKTINFO_SUPPORT && CMSG_SPACE */
