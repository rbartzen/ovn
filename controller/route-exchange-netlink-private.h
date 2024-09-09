/*
 * Copyright (c) 2024 Canonical, Ltd.
 * Copyright (c) 2011, 2012, 2013, 2014, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ROUTE_EXCHANGE_NETLINK_PRIVATE_H
#define ROUTE_EXCHANGE_NETLINK_PRIVATE_H 1

#include <fcntl.h>
#include <unistd.h>
#include "ovs/lib/util.h"

/*
 * NOTE(fnordahl): The below code is stolen directly from OVS lib/route-table.c
 * with the addition of inlining of function definitions for practical reasons
 * and modifications:
 *
 * struct route_data:
 *
 * - Add rta_table_id.
 * - Add plen.
 * - Add rtm_protocol
 *
 * route_table_parse():
 *
 * - Consider non-standard routing tables and store the table_id.
 *
 * route_table_dump_one_table():
 *
 * - Use uint32_t for table id and pass it to kernel using thee RTA_TABLE
 *   attribute to allow use of table IDs greater than 256.
 * - Use callback with argument instead of hard coded call to static function
 *   route_table_handle_msg().
 *
 * Ideally we would upstream those changes along with export of interesting
 * data structures and functions to OVS, but in the interest of time we vendor
 * the code here for now.
 *
 * Additionally all functions have been adapted to support multiple network
 * namespaces. This was the resion to include:
 * - nl_dump_start
 * - nl_transact
 * - nl_pool_alloc/release
 * All of these got a nl_ns prefix to differenciate them.
 *
 * The following functions are vendored just because they are static.
 *
 * BEGIN VENDORED CODE FROM OVS lib/route-table.c
 */
struct route_data {
    /* Copied from struct rtmsg. */
    unsigned char rtm_dst_len;
    bool local;

    /* Extracted from Netlink attributes. */
    struct in6_addr rta_dst; /* 0 if missing. */
    struct in6_addr rta_prefsrc; /* 0 if missing. */
    struct in6_addr rta_gw;
    char ifname[IFNAMSIZ]; /* Interface name. */
    uint32_t mark;
    uint32_t rta_table_id; /* 0 if missing. */
    unsigned char plen;
    unsigned char rtm_protocol;
};

/* A digested version of a route message sent down by the kernel to indicate
 * that a route has changed. */
struct route_table_msg {
    bool relevant;        /* Should this message be processed? */
    int nlmsg_type;       /* e.g. RTM_NEWROUTE, RTM_DELROUTE. */
    struct route_data rd; /* Data parsed from this message. */
};
/* temp end of vendored code of lib/route-table.c */

/* now some vendored code from netlink-socket.c */

/* Linux header file confusion causes this to be undefined. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

struct nl_sock {
#ifdef _WIN32
    HANDLE handle;
    OVERLAPPED overlapped;
    DWORD read_ioctl;
#else
    int fd;
#endif
    uint32_t next_seq;
    uint32_t pid;
    int protocol;
    unsigned int rcvbuf;        /* Receive buffer size (SO_RCVBUF). */
};

static void
nl_sock_record_errors__(struct nl_transaction **transactions, size_t n,
                        int error)
{
    size_t i;

    for (i = 0; i < n; i++) {
        struct nl_transaction *txn = transactions[i];

        txn->error = error;
        if (txn->reply) {
            ofpbuf_clear(txn->reply);
        }
    }
}

static uint32_t
nl_sock_allocate_seq(struct nl_sock *sock, unsigned int n)
{
    uint32_t seq = sock->next_seq;

    sock->next_seq += n;

    /* Make it impossible for the next request for sequence numbers to wrap
     * around to 0.  Start over with 1 to avoid ever using a sequence number of
     * 0, because the kernel uses sequence number 0 for notifications. */
    if (sock->next_seq >= UINT32_MAX / 2) {
        sock->next_seq = 1;
    }

    return seq;
}

static int
nl_sock_send__(struct nl_sock *sock, const struct ofpbuf *msg,
               uint32_t nlmsg_seq, bool wait)
{
    struct nlmsghdr *nlmsg = nl_msg_nlmsghdr(msg);
    int error;

    nlmsg->nlmsg_len = msg->size;
    nlmsg->nlmsg_seq = nlmsg_seq;
    nlmsg->nlmsg_pid = sock->pid;
    do {
        int retval;
#ifdef _WIN32
        DWORD bytes;

        if (!DeviceIoControl(sock->handle, OVS_IOCTL_WRITE,
                             msg->data, msg->size, NULL, 0,
                             &bytes, NULL)) {
            lost_communication(GetLastError());
            retval = -1;
            /* XXX: Map to a more appropriate error based on GetLastError(). */
            errno = EINVAL;
            VLOG_DBG_RL(&rl, "fatal driver failure in write: %s",
                        ovs_lasterror_to_string());
        } else {
            retval = msg->size;
        }
#else
        retval = send(sock->fd, msg->data, msg->size,
                      wait ? 0 : MSG_DONTWAIT);
#endif
        error = retval < 0 ? errno : 0;
    } while (error == EINTR);
    //log_nlmsg(__func__, error, msg->data, msg->size, sock->protocol);
    if (!error) {
        //COVERAGE_INC(netlink_sent);
    }
    return error;
}

static int
nl_sock_recv__(struct nl_sock *sock, struct ofpbuf *buf, int *nsid, bool wait)
{
    /* We can't accurately predict the size of the data to be received.  The
     * caller is supposed to have allocated enough space in 'buf' to handle the
     * "typical" case.  To handle exceptions, we make available enough space in
     * 'tail' to allow Netlink messages to be up to 64 kB long (a reasonable
     * figure since that's the maximum length of a Netlink attribute). */
    struct nlmsghdr *nlmsghdr;
    uint8_t tail[65536];
    struct iovec iov[2];
    struct msghdr msg;
    uint8_t msgctrl[64];
    struct cmsghdr *cmsg;
    ssize_t retval;
    int *ptr;
    int error;

    ovs_assert(buf->allocated >= sizeof *nlmsghdr);
    ofpbuf_clear(buf);

    iov[0].iov_base = buf->base;
    iov[0].iov_len = buf->allocated;
    iov[1].iov_base = tail;
    iov[1].iov_len = sizeof tail;

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_control = msgctrl;
    msg.msg_controllen = sizeof msgctrl;

    /* Receive a Netlink message from the kernel.
     *
     * This works around a kernel bug in which the kernel returns an error code
     * as if it were the number of bytes read.  It doesn't actually modify
     * anything in the receive buffer in that case, so we can initialize the
     * Netlink header with an impossible message length and then, upon success,
     * check whether it changed. */
    nlmsghdr = buf->base;
    do {
        nlmsghdr->nlmsg_len = UINT32_MAX;
#ifdef _WIN32
        DWORD bytes;
        if (!DeviceIoControl(sock->handle, sock->read_ioctl,
                             NULL, 0, tail, sizeof tail, &bytes, NULL)) {
            lost_communication(GetLastError());
            VLOG_DBG_RL(&rl, "fatal driver failure in transact: %s",
                        ovs_lasterror_to_string());
            retval = -1;
            /* XXX: Map to a more appropriate error. */
            errno = EINVAL;
        } else {
            retval = bytes;
            if (retval == 0) {
                retval = -1;
                errno = EAGAIN;
            } else {
                if (retval >= buf->allocated) {
                    ofpbuf_reinit(buf, retval);
                    nlmsghdr = buf->base;
                    nlmsghdr->nlmsg_len = UINT32_MAX;
                }
                memcpy(buf->data, tail, retval);
                buf->size = retval;
            }
        }
#else
        retval = recvmsg(sock->fd, &msg, wait ? 0 : MSG_DONTWAIT);
#endif
        error = (retval < 0 ? errno
                 : retval == 0 ? ECONNRESET /* not possible? */
                 : nlmsghdr->nlmsg_len != UINT32_MAX ? 0
                 : retval);
    } while (error == EINTR);
    if (error) {
        if (error == ENOBUFS) {
            /* Socket receive buffer overflow dropped one or more messages that
             * the kernel tried to send to us. */
            //COVERAGE_INC(netlink_overflow);
        }
        return error;
    }

    if (msg.msg_flags & MSG_TRUNC) {
        VLOG_ERR_RL(&rl, "truncated message (longer than %"PRIuSIZE" bytes)",
                    sizeof tail);
        return E2BIG;
    }

    if (retval < sizeof *nlmsghdr
        || nlmsghdr->nlmsg_len < sizeof *nlmsghdr
        || nlmsghdr->nlmsg_len > retval) {
        VLOG_ERR_RL(&rl, "received invalid nlmsg (%"PRIuSIZE" bytes < %"PRIuSIZE")",
                    retval, sizeof *nlmsghdr);
        return EPROTO;
    }
#ifndef _WIN32
    buf->size = MIN(retval, buf->allocated);
    if (retval > buf->allocated) {
        //COVERAGE_INC(netlink_recv_jumbo);
        ofpbuf_put(buf, tail, retval - buf->allocated);
    }
#endif

    if (nsid) {
        /* The network namespace id from which the message was sent comes
         * as ancillary data. For older kernels, this data is either not
         * available or it might be -1, so it falls back to local network
         * namespace (no id). Latest kernels return a valid ID only if
         * available or nothing. */
        //netnsid_set_local(nsid);
        *nsid = -1;
#ifndef _WIN32
        cmsg = CMSG_FIRSTHDR(&msg);
        while (cmsg != NULL) {
            if (cmsg->cmsg_level == SOL_NETLINK
                && cmsg->cmsg_type == NETLINK_LISTEN_ALL_NSID) {
                ptr = ALIGNED_CAST(int *, CMSG_DATA(cmsg));
                *nsid = *ptr;
            }
            if (cmsg->cmsg_level == SOL_SOCKET
                && cmsg->cmsg_type == SCM_RIGHTS) {
                /* This is unexpected and unwanted, close all fds */
                int nfds;
                int i;
                nfds = (cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr)))
                       / sizeof(int);
                ptr = ALIGNED_CAST(int *, CMSG_DATA(cmsg));
                for (i = 0; i < nfds; i++) {
                    VLOG_ERR_RL(&rl, "closing unexpected received fd (%d).",
                                ptr[i]);
                    close(ptr[i]);
                }
            }

            cmsg = CMSG_NXTHDR(&msg, cmsg);
        }
#endif
    }

    //log_nlmsg(__func__, 0, buf->data, buf->size, sock->protocol);
    //COVERAGE_INC(netlink_received);

    return 0;
}
#define MAX_IOVS 128
static int max_iovs = MAX_IOVS;

static int
nl_sock_transact_multiple__(struct nl_sock *sock,
                            struct nl_transaction **transactions, size_t n,
                            size_t *done)
{
    uint64_t tmp_reply_stub[1024 / 8];
    struct nl_transaction tmp_txn;
    struct ofpbuf tmp_reply;

    uint32_t base_seq;
    struct iovec iovs[MAX_IOVS];
    struct msghdr msg;
    int error;
    int i;

    base_seq = nl_sock_allocate_seq(sock, n);
    *done = 0;
    for (i = 0; i < n; i++) {
        struct nl_transaction *txn = transactions[i];
        struct nlmsghdr *nlmsg = nl_msg_nlmsghdr(txn->request);

        nlmsg->nlmsg_len = txn->request->size;
        nlmsg->nlmsg_seq = base_seq + i;
        nlmsg->nlmsg_pid = sock->pid;

        iovs[i].iov_base = txn->request->data;
        iovs[i].iov_len = txn->request->size;
    }

#ifndef _WIN32
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iovs;
    msg.msg_iovlen = n;
    do {
        error = sendmsg(sock->fd, &msg, 0) < 0 ? errno : 0;
    } while (error == EINTR);

    /*for (i = 0; i < n; i++) {
        struct nl_transaction *txn = transactions[i];

        log_nlmsg(__func__, error, txn->request->data,
                  txn->request->size, sock->protocol);
    }
    if (!error) {
        COVERAGE_ADD(netlink_sent, n);
    }*/

    if (error) {
        return error;
    }

    ofpbuf_use_stub(&tmp_reply, tmp_reply_stub, sizeof tmp_reply_stub);
    tmp_txn.request = NULL;
    tmp_txn.reply = &tmp_reply;
    tmp_txn.error = 0;
    while (n > 0) {
        struct nl_transaction *buf_txn, *txn;
        uint32_t seq;

        /* Find a transaction whose buffer we can use for receiving a reply.
         * If no such transaction is left, use tmp_txn. */
        buf_txn = &tmp_txn;
        for (i = 0; i < n; i++) {
            if (transactions[i]->reply) {
                buf_txn = transactions[i];
                break;
            }
        }

        /* Receive a reply. */
        error = nl_sock_recv__(sock, buf_txn->reply, NULL, false);
        if (error) {
            if (error == EAGAIN) {
                nl_sock_record_errors__(transactions, n, 0);
                *done += n;
                error = 0;
            }
            break;
        }

        /* Match the reply up with a transaction. */
        seq = nl_msg_nlmsghdr(buf_txn->reply)->nlmsg_seq;
        if (seq < base_seq || seq >= base_seq + n) {
            VLOG_DBG_RL(&rl, "ignoring unexpected seq %#"PRIx32, seq);
            continue;
        }
        i = seq - base_seq;
        txn = transactions[i];

        const char *err_msg = NULL;
        /* Fill in the results for 'txn'. */
        if (nl_msg_nlmsgerr(buf_txn->reply, &txn->error, &err_msg)) {
            if (txn->error) {
                VLOG_DBG_RL(&rl, "received NAK error=%d - %s",
                            txn->error,
                            err_msg ? err_msg : ovs_strerror(txn->error));
            }
            if (txn->reply) {
                ofpbuf_clear(txn->reply);
            }
        } else {
            txn->error = 0;
            if (txn->reply && txn != buf_txn) {
                /* Swap buffers. */
                struct ofpbuf *reply = buf_txn->reply;
                buf_txn->reply = txn->reply;
                txn->reply = reply;
            }
        }

        /* Fill in the results for transactions before 'txn'.  (We have to do
         * this after the results for 'txn' itself because of the buffer swap
         * above.) */
        nl_sock_record_errors__(transactions, i, 0);

        /* Advance. */
        *done += i + 1;
        transactions += i + 1;
        n -= i + 1;
        base_seq += i + 1;
    }
    ofpbuf_uninit(&tmp_reply);
#else
    error = 0;
    uint8_t reply_buf[65536];
    for (i = 0; i < n; i++) {
        DWORD reply_len;
        bool ret;
        struct nl_transaction *txn = transactions[i];
        struct nlmsghdr *request_nlmsg, *reply_nlmsg;

        ret = DeviceIoControl(sock->handle, OVS_IOCTL_TRANSACT,
                              txn->request->data,
                              txn->request->size,
                              reply_buf, sizeof reply_buf,
                              &reply_len, NULL);

        if (ret && reply_len == 0) {
            /*
             * The current transaction did not produce any data to read and that
             * is not an error as such. Continue with the remainder of the
             * transactions.
             */
            txn->error = 0;
            if (txn->reply) {
                ofpbuf_clear(txn->reply);
            }
        } else if (!ret) {
            /* XXX: Map to a more appropriate error. */
            lost_communication(GetLastError());
            error = EINVAL;
            VLOG_DBG_RL(&rl, "fatal driver failure: %s",
                ovs_lasterror_to_string());
            break;
        }

        if (reply_len != 0) {
            request_nlmsg = nl_msg_nlmsghdr(txn->request);

            if (reply_len < sizeof *reply_nlmsg) {
                nl_sock_record_errors__(transactions, n, 0);
                VLOG_DBG_RL(&rl, "insufficient length of reply %#"PRIu32
                    " for seq: %#"PRIx32, reply_len, request_nlmsg->nlmsg_seq);
                break;
            }

            /* Validate the sequence number in the reply. */
            reply_nlmsg = (struct nlmsghdr *)reply_buf;

            if (request_nlmsg->nlmsg_seq != reply_nlmsg->nlmsg_seq) {
                ovs_assert(request_nlmsg->nlmsg_seq == reply_nlmsg->nlmsg_seq);
                VLOG_DBG_RL(&rl, "mismatched seq request %#"PRIx32
                    ", reply %#"PRIx32, request_nlmsg->nlmsg_seq,
                    reply_nlmsg->nlmsg_seq);
                break;
            }

            /* Handle errors embedded within the netlink message. */
            ofpbuf_use_stub(&tmp_reply, reply_buf, sizeof reply_buf);
            tmp_reply.size = sizeof reply_buf;
            if (nl_msg_nlmsgerr(&tmp_reply, &txn->error, NULL)) {
                if (txn->reply) {
                    ofpbuf_clear(txn->reply);
                }
                if (txn->error) {
                    VLOG_DBG_RL(&rl, "received NAK error=%d (%s)",
                                error, ovs_strerror(txn->error));
                }
            } else {
                txn->error = 0;
                if (txn->reply) {
                    /* Copy the reply to the buffer specified by the caller. */
                    if (reply_len > txn->reply->allocated) {
                        ofpbuf_reinit(txn->reply, reply_len);
                    }
                    memcpy(txn->reply->data, reply_buf, reply_len);
                    txn->reply->size = reply_len;
                }
            }
            ofpbuf_uninit(&tmp_reply);
        }

        /* Count the number of successful transactions. */
        (*done)++;

    }

    if (!error) {
        COVERAGE_ADD(netlink_sent, n);
    }
#endif

    return error;
}

static void
nl_sock_transact_multiple(struct nl_sock *sock,
                          struct nl_transaction **transactions, size_t n)
{
    int max_batch_count;
    int error;

    if (!n) {
        return;
    }

    /* In theory, every request could have a 64 kB reply.  But the default and
     * maximum socket rcvbuf size with typical Dom0 memory sizes both tend to
     * be a bit below 128 kB, so that would only allow a single message in a
     * "batch".  So we assume that replies average (at most) 4 kB, which allows
     * a good deal of batching.
     *
     * In practice, most of the requests that we batch either have no reply at
     * all or a brief reply. */
    max_batch_count = MAX(sock->rcvbuf / 4096, 1);
    max_batch_count = MIN(max_batch_count, max_iovs);

    while (n > 0) {
        size_t count, bytes;
        size_t done;

        /* Batch up to 'max_batch_count' transactions.  But cap it at about a
         * page of requests total because big skbuffs are expensive to
         * allocate in the kernel.  */
#if defined(PAGESIZE)
        enum { MAX_BATCH_BYTES = MAX(1, PAGESIZE - 512) };
#else
        enum { MAX_BATCH_BYTES = 4096 - 512 };
#endif
        bytes = transactions[0]->request->size;
        for (count = 1; count < n && count < max_batch_count; count++) {
            if (bytes + transactions[count]->request->size > MAX_BATCH_BYTES) {
                break;
            }
            bytes += transactions[count]->request->size;
        }

        error = nl_sock_transact_multiple__(sock, transactions, count, &done);
        transactions += done;
        n -= done;

        if (error == ENOBUFS) {
            VLOG_DBG_RL(&rl, "receive buffer overflow, resending request");
        } else if (error) {
            VLOG_ERR_RL(&rl, "transaction error (%s)", ovs_strerror(error));
            nl_sock_record_errors__(transactions, n, error);
            if (error != EAGAIN) {
                /* A fatal error has occurred.  Abort the rest of
                 * transactions. */
                break;
            }
        }
    }
}

static int
nl_sock_transact(struct nl_sock *sock, const struct ofpbuf *request,
                 struct ofpbuf **replyp)
{
    struct nl_transaction *transactionp;
    struct nl_transaction transaction;

    transaction.request = CONST_CAST(struct ofpbuf *, request);
    transaction.reply = replyp ? ofpbuf_new(1024) : NULL;
    transactionp = &transaction;

    nl_sock_transact_multiple(sock, &transactionp, 1);

    if (replyp) {
        if (transaction.error) {
            ofpbuf_delete(transaction.reply);
            *replyp = NULL;
        } else {
            *replyp = transaction.reply;
        }
    }

    return transaction.error;
}

/* this function is completely different than originally as it does not do any
 * kind of socket caching. This is just for testing.
 * Also it is partially stolen from the frr code of netns_linux.c
 * */
static int
nl_ns_pool_alloc(const char *netns, int protocol, struct nl_sock **sockp)
{
    int ret, ns_fd, ns_default_fd, err;
    if (netns) {
        ns_default_fd = open("/proc/self/ns/net", O_RDONLY);
        if (ns_default_fd < 0) {
            printf("something wrong when opening self net fd, %d\n", errno);
        }
        char *netns_path = xasprintf("/var/run/netns/%s", netns);
        ns_fd = open(netns_path, O_RDONLY);
        if (ns_fd < 0) {
            printf("something wrong when opening other net fd, %d\n", errno);
        }
        err = setns(ns_fd, CLONE_NEWNET);
        if (err < 0) {
            printf("something wrong during setns to target, %d\n", errno);
        }
        close(ns_fd);
    }
    ret = nl_sock_create(protocol, sockp);
    if (netns) {
        err = setns(ns_default_fd, CLONE_NEWNET);
        if (err < 0) {
            printf("something wrong during setns to home, %d\n", errno);
        }
        close(ns_default_fd);
    }
    return ret;
}

/* as we dont cache we just free it here */
static void
nl_ns_pool_release(struct nl_sock *sock)
{
    nl_sock_destroy(sock);
}


static void
nl_ns_dump_start(const char *netns, struct nl_dump *dump, int protocol, const struct ofpbuf *request)
{
    nl_msg_nlmsghdr(request)->nlmsg_flags |= NLM_F_DUMP | NLM_F_ACK;

    ovs_mutex_init(&dump->mutex);
    ovs_mutex_lock(&dump->mutex);
    dump->status = nl_ns_pool_alloc(netns, protocol, &dump->sock);
    if (!dump->status) {
        dump->status = nl_sock_send__(dump->sock, request,
                                      nl_sock_allocate_seq(dump->sock, 1),
                                      true);
    }
    dump->nl_seq = nl_msg_nlmsghdr(request)->nlmsg_seq;
    ovs_mutex_unlock(&dump->mutex);
}

static int
nl_ns_transact(const char *netns, int protocol, const struct ofpbuf *request,
            struct ofpbuf **replyp)
{
    struct nl_sock *sock;
    int error;

    error = nl_ns_pool_alloc(netns, protocol, &sock);
    if (error) {
        if (replyp) {
            *replyp = NULL;
        }
        return error;
    }

    error = nl_sock_transact(sock, request, replyp);

    nl_ns_pool_release(sock);
    return error;
}
/* end of vendored code from netlink-socket.c */

/* now some more vendored code of lib/route-table.c */
/* Return RTNLGRP_IPV4_ROUTE or RTNLGRP_IPV6_ROUTE on success, 0 on parse
 * error. */
static inline int
route_table_parse(struct ofpbuf *buf, struct route_table_msg *change)
{
    bool parsed, ipv4 = false;

    static const struct nl_policy policy[] = {
        [RTA_DST] = { .type = NL_A_U32, .optional = true  },
        [RTA_OIF] = { .type = NL_A_U32, .optional = true },
        [RTA_GATEWAY] = { .type = NL_A_U32, .optional = true },
        [RTA_MARK] = { .type = NL_A_U32, .optional = true },
        [RTA_PREFSRC] = { .type = NL_A_U32, .optional = true },
        [RTA_TABLE] = { .type = NL_A_U32, .optional = true },
    };

    static const struct nl_policy policy6[] = {
        [RTA_DST] = { .type = NL_A_IPV6, .optional = true },
        [RTA_OIF] = { .type = NL_A_U32, .optional = true },
        [RTA_MARK] = { .type = NL_A_U32, .optional = true },
        [RTA_GATEWAY] = { .type = NL_A_IPV6, .optional = true },
        [RTA_PREFSRC] = { .type = NL_A_IPV6, .optional = true },
        [RTA_TABLE] = { .type = NL_A_U32, .optional = true },
    };

    struct nlattr *attrs[ARRAY_SIZE(policy)];
    const struct rtmsg *rtm;

    rtm = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *rtm);

    if (rtm->rtm_family == AF_INET) {
        parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct rtmsg),
                                 policy, attrs, ARRAY_SIZE(policy));
        ipv4 = true;
    } else if (rtm->rtm_family == AF_INET6) {
        parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct rtmsg),
                                 policy6, attrs, ARRAY_SIZE(policy6));
    } else {
        VLOG_DBG_RL(&rl, "received non AF_INET rtnetlink route message");
        return 0;
    }

    if (parsed) {
        const struct nlmsghdr *nlmsg;
        uint32_t table_id;
        int rta_oif;      /* Output interface index. */

        nlmsg = buf->data;

        memset(change, 0, sizeof *change);
        change->relevant = true;

        if (rtm->rtm_scope == RT_SCOPE_NOWHERE) {
            change->relevant = false;
        }

        if (rtm->rtm_type != RTN_UNICAST &&
            rtm->rtm_type != RTN_LOCAL) {
            change->relevant = false;
        }

        table_id = rtm->rtm_table;
        if (attrs[RTA_TABLE]) {
            table_id = nl_attr_get_u32(attrs[RTA_TABLE]);
            change->rd.rta_table_id = table_id;
        }

        change->nlmsg_type     = nlmsg->nlmsg_type;
        change->rd.rtm_dst_len = rtm->rtm_dst_len + (ipv4 ? 96 : 0);
        change->rd.plen = rtm->rtm_dst_len;
        change->rd.rtm_protocol = rtm->rtm_protocol;
        change->rd.local = rtm->rtm_type == RTN_LOCAL;
        if (attrs[RTA_OIF]) {
            rta_oif = nl_attr_get_u32(attrs[RTA_OIF]);

            if (!if_indextoname(rta_oif, change->rd.ifname)) {
                int error = errno;

                VLOG_DBG_RL(&rl, "Could not find interface name[%u]: %s",
                            rta_oif, ovs_strerror(error));
                if (error == ENXIO) {
                    change->relevant = false;
                } else {
                    return 0;
                }
            }
        }

        if (attrs[RTA_DST]) {
            if (ipv4) {
                ovs_be32 dst;
                dst = nl_attr_get_be32(attrs[RTA_DST]);
                in6_addr_set_mapped_ipv4(&change->rd.rta_dst, dst);
            } else {
                change->rd.rta_dst = nl_attr_get_in6_addr(attrs[RTA_DST]);
            }
        } else if (ipv4) {
            in6_addr_set_mapped_ipv4(&change->rd.rta_dst, 0);
        }
        if (attrs[RTA_PREFSRC]) {
            if (ipv4) {
                ovs_be32 prefsrc;
                prefsrc = nl_attr_get_be32(attrs[RTA_PREFSRC]);
                in6_addr_set_mapped_ipv4(&change->rd.rta_prefsrc, prefsrc);
            } else {
                change->rd.rta_prefsrc =
                    nl_attr_get_in6_addr(attrs[RTA_PREFSRC]);
            }
        }
        if (attrs[RTA_GATEWAY]) {
            if (ipv4) {
                ovs_be32 gw;
                gw = nl_attr_get_be32(attrs[RTA_GATEWAY]);
                in6_addr_set_mapped_ipv4(&change->rd.rta_gw, gw);
            } else {
                change->rd.rta_gw = nl_attr_get_in6_addr(attrs[RTA_GATEWAY]);
            }
        }
        if (attrs[RTA_MARK]) {
            change->rd.mark = nl_attr_get_u32(attrs[RTA_MARK]);
        }
    } else {
        VLOG_DBG_RL(&rl, "received unparseable rtnetlink route message");
        return 0;
    }

    /* Success. */
    return ipv4 ? RTNLGRP_IPV4_ROUTE : RTNLGRP_IPV6_ROUTE;
}

static inline bool
route_table_dump_one_table(
    char *netns,
    uint32_t id,
    void (*handle_msg)(struct route_table_msg *, void *),
    void *data)
{
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf request, reply, buf;
    struct rtmsg *rq_msg;
    bool filtered = true;
    struct nl_dump dump;

    ofpbuf_init(&request, 0);

    nl_msg_put_nlmsghdr(&request, 0, RTM_GETROUTE, NLM_F_REQUEST);

    rq_msg = ofpbuf_put_zeros(&request, sizeof *rq_msg);
    rq_msg->rtm_family = AF_UNSPEC;
    rq_msg->rtm_table = RT_TABLE_UNSPEC;

    nl_msg_put_u32(&request, RTA_TABLE, id);

    nl_ns_dump_start(netns, &dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    while (nl_dump_next(&dump, &reply, &buf)) {
        struct route_table_msg msg;

        if (route_table_parse(&reply, &msg)) {
            struct nlmsghdr *nlmsghdr = nl_msg_nlmsghdr(&reply);

            /* Older kernels do not support filtering. */
            if (!(nlmsghdr->nlmsg_flags & NLM_F_DUMP_FILTERED)) {
                filtered = false;
            }
            (*handle_msg)(&msg, data);
        }
    }
    ofpbuf_uninit(&buf);
    nl_dump_done(&dump);

    return filtered;
}
/* END VENDORED CODE */

#endif /* route-exchange-netlink-private.h */
