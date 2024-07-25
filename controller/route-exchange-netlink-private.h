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

/*
 * NOTE(fnordahl): The below code is stolen directly from OVS lib/route-table.c
 * with the addition of inlining of function definitions for practical reasons
 * and modifications:
 *
 * struct route_data:
 *
 * - Add rta_table_id.
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
};

/* A digested version of a route message sent down by the kernel to indicate
 * that a route has changed. */
struct route_table_msg {
    bool relevant;        /* Should this message be processed? */
    int nlmsg_type;       /* e.g. RTM_NEWROUTE, RTM_DELROUTE. */
    struct route_data rd; /* Data parsed from this message. */
};

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

    nl_dump_start(&dump, NETLINK_ROUTE, &request);
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
