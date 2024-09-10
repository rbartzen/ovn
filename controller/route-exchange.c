/*
 * Copyright (c) 2024 Canonical
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

#include <config.h>

#include <errno.h>
#include <net/if.h>

#include "openvswitch/vlog.h"

#include "lib/ovn-sb-idl.h"

#include "binding.h"
#include "ha-chassis.h"
#include "lb.h"
#include "local_data.h"
#include "route-exchange.h"
#include "route-exchange-netlink.h"


VLOG_DEFINE_THIS_MODULE(route_exchange);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

/* While the linux kernel can handle 2^32 routing tables, only so many can fit
 * in the corresponding VRF interface name. */
#define MAX_TABLE_ID 1000000000

static struct sset _maintained_vrfs = SSET_INITIALIZER(&_maintained_vrfs);

struct route_entry {
    struct hmap_node hmap_node;

    const struct sbrec_route *sb_route;

    const struct sbrec_datapath_binding *sb_db;
    char *logical_port;
    char *ip_prefix;
    char *nexthop;
    bool stale;
};

static struct route_entry *
route_alloc_entry(struct hmap *routes,
                  const struct sbrec_datapath_binding *sb_db,
                  const char *logical_port,
                  const char *ip_prefix, const char *nexthop)
{
    struct route_entry *route_e = xzalloc(sizeof *route_e);

    route_e->sb_db = sb_db;
    route_e->logical_port = xstrdup(logical_port);
    route_e->ip_prefix = xstrdup(ip_prefix);
    route_e->nexthop = xstrdup(nexthop);
    route_e->stale = false;
    uint32_t hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    hmap_insert(routes, &route_e->hmap_node, hash);

    return route_e;
}

static struct route_entry *
route_lookup_or_add(struct hmap *route_map,
                    const struct sbrec_datapath_binding *sb_db,
                    const char *logical_port, const char *ip_prefix,
                    const char *nexthop)
{
    struct route_entry *route_e;
    uint32_t hash;

    hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    HMAP_FOR_EACH_WITH_HASH (route_e, hmap_node, hash, route_map) {
        if (!strcmp(route_e->nexthop, nexthop)) {
            return route_e;
        }
    }

    route_e = route_alloc_entry(route_map, sb_db,
                                 logical_port, ip_prefix, nexthop);
    return route_e;
}

static void
route_erase_entry(struct route_entry *route_e)
{
    free(route_e->logical_port);
    free(route_e->ip_prefix);
    free(route_e->nexthop);
    free(route_e);
}

static void
sb_sync_learned_routes(const struct sbrec_datapath_binding *datapath,
                       const struct hmap *learned_routes,
                       const struct sset *bound_ports,
                       struct ovsdb_idl_txn *ovnsb_idl_txn,
                       struct ovsdb_idl_index *sbrec_route_by_datapath)
{
    struct hmap sync_routes = HMAP_INITIALIZER(&sync_routes);
    struct route_entry *route_e;
    const struct sbrec_route *sb_route;

    struct sbrec_route *filter =
            sbrec_route_index_init_row(sbrec_route_by_datapath);
    sbrec_route_index_set_datapath(filter, datapath);
    SBREC_ROUTE_FOR_EACH_EQUAL(sb_route, filter, sbrec_route_by_datapath) {
        if (strcmp(sb_route->type, "receive")) {
            continue;
        }
        /* If the port is not local we don't care about it, someone else will */
        if (!sset_contains(bound_ports, sb_route->logical_port)) {
            continue;
        }
        route_e = route_alloc_entry(&sync_routes,
                                    sb_route->datapath,
                                    sb_route->logical_port,
                                    sb_route->ip_prefix,
                                    sb_route->nexthop);
        route_e->stale = true;
        route_e->sb_route = sb_route;
    }
    sbrec_route_index_destroy_row(filter);

    struct receive_route_node *learned_route;
    HMAP_FOR_EACH(learned_route, hmap_node, learned_routes) {
        char *ip_prefix = normalize_v46_prefix(&learned_route->addr, learned_route->plen);
        char *nexthop = normalize_v46(&learned_route->nexthop);

        const char *logical_port;
        SSET_FOR_EACH(logical_port, bound_ports) {
            route_e = route_lookup_or_add(&sync_routes,
                datapath,
                logical_port, ip_prefix, nexthop);
            route_e->stale = false;
            if (!route_e->sb_route) {
                sb_route = sbrec_route_insert(ovnsb_idl_txn);
                sbrec_route_set_datapath(sb_route, datapath);
                sbrec_route_set_logical_port(sb_route, logical_port);
                sbrec_route_set_ip_prefix(sb_route, ip_prefix);
                sbrec_route_set_nexthop(sb_route, nexthop);
                sbrec_route_set_type(sb_route, "receive");
                route_e->sb_route = sb_route;
            }
        }
        free(ip_prefix);
        free(nexthop);
    }

    HMAP_FOR_EACH_POP (route_e, hmap_node, &sync_routes) {
        if (route_e->stale) {
            sbrec_route_delete(route_e->sb_route);
        }
        route_erase_entry(route_e);
    }
    hmap_destroy(&sync_routes);
}

bool
route_exchange_relevant_port(const struct sbrec_port_binding *pb)
{
    return (pb && smap_get_bool(&pb->options, "dynamic-routing", false));
}

void
route_exchange_run(struct route_exchange_ctx_in *r_ctx_in,
                   struct route_exchange_ctx_out *r_ctx_out)
{
    struct sset old_maintained_vrfs = SSET_INITIALIZER(&old_maintained_vrfs);
    sset_swap(&_maintained_vrfs, &old_maintained_vrfs);

    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, r_ctx_in->local_datapaths) {
        if (!ld->n_peer_ports || ld->is_switch) {
            continue;
        }

        bool maintain_vrf = false;
        bool use_netns = false;
        bool relevant_datapath = false;
        struct hmap local_routes
            = HMAP_INITIALIZER(&local_routes);
        struct hmap learned_routes
            = HMAP_INITIALIZER(&learned_routes);
        struct sset bound_ports = SSET_INITIALIZER(&bound_ports);

        /* This is a LR datapath, find LRPs with route exchange options
         * that are bound locally. */
        for (size_t i = 0; i < ld->n_peer_ports; i++) {
            const struct sbrec_port_binding *local_peer
                = ld->peer_ports[i].local;
            if (!local_peer) {
                continue;
            }
            const char *crp = smap_get(&local_peer->options, "chassis-redirect-port");
            if (!crp) {
                continue;
            }
            if (!sset_contains(r_ctx_in->local_lports, crp)) {
                continue;
            }
            const struct sbrec_port_binding *sb_crp = lport_lookup_by_name(
                r_ctx_in->sbrec_port_binding_by_name, crp);
            if (!route_exchange_relevant_port(sb_crp)) {
                continue;
            }

            maintain_vrf |= smap_get_bool(&sb_crp->options,
                                          "maintain-vrf", false);
            use_netns |= smap_get_bool(&sb_crp->options,
                                       "use-netns", false);
            relevant_datapath = true;
            sset_add(&bound_ports, local_peer->logical_port);
        }

        if (!relevant_datapath) {
            continue;
        }

        /* While tunnel_key would most likely never be negative, the compiler
         * has opinions if we don't check before using it in snprintf below. */
        if (ld->datapath->tunnel_key < 0 ||
            ld->datapath->tunnel_key > MAX_TABLE_ID) {
            VLOG_WARN_RL(&rl,
                         "skip route sync for datapath "UUID_FMT", "
                         "tunnel_key %"PRIi64" would make VRF interface name "
                         "overflow.",
                         UUID_ARGS(&ld->datapath->header_.uuid),
                         ld->datapath->tunnel_key);
            goto out;
        }
        char vrf_name[IFNAMSIZ + 1];
        snprintf(vrf_name, sizeof vrf_name, "ovnvrf%"PRIi64,
                 ld->datapath->tunnel_key);

        if (maintain_vrf && use_netns) {
            VLOG_WARN_RL(&rl,
                         "For VRF %s both maintain-vrf and use-netns are set, "
                         "this will never work", vrf_name);
            goto out;
        }

        if (maintain_vrf) {
            int error = re_nl_create_vrf(vrf_name, ld->datapath->tunnel_key);
            if (error && error != EEXIST) {
                VLOG_WARN_RL(&rl,
                             "Unable to create VRF %s for datapath "UUID_FMT
                             ": %s.",
                             vrf_name, UUID_ARGS(&ld->datapath->header_.uuid),
                             ovs_strerror(error));
                goto out;
            }
            sset_add(&_maintained_vrfs, vrf_name);
        }

        struct sbrec_route *route_filter = sbrec_route_index_init_row(
            r_ctx_in->sbrec_route_by_datapath);
        sbrec_route_index_set_datapath(route_filter, ld->datapath);
        struct sbrec_route *route;
        SBREC_ROUTE_FOR_EACH_EQUAL(route, route_filter, r_ctx_in->sbrec_route_by_datapath) {
            if (!strcmp(route->type, "receive")) {
                continue;
            }
            struct in6_addr prefix;
            unsigned int plen;
            if (!ip46_parse_cidr(route->ip_prefix, &prefix, &plen)) {
                VLOG_WARN_RL(&rl, "bad 'ip_prefix' %s in route "
                             UUID_FMT, route->ip_prefix,
                             UUID_ARGS(&route->header_.uuid));
                continue;
            }

            route_insert(&local_routes, &prefix, plen);
        }
        sbrec_route_index_destroy_row(route_filter);

        if (!hmap_is_empty(&local_routes)) {
            tracked_datapath_add(ld->datapath, TRACKED_RESOURCE_NEW,
                                 r_ctx_out->tracked_re_datapaths);
        }
        re_nl_sync_routes(ld->datapath->tunnel_key,
                          &local_routes, &learned_routes, use_netns);

        sb_sync_learned_routes(ld->datapath, &learned_routes, &bound_ports,
                               r_ctx_in->ovnsb_idl_txn,
                               r_ctx_in->sbrec_route_by_datapath);

out:
        routes_destroy(&local_routes);
        routes_destroy(&learned_routes);
        sset_destroy(&bound_ports);
    }

    /* Remove VRFs previously maintained by us not found in the above loop. */
    const char *vrf_name;
    SSET_FOR_EACH_SAFE (vrf_name, &old_maintained_vrfs) {
        if (!sset_find(&_maintained_vrfs, vrf_name)) {
            re_nl_delete_vrf(vrf_name);
        }
        sset_delete(&old_maintained_vrfs, SSET_NODE_FROM_NAME(vrf_name));
    }
    sset_destroy(&old_maintained_vrfs);
}

static void
route_exchange_cleanup__(bool cleanup)
{
    const char *vrf_name;
    SSET_FOR_EACH_SAFE (vrf_name, &_maintained_vrfs) {
        if (cleanup) {
            re_nl_delete_vrf(vrf_name);
        } else {
            sset_delete(&_maintained_vrfs, SSET_NODE_FROM_NAME(vrf_name));
        }
    }
    if (!cleanup) {
        sset_destroy(&_maintained_vrfs);
    }
}

void
route_exchange_cleanup(void)
{
    route_exchange_cleanup__(true);
}

void
route_exchange_destroy(void)
{
    route_exchange_cleanup__(false);
}
