/*
 * Copyright (c) 2023, Red Hat, Inc.
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

#include "openvswitch/vlog.h"
#include "stopwatch.h"
#include "northd.h"

#include "en-routes-sync.h"
#include "en-lr-stateful.h"
#include "lib/stopwatch-names.h"
#include "openvswitch/hmap.h"
#include "ovn-util.h"

VLOG_DEFINE_THIS_MODULE(en_routes_sync);

static void
routes_table_sync(struct ovsdb_idl_txn *ovnsb_txn,
                  const struct sbrec_route_table *sbrec_route_table,
                  const struct lr_stateful_table *lr_stateful_table,
                  const struct hmap *parsed_routes,
                  const struct hmap *lr_ports,
                  const struct ovn_datapaths *lr_datapaths,
                  struct hmap *parsed_routes_out);

static void
routes_sync_init(struct routes_sync_data *data)
{
    hmap_init(&data->parsed_routes);
}

static void
routes_sync_destroy(struct routes_sync_data *data)
{
    struct parsed_route *r;
    HMAP_FOR_EACH_POP (r, key_node, &data->parsed_routes) {
        parsed_route_free(r);
    }
    hmap_destroy(&data->parsed_routes);
}

void
*en_routes_sync_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct routes_sync_data *data = xzalloc(sizeof *data);
    routes_sync_init(data);
    return data;
}

void
en_routes_sync_cleanup(void *data)
{
    routes_sync_destroy(data);
    free(data);
}

void
en_routes_sync_run(struct engine_node *node, void *data)
{
    routes_sync_destroy(data);
    routes_sync_init(data);

    struct routes_sync_data *routes_sync_data = data;
    struct routes_data *routes_data
        = engine_get_input_data("routes", node);
    const struct engine_context *eng_ctx = engine_get_context();
    const struct sbrec_route_table *sbrec_route_table =
        EN_OVSDB_GET(engine_get_input("SB_route", node));
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct ed_type_lr_stateful *lr_stateful_data =
        engine_get_input_data("lr_stateful", node);

    stopwatch_start(ROUTES_SYNC_RUN_STOPWATCH_NAME, time_msec());

    routes_table_sync(eng_ctx->ovnsb_idl_txn, sbrec_route_table,
                      &lr_stateful_data->table,
                      &routes_data->parsed_routes,
                      &northd_data->lr_ports,
                      &northd_data->lr_datapaths,
                      &routes_sync_data->parsed_routes);

    stopwatch_stop(ROUTES_SYNC_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}

struct route_entry {
    struct hmap_node hmap_node;

    const struct sbrec_route *sb_route;
    const struct sbrec_datapath_binding *sb_db;

    char *logical_port;
    char *ip_prefix;
    char *tracked_port;
    char *type;
    bool stale;
};

static struct route_entry *
route_alloc_entry(struct hmap *routes,
                  const struct sbrec_datapath_binding *sb_db,
                  const char *logical_port,
                  const char *ip_prefix,
                  const char *route_type,
                  const char *tracked_port)
{
    struct route_entry *route_e = xzalloc(sizeof *route_e);

    route_e->sb_db = sb_db;
    route_e->logical_port = xstrdup(logical_port);
    route_e->ip_prefix = xstrdup(ip_prefix);
    route_e->type = xstrdup(route_type);
    if (tracked_port) {
        route_e->tracked_port = xstrdup(tracked_port);
    }
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
                    const char *route_type, const char *tracked_port)
{
    struct route_entry *route_e;
    uint32_t hash;

    hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    HMAP_FOR_EACH_WITH_HASH (route_e, hmap_node, hash, route_map) {
        if (!strcmp(route_e->type, route_type) &&
            // TODO this is ugly
            ((route_e->tracked_port == NULL) == (tracked_port == NULL)) &&
            (route_e->tracked_port == NULL || !strcmp(route_e->tracked_port, tracked_port))) {
            return route_e;
        }
    }

    route_e = route_alloc_entry(route_map, sb_db,
                                 logical_port, ip_prefix, route_type,
                                 tracked_port);
    return route_e;
}

static struct route_entry *
route_sync_to_sb(struct ovsdb_idl_txn *ovnsb_txn, struct hmap *route_map,
                 const struct sbrec_datapath_binding *sb_db,
                 const char *logical_port, const char *ip_prefix,
                 const char *route_type, const char *tracked_port)
{
    struct route_entry *route_e = route_lookup_or_add(route_map,
                                                      sb_db,
                                                      logical_port,
                                                      ip_prefix,
                                                      route_type,
                                                      tracked_port);
    route_e->stale = false;

    if (!route_e->sb_route) {
        const struct sbrec_route *sr = sbrec_route_insert(ovnsb_txn);
        sbrec_route_set_datapath(sr, route_e->sb_db);
        sbrec_route_set_logical_port(sr, route_e->logical_port);
        sbrec_route_set_ip_prefix(sr, route_e->ip_prefix);
        sbrec_route_set_type(sr, route_e->type);
        if (route_e->tracked_port) {
            sbrec_route_set_tracked_port(sr, route_e->tracked_port);
        }
        route_e->sb_route = sr;
    }

    return route_e;
}

static void
route_erase_entry(struct route_entry *route_e)
{
    free(route_e->logical_port);
    free(route_e->ip_prefix);
    free(route_e->type);
    free(route_e);
}

static void
parse_route_from_sbrec_route(struct hmap *parsed_routes_out,
                             const struct hmap *lr_ports,
                             const struct hmap *lr_datapaths,
                             const struct sbrec_route *route)
{
    /* TODO: this is mostly stolen from parsed_route_add_static, we should
     * refactor this so that we do not need to duplicate it all. */

    const struct ovn_datapath *od = ovn_datapath_from_sbrec(
        NULL, lr_datapaths, route->datapath);

    /* Verify that the next hop is an IP address with an all-ones mask. */
    struct in6_addr *nexthop = xmalloc(sizeof(*nexthop));
    unsigned int plen;
    if (!ip46_parse_cidr(route->nexthop, nexthop, &plen)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'nexthop' %s in learned route "
                     UUID_FMT, route->nexthop,
                     UUID_ARGS(&route->header_.uuid));
        free(nexthop);
        return;
    }
    if ((IN6_IS_ADDR_V4MAPPED(nexthop) && plen != 32) ||
        (!IN6_IS_ADDR_V4MAPPED(nexthop) && plen != 128)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad next hop mask %s in learned route "
                     UUID_FMT, route->nexthop,
                     UUID_ARGS(&route->header_.uuid));
        free(nexthop);
        return;
    }

    /* Parse ip_prefix */
    struct in6_addr prefix;
    if (!ip46_parse_cidr(route->ip_prefix, &prefix, &plen)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'ip_prefix' %s in learned route "
                     UUID_FMT, route->ip_prefix,
                     UUID_ARGS(&route->header_.uuid));
        free(nexthop);
        return;
    }

    /* Verify that ip_prefix and nexthop have same address familiy. */
    if (IN6_IS_ADDR_V4MAPPED(&prefix) != IN6_IS_ADDR_V4MAPPED(nexthop)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Address family doesn't match between 'ip_prefix'"
                     " %s and 'nexthop' %s in learned route "UUID_FMT,
                     route->ip_prefix, route->nexthop,
                     UUID_ARGS(&route->header_.uuid));
        free(nexthop);
        return;
    }

    /* Verify that ip_prefix and nexthop are on the same network. */
    const char *lrp_addr_s = NULL;
    struct ovn_port *out_port = NULL;
    if (!find_route_outport(lr_ports, route->logical_port,
                            route->ip_prefix, route->nexthop,
                            IN6_IS_ADDR_V4MAPPED(&prefix),
                            &out_port, &lrp_addr_s)) {
        free(nexthop);
        return;
    }

    parsed_route_add(
        od,
        nexthop,
        prefix,
        plen,
        false,
        lrp_addr_s,
        out_port,
        0,
        false,
        false,
        ROUTE_SOURCE_LEARNED,
        &route->header_,
        parsed_routes_out
        );
}

static void
publish_lport_addresses(struct ovsdb_idl_txn *ovnsb_txn,
                        struct hmap *route_map,
                        const struct sbrec_datapath_binding *sb_db,
                        char *logical_port,
                        struct lport_addresses *addresses,
                        struct ovn_port *tracking_port)
{
    for (int i = 0; i < addresses->n_ipv4_addrs; i++) {
        const struct ipv4_netaddr *addr = &addresses->ipv4_addrs[i];
        char *addr_s = xasprintf("%s/32", addr->addr_s);
        route_sync_to_sb(ovnsb_txn, route_map,
                         sb_db,
                         logical_port,
                         addr_s,
                         "advertise",
                         tracking_port->sb->logical_port);
        free(addr_s);
    }
    for (int i = 0; i < addresses->n_ipv6_addrs; i++) {
        if (in6_is_lla(&addresses->ipv6_addrs[i].network)) {
            continue;
        }
        const struct ipv6_netaddr *addr = &addresses->ipv6_addrs[i];
        char *addr_s = xasprintf("%s/128", addr->addr_s);
        route_sync_to_sb(ovnsb_txn, route_map,
                         sb_db,
                         logical_port,
                         addr_s,
                         "advertise",
                         tracking_port->sb->logical_port);
        free(addr_s);
    }
}


static void
publish_host_routes(struct ovsdb_idl_txn *ovnsb_txn,
                    struct hmap *route_map,
                    const struct lr_stateful_table *lr_stateful_table,
                    const struct parsed_route *route)
{
    struct ovn_port *port;
    HMAP_FOR_EACH(port, dp_node, &route->out_port->peer->od->ports) {
        if (port->peer) {
            /* This is a LSP connected to an LRP */
            struct lport_addresses *addresses = &port->peer->lrp_networks;
            publish_lport_addresses(ovnsb_txn, route_map, route->od->sb,
                                    route->out_port->key,
                                    addresses, port->peer);

            const struct lr_stateful_record *lr_stateful_rec;
            lr_stateful_rec = lr_stateful_table_find_by_index(lr_stateful_table,
                                                              port->peer->od->index);
            struct ovn_port_routable_addresses addrs = get_op_addresses(
                port->peer, lr_stateful_rec, false);
            for (int i = 0; i < addrs.n_addrs; i++) {
                publish_lport_addresses(ovnsb_txn, route_map, route->od->sb,
                                        route->out_port->key,
                                        &addrs.laddrs[i],
                                        port->peer);
            }
        } else {
            /* This is just a plain LSP */
            for (int i = 0; i < port->n_lsp_addrs; i++) {
                publish_lport_addresses(ovnsb_txn, route_map, route->od->sb,
                                        route->out_port->key,
                                        &port->lsp_addrs[i],
                                        port);
            }
        }
    }
}

static void
routes_table_sync(struct ovsdb_idl_txn *ovnsb_txn,
                  const struct sbrec_route_table *sbrec_route_table,
                  const struct lr_stateful_table *lr_stateful_table,
                  const struct hmap *parsed_routes,
                  const struct hmap *lr_ports,
                  const struct ovn_datapaths *lr_datapaths,
                  struct hmap *parsed_routes_out)
{
    if (!ovnsb_txn) {
        return;
    }

    struct hmap sync_routes = HMAP_INITIALIZER(&sync_routes);

    const struct parsed_route *route;

    struct route_entry *route_e;
    const struct sbrec_route *sb_route;
    SBREC_ROUTE_TABLE_FOR_EACH (sb_route, sbrec_route_table) {
        route_e = route_alloc_entry(&sync_routes,
                                    sb_route->datapath,
                                    sb_route->logical_port,
                                    sb_route->ip_prefix,
                                    sb_route->type,
                                    sb_route->tracked_port);
        route_e->stale = true;
        route_e->sb_route = sb_route;

        if (!strcmp(route_e->type, "receive")) {
            parse_route_from_sbrec_route(parsed_routes_out, lr_ports,
                                         &lr_datapaths->datapaths,
                                         sb_route);
        }
    }

    HMAP_FOR_EACH(route, key_node, parsed_routes) {
        hmap_insert(parsed_routes_out, &parsed_route_clone(route)->key_node, parsed_route_hash(route));
        if (route->is_discard_route) {
            continue;
        }
        if (prefix_is_link_local(&route->prefix, route->plen)) {
            continue;
        }
        if (!smap_get_bool(&route->od->nbr->options, "dynamic-routing", false)) {
            continue;
        }
        if (route->source == ROUTE_SOURCE_CONNECTED && !smap_get_bool(&route->out_port->nbrp->options, "dynamic-routing-connected", false)) {
            continue;
        }
        if (route->source == ROUTE_SOURCE_STATIC && !smap_get_bool(&route->out_port->nbrp->options, "dynamic-routing-static", false)) {
            continue;
        }

        if (smap_get_bool(&route->out_port->nbrp->options, "dynamic-routing-connected-as-host-routes", false)) {
            publish_host_routes(ovnsb_txn, &sync_routes,
                                lr_stateful_table, route);
        } else {
            char *ip_prefix = normalize_v46_prefix(&route->prefix, route->plen);
            route_sync_to_sb(ovnsb_txn, &sync_routes,
                             route->od->sb,
                             route->out_port->key,
                             ip_prefix,
                             "advertise",
                             NULL);
            free(ip_prefix);
        }
    }

    HMAP_FOR_EACH_POP (route_e, hmap_node, &sync_routes) {
        /* These routes are added by ovn-controller we should only read but
         * not remove them */
        if (!strcmp(route_e->sb_route->type, "receive")) {
            continue;
        }
        if (route_e->stale) {
            sbrec_route_delete(route_e->sb_route);
        }
        route_erase_entry(route_e);
    }
    hmap_destroy(&sync_routes);
}

