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
#include "lib/stopwatch-names.h"
#include "openvswitch/hmap.h"
#include "ovn-util.h"

VLOG_DEFINE_THIS_MODULE(en_routes_sync);

static void
routes_table_sync(struct ovsdb_idl_txn *ovnsb_txn,
                  const struct sbrec_route_table *sbrec_route_table,
                  const struct hmap *parsed_routes);

void
*en_routes_sync_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_routes_sync_cleanup(void *data_ OVS_UNUSED)
{
}

void
en_routes_sync_run(struct engine_node *node, void *data_ OVS_UNUSED)
{
    struct routes_data *routes_data
        = engine_get_input_data("routes", node);
    const struct engine_context *eng_ctx = engine_get_context();
    const struct sbrec_route_table *sbrec_route_table =
        EN_OVSDB_GET(engine_get_input("SB_route", node));

    stopwatch_start(ROUTES_SYNC_RUN_STOPWATCH_NAME, time_msec());

    routes_table_sync(eng_ctx->ovnsb_idl_txn, sbrec_route_table,
                      &routes_data->parsed_routes);

    stopwatch_stop(ROUTES_SYNC_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}

struct route_entry {
    struct hmap_node hmap_node;

    const struct sbrec_route *sb_route;
    const struct sbrec_datapath_binding *sb_db;

    char *logical_port;
    char *ip_prefix;
    char *type;
    bool stale;
};

static struct route_entry *
route_alloc_entry(struct hmap *routes,
                  const struct sbrec_datapath_binding *sb_db,
                  char *logical_port, char *ip_prefix, char *route_type)
{
    struct route_entry *route_e = xzalloc(sizeof *route_e);

    route_e->sb_db = sb_db;
    route_e->logical_port = xstrdup(logical_port);
    route_e->ip_prefix = xstrdup(ip_prefix);
    route_e->type = xstrdup(route_type);
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
                    char *logical_port, const struct in6_addr *prefix,
                    unsigned int plen, char *route_type)
{
    struct route_entry *route_e;
    uint32_t hash;

    char *ip_prefix = normalize_v46_prefix(prefix, plen);

    hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    HMAP_FOR_EACH_WITH_HASH (route_e, hmap_node, hash, route_map) {
        if (!strcmp(route_e->type, route_type)) {
            free(ip_prefix);
            return route_e;
        }
    }

    route_e =  route_alloc_entry(route_map, sb_db,
                                 logical_port, ip_prefix, route_type);
    free(ip_prefix);
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
routes_table_sync(struct ovsdb_idl_txn *ovnsb_txn,
                  const struct sbrec_route_table *sbrec_route_table,
                  const struct hmap *parsed_routes)
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
                                    sb_route->type);
        route_e->stale = true;
        route_e->sb_route = sb_route;
    }

    HMAP_FOR_EACH(route, key_node, parsed_routes) {
        if (route->is_discard_route) {
            continue;
        }
        if (prefix_is_link_local(&route->prefix, route->plen)) {
            continue;
        }
        if (!smap_get_bool(&route->od->nbr->options, "dynamic-routing", false)) {
            continue;
        }
        route_e = route_lookup_or_add(&sync_routes,
                                      route->od->sb,
                                      route->out_port->key,
                                      &route->prefix,
                                      route->plen,
                                      "advertise");
        route_e->stale = false;

        if (!route_e->sb_route) {
            const struct sbrec_route *sr = sbrec_route_insert(ovnsb_txn);
            sbrec_route_set_datapath(sr, route_e->sb_db);
            sbrec_route_set_logical_port(sr, route_e->logical_port);
            sbrec_route_set_ip_prefix(sr, route_e->ip_prefix);
            sbrec_route_set_type(sr, route_e->type);
            route_e->sb_route = sr;
        }
    }

    HMAP_FOR_EACH_POP (route_e, hmap_node, &sync_routes) {
        if (route_e->stale) {
            sbrec_route_delete(route_e->sb_route);
        }
        route_erase_entry(route_e);
    }
    hmap_destroy(&sync_routes);
}

