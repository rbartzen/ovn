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

#ifndef ROUTE_EXCHANGE_H
#define ROUTE_EXCHANGE_H 1

#include <stdbool.h>

struct hmap;
struct ovsdb_idl_index;
struct sbrec_chassis;
struct sbrec_port_binding;
struct sset;

struct route_exchange_ctx_in {
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    const struct sbrec_load_balancer_table *lb_table;
    const struct sbrec_chassis *chassis_rec;
    const struct sset *active_tunnels;
    struct hmap *local_datapaths;
    struct hmap *local_lbs;
    const struct sset *local_lports;
    struct ovsdb_idl_index *sbrec_route_by_datapath;
};

struct route_exchange_ctx_out {
    struct hmap *tracked_re_datapaths;
};

bool route_exchange_relevant_port(const struct sbrec_port_binding *pb);
void route_exchange_run(struct route_exchange_ctx_in *,
                        struct route_exchange_ctx_out *);
void route_exchange_cleanup(void);
void route_exchange_destroy(void);

#endif /* ROUTE_EXCHANGE_H */
