/*
 * Copyright (c) 2024, Red Hat, Inc.
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

#ifndef OVN_CONTROLLER_LB_H
#define OVN_CONTROLLER_LB_H 1

#include "lib/lb.h"

struct sbrec_load_balancer;
struct sbrec_load_balancer_table;

struct ovn_controller_lb {
    struct hmap_node hmap_node;

    const struct sbrec_load_balancer *slb; /* May be NULL. */

    uint8_t proto;

    struct ovn_lb_vip *vips;
    size_t n_vips;
    bool hairpin_orig_tuple; /* True if ovn-northd stores the original
                              * destination tuple in registers.
                              */
    bool ct_flush; /* True if we should flush CT after backend removal. */

    struct lport_addresses hairpin_snat_ips; /* IP (v4 and/or v6) to be used
                                              * as source for hairpinned
                                              * traffic.
                                              */
};

/* Stores the load balancers that are applied to the datapath 'dp'. */
struct load_balancers_by_dp {
    struct hmap_node node;
    const struct sbrec_datapath_binding *dp;
    const struct sbrec_load_balancer **dp_lbs;
    size_t n_allocated_dp_lbs;
    size_t n_dp_lbs;
};

struct ovn_controller_lb *ovn_controller_lb_create(
    const struct sbrec_load_balancer *,
    const struct smap *template_vars,
    struct sset *template_vars_ref);
void ovn_controller_lb_destroy(struct ovn_controller_lb *);
void ovn_controller_lbs_destroy(struct hmap *ovn_controller_lbs);
struct ovn_controller_lb *ovn_controller_lb_find(
    const struct hmap *ovn_controller_lbs,
    const struct uuid *uuid);

struct hmap *load_balancers_by_dp_init(
    const struct hmap *local_datapaths,
    const struct sbrec_load_balancer_table *lb_table);
struct load_balancers_by_dp *load_balancers_by_dp_find(
    struct hmap *lbs,
    const struct sbrec_datapath_binding *dp);
void load_balancers_by_dp_cleanup(struct hmap *lbs);


#endif /* OVN_CONTROLLER_LB_H */

