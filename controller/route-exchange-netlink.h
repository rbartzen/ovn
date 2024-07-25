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

#ifndef ROUTE_EXCHANGE_NETLINK_H
#define ROUTE_EXCHANGE_NETLINK_H 1

#include <stdint.h>

struct in6_addr;
struct hmap;

int re_nl_create_vrf(const char *ifname, uint32_t table_id);
int re_nl_delete_vrf(const char *ifname);

int re_nl_add_route(uint32_t table_id, struct in6_addr *dst,
                    const char *ifname);
int re_nl_delete_route(uint32_t table_id, struct in6_addr *dst);

void re_nl_dump(uint32_t table_id);

void host_route_insert(struct hmap *host_routes, uint32_t table_id,
                       struct in6_addr *dst);
void host_routes_destroy(struct hmap *);
void re_nl_sync_routes(uint32_t table_id, const char *ifname,
                       struct hmap *host_routes);

#endif /* route-exchange-netlink.h */
