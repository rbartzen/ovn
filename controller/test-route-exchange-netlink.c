/* Copyright (c) 2021, Canonical
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

#include "openvswitch/hmap.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "route-exchange-netlink.h"
#include "tests/ovstest.h"

#define VRF_IFNAME "ovnvrf42"
#define TABLE_ID 42

static void
test_re_nl_sync_routes(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct hmap host_routes = HMAP_INITIALIZER(&host_routes);
    struct in6_addr dst4, dst6;
    ovs_be32 ip;
    int err;

    ipv6_parse("2001:db8:42::100", &dst6);
    host_route_insert(&host_routes, TABLE_ID, &dst6);

    ip_parse("172.16.42.100", &ip);
    in6_addr_set_mapped_ipv4(&dst4, ip);
    host_route_insert(&host_routes, TABLE_ID, &dst4);

    err = re_nl_create_vrf(VRF_IFNAME, TABLE_ID);
    ovs_assert(err == 0);
    err = re_nl_create_vrf(VRF_IFNAME, TABLE_ID);
    ovs_assert(err == EEXIST);
    re_nl_sync_routes(TABLE_ID, VRF_IFNAME, &host_routes);
    host_routes_destroy(&host_routes);

    err = re_nl_add_route(TABLE_ID, &dst6, VRF_IFNAME);
    ovs_assert(err == EEXIST);
    err = re_nl_add_route(TABLE_ID, &dst4, VRF_IFNAME);
    ovs_assert(err == EEXIST);

    hmap_init(&host_routes);
    re_nl_sync_routes(TABLE_ID, VRF_IFNAME, &host_routes);
    host_routes_destroy(&host_routes);

    err = re_nl_add_route(TABLE_ID, &dst6, VRF_IFNAME);
    ovs_assert(err == 0);
    err = re_nl_add_route(TABLE_ID, &dst4, VRF_IFNAME);
    ovs_assert(err == 0);

    err = re_nl_delete_vrf(VRF_IFNAME);
    ovs_assert(err == 0);
}

static void
test_re_nl_create_vrf(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int err;

    err = re_nl_create_vrf(VRF_IFNAME, TABLE_ID);
    ovs_assert(err == 0);
    err = re_nl_create_vrf(VRF_IFNAME, TABLE_ID);
    ovs_assert(err == EEXIST);
    err = re_nl_delete_vrf(VRF_IFNAME);
    ovs_assert(err == 0);
}

static void
test_re_nl_delete_vrf(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int err;

    err = re_nl_create_vrf(VRF_IFNAME, TABLE_ID);
    ovs_assert(err == 0);
    err = re_nl_delete_vrf(VRF_IFNAME);
    ovs_assert(err == 0);
    err = re_nl_delete_vrf(VRF_IFNAME);
    ovs_assert(err == ENODEV);
}

static void
test_re_nl_add_route(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int err;
    struct in6_addr dst4, dst6;
    ovs_be32 ip;

    ipv6_parse("2001:db8:42::100", &dst6);
    ip_parse("172.16.42.100", &ip);
    in6_addr_set_mapped_ipv4(&dst4, ip);

    err = re_nl_create_vrf(VRF_IFNAME, TABLE_ID);
    ovs_assert(err == 0);

    err = re_nl_add_route(TABLE_ID, &dst6, VRF_IFNAME);
    ovs_assert(err == 0);
    err = re_nl_add_route(TABLE_ID, &dst4, VRF_IFNAME);
    ovs_assert(err == 0);
    err = re_nl_add_route(TABLE_ID, &dst6, VRF_IFNAME);
    ovs_assert(err == EEXIST);
    err = re_nl_add_route(TABLE_ID, &dst4, VRF_IFNAME);
    ovs_assert(err == EEXIST);

    err = re_nl_delete_vrf(VRF_IFNAME);
    ovs_assert(err == 0);
}

static void
test_re_nl_delete_route(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int err;
    struct in6_addr dst4, dst6;
    ovs_be32 ip;

    ipv6_parse("2001:db8:42::100", &dst6);
    ip_parse("172.16.42.100", &ip);
    in6_addr_set_mapped_ipv4(&dst4, ip);

    err = re_nl_create_vrf(VRF_IFNAME, TABLE_ID);
    ovs_assert(err == 0);

    err = re_nl_add_route(TABLE_ID, &dst6, VRF_IFNAME);
    ovs_assert(err == 0);
    err = re_nl_add_route(TABLE_ID, &dst4, VRF_IFNAME);
    ovs_assert(err == 0);

    err = re_nl_delete_route(TABLE_ID, &dst6);
    ovs_assert(err == 0);
    err = re_nl_delete_route(TABLE_ID, &dst4);
    ovs_assert(err == 0);
    err = re_nl_delete_route(TABLE_ID, &dst6);
    ovs_assert(err == ESRCH);
    err = re_nl_delete_route(TABLE_ID, &dst4);
    ovs_assert(err == ESRCH);

    err = re_nl_delete_vrf(VRF_IFNAME);
    ovs_assert(err == 0);
}

static void
test_route_exchange_netlink_main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"sync-routes", NULL, 0, 0, test_re_nl_sync_routes, OVS_RO},
        {"create-vrf", NULL, 0, 0, test_re_nl_create_vrf, OVS_RO},
        {"delete-vrf", NULL, 0, 0, test_re_nl_delete_vrf, OVS_RO},
        {"add-route", NULL, 0, 0, test_re_nl_add_route, OVS_RO},
        {"delete-route", NULL, 0, 0, test_re_nl_delete_route, OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-route-exchange-netlink",
                 test_route_exchange_netlink_main);
