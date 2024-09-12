/* Copyright (c) 2017, Red Hat, Inc.
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

#ifndef OVN_LRP_INDEX_H
#define OVN_LRP_INDEX_H 1

struct ovsdb_idl;

struct ovsdb_idl_index *lrp_index_create(struct ovsdb_idl *);

const struct nbrec_logical_router_port *lrp_lookup_by_name(
    struct ovsdb_idl_index *nbrec_lrp_by_name, const char *name);

#endif /* lib/lrp-index.h */
