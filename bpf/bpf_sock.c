// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#define SKIP_POLICY_MAP	1
#define SKIP_CALLS_MAP	1

#include "lib/common.h"
#include "lib/lb.h"
#include "lib/endian.h"
#include "lib/eps.h"
#include "lib/identity.h"
#include "lib/metrics.h"
#include "lib/nat_46x64.h"
#include "lib/sock.h"
#include "lib/trace_sock.h"

#define SYS_REJECT	0
#define SYS_PROCEED	1

#ifndef HOST_NETNS_COOKIE
# define HOST_NETNS_COOKIE   get_netns_cookie(NULL)
#endif

static __always_inline __maybe_unused bool is_v4_loopback(__be32 daddr)
{
    /* Check for 127.0.0.0/8 range, RFC3330. */
    bool result = (daddr & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000);
    bpf_printk("bpf_sock: is_v4_loopback: daddr=%x, result=%d", daddr, result);
    return result;
}

static __always_inline __maybe_unused bool is_v6_loopback(const union v6addr *daddr)
{
    /* Check for ::1/128, RFC4291. */
    union v6addr loopback = { .addr[15] = 1, };
    bool result = ipv6_addr_equals(&loopback, daddr);
    bpf_printk("bpf_sock: is_v6_loopback: daddr=%x:%x:%x:%x, result=%d",
               daddr->addr[0], daddr->addr[1], daddr->addr[2], daddr->addr[3], result);
    return result;
}

/* Hack due to missing narrow ctx access. */
#define ctx_protocol(__ctx) ((__u8)(volatile __u32)(__ctx)->protocol)

/* Hack due to missing narrow ctx access. */
static __always_inline __maybe_unused __be16
ctx_dst_port(const struct bpf_sock_addr *ctx)
{
    volatile __u32 dport = ctx->user_port;
    bpf_printk("bpf_sock: ctx_dst_port: dport=%u", dport);
    return (__be16)dport;
}

static __always_inline __maybe_unused __be16
ctx_src_port(const struct bpf_sock *ctx)
{
    volatile __u16 sport = (__u16)ctx->src_port;
    bpf_printk("bpf_sock: ctx_src_port: sport=%u", sport);
    return (__be16)bpf_htons(sport);
}

static __always_inline __maybe_unused
void ctx_set_port(struct bpf_sock_addr *ctx, __be16 dport)
{
    bpf_printk("bpf_sock: ctx_set_port: Setting port to dport=%u", dport);
    ctx->user_port = (__u32)dport;
}

static __always_inline __maybe_unused bool task_in_extended_hostns(void)
{
#ifdef ENABLE_MKE
    /* Extension for non-Cilium managed containers on MKE. */
    bool result = get_cgroup_classid() == MKE_HOST;
    bpf_printk("bpf_sock: task_in_extended_hostns: result=%d", result);
    return result;
#else
    bpf_printk("bpf_sock: task_in_extended_hostns: ENABLE_MKE not defined, returning false");
    return false;
#endif
}

static __always_inline __maybe_unused bool
ctx_in_hostns(void *ctx __maybe_unused, __net_cookie *cookie)
{
#ifdef HAVE_NETNS_COOKIE
    __net_cookie own_cookie = get_netns_cookie(ctx);
    bool result = own_cookie == HOST_NETNS_COOKIE || task_in_extended_hostns();

    bpf_printk("bpf_sock: ctx_in_hostns: own_cookie=%llu, HOST_NETNS_COOKIE=%llu, result=%d",
               own_cookie, HOST_NETNS_COOKIE, result);
    if (cookie) {
        *cookie = own_cookie;
        bpf_printk("bpf_sock: ctx_in_hostns: Stored cookie=%llu", own_cookie);
    }
    return result;
#else
    bpf_printk("bpf_sock: ctx_in_hostns: HAVE_NETNS_COOKIE not defined, returning true");
    if (cookie) {
        *cookie = 0;
        bpf_printk("bpf_sock: ctx_in_hostns: Stored cookie=0");
    }
    return true;
#endif
}

static __always_inline __maybe_unused bool
sock_is_health_check(struct bpf_sock_addr *ctx __maybe_unused)
{
#ifdef ENABLE_HEALTH_CHECK
    int val;
    int ret = get_socket_opt(ctx, SOL_SOCKET, SO_MARK, &val, sizeof(val));
    bool result = ret == 0 && val == MARK_MAGIC_HEALTH;

    bpf_printk("bpf_sock: sock_is_health_check: get_socket_opt ret=%d, val=%d, result=%d",
               ret, val, result);
    return result;
#else
    bpf_printk("bpf_sock: sock_is_health_check: ENABLE_HEALTH_CHECK not defined, returning false");
    return false;
#endif
}

static __always_inline __maybe_unused
__u64 sock_select_slot(struct bpf_sock_addr *ctx)
{
    __u8 proto = ctx_protocol(ctx);
    __u64 slot = proto == IPPROTO_TCP ? get_prandom_u32() : sock_local_cookie(ctx);

    bpf_printk("bpf_sock: sock_select_slot: proto=%u, slot=%llu", proto, slot);
    return slot;
}

static __always_inline __maybe_unused
bool sock_proto_enabled(__u8 proto)
{
    bool result;
    switch (proto) {
    case IPPROTO_TCP:
        result = true;
        break;
    case IPPROTO_UDPLITE:
    case IPPROTO_UDP:
        result = true;
        break;
    default:
        result = false;
        break;
    }
    bpf_printk("bpf_sock: sock_proto_enabled: proto=%u, result=%d", proto, result);
    return result;
}

#ifdef ENABLE_IPV4
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ipv4_revnat_tuple);
    __type(value, struct ipv4_revnat_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, LB4_REVERSE_NAT_SK_MAP_SIZE);
} LB4_REVERSE_NAT_SK_MAP __section_maps_btf;

static __always_inline int
sock4_update_revnat(struct bpf_sock_addr *ctx,
                    const struct lb4_backend *backend,
                    const struct lb4_key *orig_key,
                    __u16 rev_nat_id)
{
    struct ipv4_revnat_entry val = {}, *tmp;
    struct ipv4_revnat_tuple key = {};
    int ret = 0;

    bpf_printk("bpf_sock: sock4_update_revnat: backend addr=%x, port=%u, orig_key addr=%x, dport=%u, rev_nat_id=%u",
               backend->address, backend->port, orig_key->address, orig_key->dport, rev_nat_id);

    key.cookie = sock_local_cookie(ctx);
    key.address = backend->address;
    key.port = backend->port;
    bpf_printk("bpf_sock: sock4_update_revnat: key cookie=%llu, address=%x, port=%u",
               key.cookie, key.address, key.port);

    val.address = orig_key->address;
    val.port = orig_key->dport;
    val.rev_nat_index = rev_nat_id;
    bpf_printk("bpf_sock: sock4_update_revnat: val address=%x, port=%u, rev_nat_index=%u",
               val.address, val.port, val.rev_nat_index);

    tmp = map_lookup_elem(&LB4_REVERSE_NAT_SK_MAP, &key);
    if (!tmp || memcmp(tmp, &val, sizeof(val))) {
        bpf_printk("bpf_sock: sock4_update_revnat: Updating LB4_REVERSE_NAT_SK_MAP, tmp=%p", tmp);
        ret = map_update_elem(&LB4_REVERSE_NAT_SK_MAP, &key, &val, 0);
        bpf_printk("bpf_sock: sock4_update_revnat: map_update_elem returned ret=%d", ret);
    } else {
        bpf_printk("bpf_sock: sock4_update_revnat: No update needed, entry matches");
    }

    return ret;
}

static __always_inline bool
sock4_skip_xlate(struct lb4_service *svc, __be32 address)
{
    bool result;

    if (lb4_to_lb6_service(svc)) {
        bpf_printk("bpf_sock: sock4_skip_xlate: Service is IPv4-to-IPv6, returning true");
        return true;
    }

    if ((lb4_svc_is_external_ip(svc) && !is_defined(DISABLE_EXTERNAL_IP_MITIGATION)) ||
        (lb4_svc_is_hostport(svc) && !is_v4_loopback(address))) {
        struct remote_endpoint_info *info;

        bpf_printk("bpf_sock: sock4_skip_xlate: Checking external IP or hostport, address=%x", address);
        info = lookup_ip4_remote_endpoint(address, 0);
        if (!info || info->sec_identity != HOST_ID) {
            bpf_printk("bpf_sock: sock4_skip_xlate: No info or not HOST_ID, info=%p, sec_identity=%u, returning true",
                       info, info ? info->sec_identity : 0);
            return true;
        }
        bpf_printk("bpf_sock: sock4_skip_xlate: Found info, sec_identity=HOST_ID, continuing");
    }

    result = false;
    bpf_printk("bpf_sock: sock4_skip_xlate: Returning result=%d", result);
    return result;
}

#ifdef ENABLE_NODEPORT
static __always_inline struct lb4_service *
sock4_wildcard_lookup(struct lb4_key *key __maybe_unused,
                      const bool include_remote_hosts __maybe_unused,
                      const bool inv_match __maybe_unused,
                      const bool in_hostns __maybe_unused)
{
    struct remote_endpoint_info *info;
    __u16 service_port;

    bpf_printk("bpf_sock: sock4_wildcard_lookup: key address=%x, dport=%u, include_remote_hosts=%d, inv_match=%d, in_hostns=%d",
               key->address, key->dport, include_remote_hosts, inv_match, in_hostns);

    service_port = bpf_ntohs(key->dport);
    bpf_printk("bpf_sock: sock4_wildcard_lookup: service_port=%u", service_port);
    if ((service_port < NODEPORT_PORT_MIN ||
         service_port > NODEPORT_PORT_MAX) ^ inv_match) {
        bpf_printk("bpf_sock: sock4_wildcard_lookup: Port out of NodePort range, returning NULL");
        return NULL;
    }

    if (in_hostns && is_v4_loopback(key->address)) {
        bpf_printk("bpf_sock: sock4_wildcard_lookup: In hostns and loopback address, proceeding to wildcard lookup");
        goto wildcard_lookup;
    }

    info = lookup_ip4_remote_endpoint(key->address, 0);
    bpf_printk("bpf_sock: sock4_wildcard_lookup: lookup_ip4_remote_endpoint returned info=%p", info);
    if (info && (info->sec_identity == HOST_ID ||
                 (include_remote_hosts && identity_is_remote_node(info->sec_identity)))) {
        bpf_printk("bpf_sock: sock4_wildcard_lookup: Info matches HOST_ID or remote node, sec_identity=%u, proceeding to wildcard lookup",
                   info->sec_identity);
        goto wildcard_lookup;
    }

    bpf_printk("bpf_sock: sock4_wildcard_lookup: No matching conditions, returning NULL");
    return NULL;

wildcard_lookup:
    key->address = 0;
    bpf_printk("bpf_sock: sock4_wildcard_lookup: Set key address to 0 for wildcard lookup");
    struct lb4_service *svc = lb4_lookup_service(key, true);
    bpf_printk("bpf_sock: sock4_wildcard_lookup: lb4_lookup_service returned svc=%p", svc);
    return svc;
}
#endif /* ENABLE_NODEPORT */

static __always_inline struct lb4_service *
sock4_wildcard_lookup_full(struct lb4_key *key __maybe_unused,
                           const bool in_hostns __maybe_unused)
{
#ifdef ENABLE_NODEPORT
    bool loopback = is_v4_loopback(key->address);
    __u32 orig_addr = key->address;
    struct lb4_service *svc;

    bpf_printk("bpf_sock: sock4_wildcard_lookup_full: key address=%x, dport=%u, in_hostns=%d, loopback=%d",
               key->address, key->dport, in_hostns, loopback);

    svc = sock4_wildcard_lookup(key, true, false, in_hostns);
    bpf_printk("bpf_sock: sock4_wildcard_lookup_full: sock4_wildcard_lookup (NodePort) returned svc=%p", svc);
    if (svc && lb4_svc_is_nodeport(svc)) {
        bpf_printk("bpf_sock: sock4_wildcard_lookup_full: Service is NodePort, returning svc");
        return svc;
    }

    key->address = orig_addr;
    bpf_printk("bpf_sock: sock4_wildcard_lookup_full: Restored key address=%x", key->address);
    svc = sock4_wildcard_lookup(key, false, true, in_hostns);
    bpf_printk("bpf_sock: sock4_wildcard_lookup_full: sock4_wildcard_lookup (HostPort) returned svc=%p", svc);
    if (svc && lb4_svc_is_hostport(svc) && (!lb4_svc_is_loopback(svc) || loopback)) {
        bpf_printk("bpf_sock: sock4_wildcard_lookup_full: Service is HostPort, loopback condition met, returning svc");
        return svc;
    }

    bpf_printk("bpf_sock: sock4_wildcard_lookup_full: No matching service found, returning NULL");
    return NULL;
#else
    bpf_printk("bpf_sock: sock4_wildcard_lookup_full: ENABLE_NODEPORT not defined, returning NULL");
    return NULL;
#endif /* ENABLE_NODEPORT */
}

static __always_inline int
__sock4_xlate_fwd(struct bpf_sock_addr *ctx,
                  struct bpf_sock_addr *ctx_full,
                  const bool udp_only)
{
    union lb4_affinity_client_id id;
    const bool in_hostns = ctx_in_hostns(ctx_full, &id.client_cookie);
    struct lb4_backend *backend;
    struct lb4_service *svc;
    __u16 dst_port = ctx_dst_port(ctx);
    __u8 protocol = ctx_protocol(ctx);
    __u32 dst_ip = ctx->user_ip4;
    struct lb4_key key = {
        .address    = dst_ip,
        .dport      = dst_port,
#if defined(ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION)
        .proto      = protocol,
#endif
    }, orig_key = key;
    struct lb4_service *backend_slot;
    bool backend_from_affinity = false;
    __u32 backend_id = 0;
#ifdef ENABLE_L7_LB
    struct lb4_backend l7backend;
#endif

    bpf_printk("bpf_sock: __sock4_xlate_fwd: dst_ip=%x, dst_port=%u, protocol=%u, udp_only=%d",
               dst_ip, dst_port, protocol, udp_only);

    if (is_defined(ENABLE_SOCKET_LB_HOST_ONLY) && !in_hostns) {
        bpf_printk("bpf_sock: __sock4_xlate_fwd: ENABLE_SOCKET_LB_HOST_ONLY defined and not in hostns, returning -ENXIO");
        return -ENXIO;
    }

    if (!udp_only && !sock_proto_enabled(protocol)) {
        bpf_printk("bpf_sock: __sock4_xlate_fwd: Protocol not enabled, returning -ENOTSUP");
        return -ENOTSUP;
    }

    svc = lb4_lookup_service(&key, true);
    bpf_printk("bpf_sock: __sock4_xlate_fwd: lb4_lookup_service returned svc=%p", svc);
    if (!svc) {
        lb4_key_set_protocol(&key, protocol);
        bpf_printk("bpf_sock: __sock4_xlate_fwd: Restored key protocol=%u", key.proto);
        svc = sock4_wildcard_lookup_full(&key, in_hostns);
        bpf_printk("bpf_sock: __sock4_xlate_fwd: sock4_wildcard_lookup_full returned svc=%p", svc);
    }
    if (!svc) {
        bpf_printk("bpf_sock: __sock4_xlate_fwd: No service found, returning -ENXIO");
        return -ENXIO;
    }
    if (svc->count == 0 && !lb4_svc_is_l7loadbalancer(svc)) {
        bpf_printk("bpf_sock: __sock4_xlate_fwd: Service has no backends, returning -EHOSTUNREACH");
        return -EHOSTUNREACH;
    }

    bpf_printk("bpf_sock: __sock4_xlate_fwd: Sending pre-direction trace notification");
    send_trace_sock_notify4(ctx_full, XLATE_PRE_DIRECTION_FWD, dst_ip, bpf_ntohs(dst_port));

    if (sock4_skip_xlate(svc, orig_key.address)) {
        bpf_printk("bpf_sock: __sock4_xlate_fwd: Skipping translation, returning -EPERM");
        return -EPERM;
    }

#ifdef ENABLE_LOCAL_REDIRECT_POLICY
    if (lb4_svc_is_localredirect(svc) &&
        lb4_skip_xlate_from_ctx_to_svc(get_netns_cookie(ctx_full), orig_key.address, orig_key.dport)) {
        bpf_printk("bpf_sock: __sock4_xlate_fwd: Local redirect and skip translation, returning -ENXIO");
        return -ENXIO;
    }
#endif /* ENABLE_LOCAL_REDIRECT_POLICY */

#ifdef ENABLE_L7_LB
    if (lb4_svc_is_l7loadbalancer(svc)) {
        if (is_defined(HAVE_NETNS_COOKIE) && in_hostns) {
            l7backend.address = bpf_htonl(0x7f000001);
            l7backend.port = (__be16)svc->l7_lb_proxy_port;
            l7backend.proto = 0;
            l7backend.flags = 0;
            backend = &l7backend;
            bpf_printk("bpf_sock: __sock4_xlate_fwd: L7 LB in hostns, using proxy port=%u", svc->l7_lb_proxy_port);
            goto out;
        }
        bpf_printk("bpf_sock: __sock4_xlate_fwd: L7 LB, returning 0 for TC redirect");
        return 0;
    }
#endif /* ENABLE_L7_LB */

    if (lb4_svc_is_affinity(svc)) {
        bpf_printk("bpf_sock: __sock4_xlate_fwd: Service has affinity, looking up backend");
        backend_id = lb4_affinity_backend_id_by_netns(svc, &id);
        backend_from_affinity = true;
        bpf_printk("bpf_sock: __sock4_xlate_fwd: Affinity backend_id=%u", backend_id);

        if (backend_id != 0) {
            backend = __lb4_lookup_backend(backend_id);
            bpf_printk("bpf_sock: __sock4_xlate_fwd: __lb4_lookup_backend returned backend=%p", backend);
            if (!backend) {
                backend_id = 0;
                bpf_printk("bpf_sock: __sock4_xlate_fwd: Backend not found, resetting backend_id");
            }
            barrier();
        }
    }

    if (backend_id == 0) {
        backend_from_affinity = false;
        key.backend_slot = (sock_select_slot(ctx_full) % svc->count) + 1;
        bpf_printk("bpf_sock: __sock4_xlate_fwd: No affinity, selected backend_slot=%u", key.backend_slot);
        backend_slot = __lb4_lookup_backend_slot(&key);
        bpf_printk("bpf_sock: __sock4_xlate_fwd: __lb4_lookup_backend_slot returned backend_slot=%p", backend_slot);
        if (!backend_slot) {
            bpf_printk("bpf_sock: __sock4_xlate_fwd: No backend slot, updating metrics and returning -EHOSTUNREACH");
            update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND_SLOT);
            return -EHOSTUNREACH;
        }

        backend_id = backend_slot->backend_id;
        backend = __lb4_lookup_backend(backend_id);
        bpf_printk("bpf_sock: __sock4_xlate_fwd: Backend_id=%u, backend=%p", backend_id, backend);
    }

    if (!backend) {
        bpf_printk("bpf_sock: __sock4_xlate_fwd: No backend found, updating metrics and returning -EHOSTUNREACH");
        update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
        return -EHOSTUNREACH;
    }
    barrier();

    if (lb4_svc_is_affinity(svc) && !backend_from_affinity) {
        bpf_printk("bpf_sock: __sock4_xlate_fwd: Updating affinity with backend_id=%u", backend_id);
        lb4_update_affinity_by_netns(svc, &id, backend_id);
    }

    bpf_printk("bpf_sock: __sock4_xlate_fwd: Sending post-direction trace notification, backend addr=%x, port=%u",
               backend->address, bpf_ntohs(backend->port));
    send_trace_sock_notify4(ctx_full, XLATE_POST_DIRECTION_FWD, backend->address, bpf_ntohs(backend->port));

#ifdef ENABLE_L7_LB
out:
#endif
    bpf_printk("bpf_sock: __sock4_xlate_fwd: Updating reverse NAT");
    int ret = sock4_update_revnat(ctx_full, backend, &orig_key, svc->rev_nat_index);
    if (ret < 0) {
        bpf_printk("bpf_sock: __sock4_xlate_fwd: sock4_update_revnat failed, ret=%d, updating metrics", ret);
        update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
        return -ENOMEM;
    }

    bpf_printk("bpf_sock: __sock4_xlate_fwd: Setting user_ip4=%x, port=%u", backend->address, backend->port);
    ctx->user_ip4 = backend->address;
    ctx_set_port(ctx, backend->port);

    bpf_printk("bpf_sock: __sock4_xlate_fwd: Returning 0");
    return 0;
}

__section("cgroup/connect4")
int cil_sock4_connect(struct bpf_sock_addr *ctx)
{
    int err;

    bpf_printk("bpf_sock: cil_sock4_connect: Entering, user_ip4=%x, user_port=%u",
               ctx->user_ip4, ctx->user_port);

#ifdef ENABLE_HEALTH_CHECK
    if (sock_is_health_check(ctx)) {
        bpf_printk("bpf_sock: cil_sock4_connect: Health check detected, returning SYS_PROCEED");
        return SYS_PROCEED;
    }
#endif /* ENABLE_HEALTH_CHECK */

    bpf_printk("bpf_sock: cil_sock4_connect: Calling __sock4_xlate_fwd");
    err = __sock4_xlate_fwd(ctx, ctx, false);
    bpf_printk("bpf_sock: cil_sock4_connect: __sock4_xlate_fwd returned err=%d", err);
    if (err == -EHOSTUNREACH || err == -ENOMEM) {
        bpf_printk("bpf_sock: cil_sock4_connect: Error, setting retval and returning SYS_REJECT");
        try_set_retval(err);
        return SYS_REJECT;
    }

    bpf_printk("bpf_sock: cil_sock4_connect: Returning SYS_PROCEED");
    return SYS_PROCEED;
}

#ifdef ENABLE_NODEPORT
static __always_inline int
__sock4_post_bind(struct bpf_sock *ctx,
                  struct bpf_sock *ctx_full)
{
    __u8 protocol = ctx_protocol(ctx);
    struct lb4_service *svc;
    struct lb4_key key = {
        .address    = ctx->src_ip4,
        .dport      = ctx_src_port(ctx),
#if defined(ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION)
        .proto      = protocol,
#endif
    };

    bpf_printk("bpf_sock: __sock4_post_bind: src_ip4=%x, src_port=%u, protocol=%u",
               ctx->src_ip4, ctx_src_port(ctx), protocol);

    if (!sock_proto_enabled(protocol) || !ctx_in_hostns(ctx_full, NULL)) {
        bpf_printk("bpf_sock: __sock4_post_bind: Protocol not enabled or not in hostns, returning 0");
        return 0;
    }

    svc = lb4_lookup_service(&key, true);
    bpf_printk("bpf_sock: __sock4_post_bind: lb4_lookup_service returned svc=%p", svc);
    if (!svc) {
        lb4_key_set_protocol(&key, protocol);
        bpf_printk("bpf_sock: __sock4_post_bind: Restored key protocol=%u", key.proto);
        svc = sock4_wildcard_lookup(&key, false, false, true);
        bpf_printk("bpf_sock: __sock4_post_bind: sock4_wildcard_lookup returned svc=%p", svc);
    }

    if (svc && (lb4_svc_is_nodeport(svc) ||
                lb4_svc_is_external_ip(svc) ||
                lb4_svc_is_loadbalancer(svc)) &&
        !lb4_svc_is_l7loadbalancer(svc)) {
        bpf_printk("bpf_sock: __sock4_post_bind: Service conflict (NodePort/ExternalIP/LoadBalancer), returning -EADDRINUSE");
        return -EADDRINUSE;
    }

    bpf_printk("bpf_sock: __sock4_post_bind: No conflict, returning 0");
    return 0;
}

__section("cgroup/post_bind4")
int cil_sock4_post_bind(struct bpf_sock *ctx)
{
    int err;

    bpf_printk("bpf_sock: cil_sock4_post_bind: Entering, src_ip4=%x", ctx->src_ip4);

    err = __sock4_post_bind(ctx, ctx);
    bpf_printk("bpf_sock: cil_sock4_post_bind: __sock4_post_bind returned err=%d", err);
    if (err < 0) {
        bpf_printk("bpf_sock: cil_sock4_post_bind: Error, setting retval and returning SYS_REJECT");
        try_set_retval(err);
        return SYS_REJECT;
    }

    bpf_printk("bpf_sock: cil_sock4_post_bind: Returning SYS_PROCEED");
    return SYS_PROCEED;
}
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_HEALTH_CHECK
static __always_inline void
sock4_auto_bind(struct bpf_sock_addr *ctx)
{
    bpf_printk("bpf_sock: sock4_auto_bind: Setting user_ip4=0, port=0");
    ctx->user_ip4 = 0;
    ctx_set_port(ctx, 0);
}

static __always_inline int
__sock4_pre_bind(struct bpf_sock_addr *ctx,
                 struct bpf_sock_addr *ctx_full)
{
    __sock_cookie key = get_socket_cookie(ctx_full);
    struct lb4_health val = {
        .peer = {
            .address    = ctx->user_ip4,
            .port       = ctx_dst_port(ctx),
            .proto      = ctx_protocol(ctx),
        },
    };
    int ret;

    bpf_printk("bpf_sock: __sock4_pre_bind: key=%llu, peer address=%x, port=%u, proto=%u",
               key, val.peer.address, val.peer.port, val.peer.proto);

    ret = map_update_elem(&LB4_HEALTH_MAP, &key, &val, 0);
    bpf_printk("bpf_sock: __sock4_pre_bind: map_update_elem returned ret=%d", ret);
    if (!ret) {
        bpf_printk("bpf_sock: __sock4_pre_bind: Map update successful, calling sock4_auto_bind");
        sock4_auto_bind(ctx);
    }

    return ret;
}

__section("cgroup/bind4")
int cil_sock4_pre_bind(struct bpf_sock_addr *ctx)
{
    int ret = SYS_PROCEED;

    bpf_printk("bpf_sock: cil_sock4_pre_bind: Entering, user_ip4=%x, user_port=%u",
               ctx->user_ip4, ctx->user_port);

    if (!sock_proto_enabled(ctx_protocol(ctx)) || !ctx_in_hostns(ctx, NULL)) {
        bpf_printk("bpf_sock: cil_sock4_pre_bind: Protocol not enabled or not in hostns, returning SYS_PROCEED");
        return ret;
    }

    if (sock_is_health_check(ctx) && __sock4_pre_bind(ctx, ctx)) {
        bpf_printk("bpf_sock: cil_sock4_pre_bind: Health check failed, setting retval and returning SYS_REJECT");
        try_set_retval(-ENOBUFS);
        ret = SYS_REJECT;
    }

    bpf_printk("bpf_sock: cil_sock4_pre_bind: Returning ret=%d", ret);
    return ret;
}
#endif /* ENABLE_HEALTH_CHECK */

static __always_inline int
__sock4_xlate_rev(struct bpf_sock_addr *ctx,
                  struct bpf_sock_addr *ctx_full)
{
    struct ipv4_revnat_entry *val;
    __u16 dst_port = ctx_dst_port(ctx);
    __u8 protocol = ctx_protocol(ctx);
    __u32 dst_ip = ctx->user_ip4;
    struct ipv4_revnat_tuple key = {
        .cookie     = sock_local_cookie(ctx_full),
        .address    = dst_ip,
        .port       = dst_port,
    };

    bpf_printk("bpf_sock: __sock4_xlate_rev: dst_ip=%x, dst_port=%u, protocol=%u, cookie=%llu",
               dst_ip, dst_port, protocol, key.cookie);

    bpf_printk("bpf_sock: __sock4_xlate_rev: Sending pre-direction trace notification");
    send_trace_sock_notify4(ctx_full, XLATE_PRE_DIRECTION_REV, dst_ip, bpf_ntohs(dst_port));

    val = map_lookup_elem(&LB4_REVERSE_NAT_SK_MAP, &key);
    bpf_printk("bpf_sock: __sock4_xlate_rev: map_lookup_elem returned val=%p", val);
    if (val) {
        struct lb4_service *svc;
        struct lb4_key svc_key = {
            .address    = val->address,
            .dport      = val->port,
#if defined(ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION)
            .proto      = protocol,
#endif
        };

        bpf_printk("bpf_sock: __sock4_xlate_rev: Looking up service with address=%x, dport=%u",
                   svc_key.address, svc_key.dport);
        svc = lb4_lookup_service(&svc_key, true);
        bpf_printk("bpf_sock: __sock4_xlate_rev: lb4_lookup_service returned svc=%p", svc);
        if (!svc) {
            lb4_key_set_protocol(&svc_key, protocol);
            bpf_printk("bpf_sock: __sock4_xlate_rev: Restored svc_key protocol=%u", svc_key.proto);
            svc = sock4_wildcard_lookup_full(&svc_key, ctx_in_hostns(ctx_full, NULL));
            bpf_printk("bpf_sock: __sock4_xlate_rev: sock4_wildcard_lookup_full returned svc=%p", svc);
        }

        if (!svc || svc->rev_nat_index != val->rev_nat_index ||
            (svc->count == 0 && !lb4_svc_is_l7loadbalancer(svc))) {
            bpf_printk("bpf_sock: __sock4_xlate_rev: Invalid service or stale entry, deleting map entry");
            map_delete_elem(&LB4_REVERSE_NAT_SK_MAP, &key);
            update_metrics(0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);
            return -ENOENT;
        }

        bpf_printk("bpf_sock: __sock4_xlate_rev: Setting user_ip4=%x, port=%u", val->address, val->port);
        ctx->user_ip4 = val->address;
        ctx_set_port(ctx, val->port);
        bpf_printk("bpf_sock: __sock4_xlate_rev: Sending post-direction trace notification");
        send_trace_sock_notify4(ctx_full, XLATE_POST_DIRECTION_REV, val->address, bpf_ntohs(val->port));
        return 0;
    }

    bpf_printk("bpf_sock: __sock4_xlate_rev: No reverse NAT entry found, returning -ENXIO");
    return -ENXIO;
}

__section("cgroup/sendmsg4")
int cil_sock4_sendmsg(struct bpf_sock_addr *ctx)
{
    int err;

    bpf_printk("bpf_sock: cil_sock4_sendmsg: Entering, user_ip4=%x, user_port=%u",
               ctx->user_ip4, ctx->user_port);

    err = __sock4_xlate_fwd(ctx, ctx, true);
    bpf_printk("bpf_sock: cil_sock4_sendmsg: __sock4_xlate_fwd returned err=%d", err);
    if (err == -EHOSTUNREACH || err == -ENOMEM) {
        bpf_printk("bpf_sock: cil_sock4_sendmsg: Error, setting retval and returning SYS_REJECT");
        try_set_retval(err);
        return SYS_REJECT;
    }

    bpf_printk("bpf_sock: cil_sock4_sendmsg: Returning SYS_PROCEED");
    return SYS_PROCEED;
}

__section("cgroup/recvmsg4")
int cil_sock4_recvmsg(struct bpf_sock_addr *ctx)
{
    bpf_printk("bpf_sock: cil_sock4_recvmsg: Entering, user_ip4=%x, user_port=%u",
               ctx->user_ip4, ctx->user_port);

    int err = __sock4_xlate_rev(ctx, ctx);
    bpf_printk("bpf_sock: cil_sock4_recvmsg: __sock4_xlate_rev returned err=%d", err);

    bpf_printk("bpf_sock: cil_sock4_recvmsg: Returning SYS_PROCEED");
    return SYS_PROCEED;
}

#ifdef ENABLE_SOCKET_LB_PEER
__section("cgroup/getpeername4")
int cil_sock4_getpeername(struct bpf_sock_addr *ctx)
{
    bpf_printk("bpf_sock: cil_sock4_getpeername: Entering, user_ip4=%x, user_port=%u",
               ctx->user_ip4, ctx->user_port);

    int err = __sock4_xlate_rev(ctx, ctx);
    bpf_printk("bpf_sock: cil_sock4_getpeername: __sock4_xlate_rev returned err=%d", err);

    bpf_printk("bpf_sock: cil_sock4_getpeername: Returning SYS_PROCEED");
    return SYS_PROCEED;
}
#endif /* ENABLE_SOCKET_LB_PEER */

#endif /* ENABLE_IPV4 */

#if defined(ENABLE_IPV6) || defined(ENABLE_IPV4)
#ifdef ENABLE_IPV6
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ipv6_revnat_tuple);
    __type(value, struct ipv6_revnat_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, LB6_REVERSE_NAT_SK_MAP_SIZE);
} LB6_REVERSE_NAT_SK_MAP __section_maps_btf;

static __always_inline int
sock6_update_revnat(struct bpf_sock_addr *ctx,
                    const struct lb6_backend *backend,
                    const struct lb6_key *orig_key,
                    __u16 rev_nat_index)
{
    struct ipv6_revnat_entry val = {}, *tmp;
    struct ipv6_revnat_tuple key = {};
    int ret = 0;

    bpf_printk("bpf_sock: sock6_update_revnat: backend port=%u, orig_key dport=%u, rev_nat_index=%u",
               backend->port, orig_key->dport, rev_nat_index);
    bpf_printk("bpf_sock: sock6_update_revnat: backend address=%x:%x:%x:%x",
               backend->address.p1, backend->address.p2, backend->address.p3, backend->address.p4);

    key.cookie = sock_local_cookie(ctx);
    key.address = backend->address;
    key.port = backend->port;
    bpf_printk("bpf_sock: sock6_update_revnat: key cookie=%llu, port=%u", key.cookie, key.port);
    bpf_printk("bpf_sock: sock6_update_revnat: key address=%x:%x:%x:%x",
               key.address.p1, key.address.p2, key.address.p3, key.address.p4);

    val.address = orig_key->address;
    val.port = orig_key->dport;
    val.rev_nat_index = rev_nat_index;
    bpf_printk("bpf_sock: sock6_update_revnat: val address=%x:%x:%x:%x, port=%u, rev_nat_index=%u",
               val.address.p1, val.address.p2, val.address.p3, val.address.p4, val.port, val.rev_nat_index);

    tmp = map_lookup_elem(&LB6_REVERSE_NAT_SK_MAP, &key);
    bpf_printk("bpf_sock: sock6_update_revnat: map_lookup_elem returned tmp=%p", tmp);
    if (!tmp || memcmp(tmp, &val, sizeof(val))) {
        bpf_printk("bpf_sock: sock6_update_revnat: Updating LB6_REVERSE_NAT_SK_MAP");
        ret = map_update_elem(&LB6_REVERSE_NAT_SK_MAP, &key, &val, 0);
        bpf_printk("bpf_sock: sock6_update_revnat: map_update_elem returned ret=%d", ret);
    } else {
        bpf_printk("bpf_sock: sock6_update_revnat: No update needed, entry matches");
    }

    return ret;
}

static __always_inline void
ctx_get_v6_address(const struct bpf_sock_addr *ctx,
                   union v6addr *addr);

#endif /* ENABLE_IPV6 */

static __always_inline void
ctx_get_v6_address(const struct bpf_sock_addr *ctx,
                   union v6addr *addr)
{
    bpf_printk("bpf_sock: ctx_get_v6_address: Getting IPv6 address from ctx");
    addr->p1 = ctx->user_ip6[0];
    barrier();
    addr->p2 = ctx->user_ip6[1];
    barrier();
    addr->p3 = ctx->user_ip6[2];
    barrier();
    addr->p4 = ctx->user_ip6[3];
    barrier();
    bpf_printk("bpf_sock: ctx_get_v6_address: Address=%x:%x:%x:%x",
               addr->p1, addr->p2, addr->p3, addr->p4);
}

#ifdef ENABLE_NODEPORT
static __always_inline void
ctx_get_v6_src_address(const struct bpf_sock *ctx,
                       union v6addr *addr)
{
    bpf_printk("bpf_sock: ctx_get_v6_src_address: Getting IPv6 source address from ctx");
    addr->p1 = ctx->src_ip6[0];
    barrier();
    addr->p2 = ctx->src_ip6[1];
    barrier();
    addr->p3 = ctx->src_ip6[2];
    barrier();
    addr->p4 = ctx->src_ip6[3];
    barrier();
    bpf_printk("bpf_sock: ctx_get_v6_src_address: Source address=%x:%x:%x:%x",
               addr->p1, addr->p2, addr->p3, addr->p4);
}
#endif /* ENABLE_NODEPORT */

static __always_inline void
ctx_set_v6_address(struct bpf_sock_addr *ctx,
                   const union v6addr *addr)
{
    bpf_printk("bpf_sock: ctx_set_v6_address: Setting IPv6 address=%x:%x:%x:%x",
               addr->p1, addr->p2, addr->p3, addr->p4);
    ctx->user_ip6[0] = addr->p1;
    barrier();
    ctx->user_ip6[1] = addr->p2;
    barrier();
    ctx->user_ip6[2] = addr->p3;
    barrier();
    ctx->user_ip6[3] = addr->p4;
    barrier();
}

static __always_inline __maybe_unused bool
sock6_skip_xlate(struct lb6_service *svc, const union v6addr *address)
{
    bool result;

    bpf_printk("bpf_sock: sock6_skip_xlate: address=%x:%x:%x:%x",
               address->p1, address->p2, address->p3, address->p4);

    if (lb6_to_lb4_service(svc)) {
        bpf_printk("bpf_sock: sock6_skip_xlate: Service is IPv6-to-IPv4, returning true");
        return true;
    }

    if ((lb6_svc_is_external_ip(svc) && !is_defined(DISABLE_EXTERNAL_IP_MITIGATION)) ||
        (lb6_svc_is_hostport(svc) && !is_v6_loopback(address))) {
        struct remote_endpoint_info *info;

        bpf_printk("bpf_sock: sock6_skip_xlate: Checking external IP or hostport");
        info = lookup_ip6_remote_endpoint(address, 0);
        bpf_printk("bpf_sock: sock6_skip_xlate: lookup_ip6_remote_endpoint returned info=%p", info);
        if (!info || info->sec_identity != HOST_ID) {
            bpf_printk("bpf_sock: sock6_skip_xlate: No info or not HOST_ID, sec_identity=%u, returning true",
                       info ? info->sec_identity : 0);
            return true;
        }
        bpf_printk("bpf_sock: sock6_skip_xlate: Found info, sec_identity=HOST_ID, continuing");
    }

    result = false;
    bpf_printk("bpf_sock: sock6_skip_xlate: Returning result=%d", result);
    return result;
}

#ifdef ENABLE_NODEPORT
static __always_inline __maybe_unused struct lb6_service *
sock6_wildcard_lookup(struct lb6_key *key __maybe_unused,
                      const bool include_remote_hosts __maybe_unused,
                      const bool inv_match __maybe_unused,
                      const bool in_hostns __maybe_unused)
{
    struct remote_endpoint_info *info;
    __u16 service_port;

    bpf_printk("bpf_sock: sock6_wildcard_lookup: key dport=%u, address=%x:%x:%x:%x",
               key->dport, key->address.p1, key->address.p2, key->address.p3, key->address.p4);
    bpf_printk("bpf_sock: sock6_wildcard_lookup: include_remote_hosts=%d, inv_match=%d, in_hostns=%d",
               include_remote_hosts, inv_match, in_hostns);

    service_port = bpf_ntohs(key->dport);
    bpf_printk("bpf_sock: sock6_wildcard_lookup: service_port=%u", service_port);
    if ((service_port < NODEPORT_PORT_MIN ||
         service_port > NODEPORT_PORT_MAX) ^ inv_match) {
        bpf_printk("bpf_sock: sock6_wildcard_lookup: Port out of NodePort range, returning NULL");
        return NULL;
    }

    if (in_hostns && is_v6_loopback(&key->address)) {
        bpf_printk("bpf_sock: sock6_wildcard_lookup: In hostns and loopback address, proceeding to wildcard lookup");
        goto wildcard_lookup;
    }

    info = lookup_ip6_remote_endpoint(&key->address, 0);
    bpf_printk("bpf_sock: sock6_wildcard_lookup: lookup_ip6_remote_endpoint returned info=%p", info);
    if (info && (info->sec_identity == HOST_ID ||
                 (include_remote_hosts && identity_is_remote_node(info->sec_identity)))) {
        bpf_printk("bpf_sock: sock6_wildcard_lookup: Info matches HOST_ID or remote node, sec_identity=%u, proceeding to wildcard lookup",
                   info->sec_identity);
        goto wildcard_lookup;
    }

    bpf_printk("bpf_sock: sock6_wildcard_lookup: No matching conditions, returning NULL");
    return NULL;

wildcard_lookup:
    bpf_printk("bpf_sock: sock6_wildcard_lookup: Setting key address to 0 for wildcard lookup");
    memset(&key->address, 0, sizeof(key->address));
    struct lb6_service *svc = lb6_lookup_service(key, true);
    bpf_printk("bpf_sock: sock6_wildcard_lookup: lb6_lookup_service returned svc=%p", svc);
    return svc;
}
#endif /* ENABLE_NODEPORT */

static __always_inline __maybe_unused struct lb6_service *
sock6_wildcard_lookup_full(struct lb6_key *key __maybe_unused,
                           const bool in_hostns __maybe_unused)
{
#ifdef ENABLE_NODEPORT
    bool loopback = is_v6_loopback(&key->address);
    union v6addr orig_address;
    struct lb6_service *svc;

    bpf_printk("bpf_sock: sock6_wildcard_lookup_full: key dport=%u, address=%x:%x:%x:%x, in_hostns=%d",
               key->dport, key->address.p1, key->address.p2, key->address.p3, key->address.p4, in_hostns);
    bpf_printk("bpf_sock: sock6_wildcard_lookup_full: loopback=%d", loopback);

    memcpy(&orig_address, &key->address, sizeof(orig_address));
    bpf_printk("bpf_sock: sock6_wildcard_lookup_full: Saved orig_address=%x:%x:%x:%x",
               orig_address.p1, orig_address.p2, orig_address.p3, orig_address.p4);

    svc = sock6_wildcard_lookup(key, true, false, in_hostns);
    bpf_printk("bpf_sock: sock6_wildcard_lookup_full: sock6_wildcard_lookup (NodePort) returned svc=%p", svc);
    if (svc && lb6_svc_is_nodeport(svc)) {
        bpf_printk("bpf_sock: sock6_wildcard_lookup_full: Service is NodePort, returning svc");
        return svc;
    }

    bpf_printk("bpf_sock: sock6_wildcard_lookup_full: Restoring key address");
    memcpy(&key->address, &orig_address, sizeof(orig_address));
    svc = sock6_wildcard_lookup(key, false, true, in_hostns);
    bpf_printk("bpf_sock: sock6_wildcard_lookup_full: sock6_wildcard_lookup (HostPort) returned svc=%p", svc);
    if (svc && lb6_svc_is_hostport(svc) && (!lb6_svc_is_loopback(svc) || loopback)) {
        bpf_printk("bpf_sock: sock6_wildcard_lookup_full: Service is HostPort, loopback condition met, returning svc");
        return svc;
    }

    bpf_printk("bpf_sock: sock6_wildcard_lookup_full: No matching service found, returning NULL");
    return NULL;
#else
    bpf_printk("bpf_sock: sock6_wildcard_lookup_full: ENABLE_NODEPORT not defined, returning NULL");
    return NULL;
#endif /* ENABLE_NODEPORT */
}

static __always_inline
int sock6_xlate_v4_in_v6(struct bpf_sock_addr *ctx __maybe_unused,
                         const bool udp_only __maybe_unused)
{
#ifdef ENABLE_IPV4
    struct bpf_sock_addr fake_ctx;
    union v6addr addr6;
    int ret;

    bpf_printk("bpf_sock: sock6_xlate_v4_in_v6: udp_only=%d", udp_only);
    ctx_get_v6_address(ctx, &addr6);
    if (!is_v4_in_v6(&addr6)) {
        bpf_printk("bpf_sock: sock6_xlate_v4_in_v6: Not a v4-in-v6 address, returning -ENXIO");
        return -ENXIO;
    }

    bpf_printk("bpf_sock: sock6_xlate_v4_in_v6: Creating fake_ctx with user_ip4=%x, user_port=%u, protocol=%u",
               addr6.p4, ctx_dst_port(ctx), ctx_protocol(ctx));
    memset(&fake_ctx, 0, sizeof(fake_ctx));
    fake_ctx.protocol  = ctx_protocol(ctx);
    fake_ctx.user_ip4  = addr6.p4;
    fake_ctx.user_port = ctx_dst_port(ctx);

    ret = __sock4_xlate_fwd(&fake_ctx, ctx, udp_only);
    bpf_printk("bpf_sock: sock6_xlate_v4_in_v6: __sock4_xlate_fwd returned ret=%d", ret);
    if (ret < 0) {
        bpf_printk("bpf_sock: sock6_xlate_v4_in_v6: Returning ret=%d", ret);
        return ret;
    }

    bpf_printk("bpf_sock: sock6_xlate_v4_in_v6: Building v4-in-v6 address with user_ip4=%x", fake_ctx.user_ip4);
    build_v4_in_v6(&addr6, fake_ctx.user_ip4);
    ctx_set_v6_address(ctx, &addr6);
    ctx_set_port(ctx, (__u16)fake_ctx.user_port);

    bpf_printk("bpf_sock: sock6_xlate_v4_in_v6: Returning 0");
    return 0;
#else
    bpf_printk("bpf_sock: sock6_xlate_v4_in_v6: ENABLE_IPV4 not defined, returning -ENXIO");
    return -ENXIO;
#endif /* ENABLE_IPV4 */
}

#ifdef ENABLE_NODEPORT
static __always_inline int
sock6_post_bind_v4_in_v6(struct bpf_sock *ctx __maybe_unused)
{
#ifdef ENABLE_IPV4
    struct bpf_sock fake_ctx;
    union v6addr addr6;

    bpf_printk("bpf_sock: sock6_post_bind_v4_in_v6: Entering");
    ctx_get_v6_src_address(ctx, &addr6);
    if (!is_v4_in_v6(&addr6)) {
        bpf_printk("bpf_sock: sock6_post_bind_v4_in_v6: Not a v4-in-v6 address, returning 0");
        return 0;
    }

    bpf_printk("bpf_sock: sock6_post_bind_v4_in_v6: Creating fake_ctx with src_ip4=%x, src_port=%u, protocol=%u",
               addr6.p4, ctx->src_port, ctx_protocol(ctx));
    memset(&fake_ctx, 0, sizeof(fake_ctx));
    fake_ctx.protocol = ctx_protocol(ctx);
    fake_ctx.src_ip4  = addr6.p4;
    fake_ctx.src_port = ctx->src_port;

    int ret = __sock4_post_bind(&fake_ctx, ctx);
    bpf_printk("bpf_sock: sock6_post_bind_v4_in_v6: __sock4_post_bind returned ret=%d", ret);
    return ret;
#else
    bpf_printk("bpf_sock: sock6_post_bind_v4_in_v6: ENABLE_IPV4 not defined, returning 0");
    return 0;
#endif /* ENABLE_IPV4 */
}

static __always_inline int
__sock6_post_bind(struct bpf_sock *ctx)
{
    __u8 protocol = ctx_protocol(ctx);
    struct lb6_service *svc;
    struct lb6_key key = {
        .dport      = ctx_src_port(ctx),
#if defined(ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION)
        .proto      = protocol,
#endif
    };

    bpf_printk("bpf_sock: __sock6_post_bind: protocol=%u, dport=%u", protocol, key.dport);

    if (!sock_proto_enabled(protocol) || !ctx_in_hostns(ctx, NULL)) {
        bpf_printk("bpf_sock: __sock6_post_bind: Protocol not enabled or not in hostns, returning 0");
        return 0;
    }

    ctx_get_v6_src_address(ctx, &key.address);
    svc = lb6_lookup_service(&key, true);
    bpf_printk("bpf_sock: __sock6_post_bind: lb6_lookup_service returned svc=%p", svc);
    if (!svc) {
        bpf_printk("bpf_sock: __sock6_post_bind: Restoring key protocol=%u", protocol);
        lb6_key_set_protocol(&key, protocol);
        svc = sock6_wildcard_lookup(&key, false, false, true);
        bpf_printk("bpf_sock: __sock6_post_bind: sock6_wildcard_lookup returned svc=%p", svc);
        if (!svc) {
            bpf_printk("bpf_sock: __sock6_post_bind: No service found, calling sock6_post_bind_v4_in_v6");
            return sock6_post_bind_v4_in_v6(ctx);
        }
    }

    if (svc && (lb6_svc_is_nodeport(svc) ||
                lb6_svc_is_external_ip(svc) ||
                lb6_svc_is_loadbalancer(svc)) &&
        !lb6_svc_is_l7loadbalancer(svc)) {
        bpf_printk("bpf_sock: __sock6_post_bind: Service conflict (NodePort/ExternalIP/LoadBalancer), returning -EADDRINUSE");
        return -EADDRINUSE;
    }

    bpf_printk("bpf_sock: __sock6_post_bind: No conflict, returning 0");
    return 0;
}

__section("cgroup/post_bind6")
int cil_sock6_post_bind(struct bpf_sock *ctx)
{
    int err;

    bpf_printk("bpf_sock: cil_sock6_post_bind: Entering, src_port=%u", ctx->src_port);
    err = __sock6_post_bind(ctx);
    bpf_printk("bpf_sock: cil_sock6_post_bind: __sock6_post_bind returned err=%d", err);
    if (err < 0) {
        bpf_printk("bpf_sock: cil_sock6_post_bind: Error, setting retval and returning SYS_REJECT");
        try_set_retval(err);
        return SYS_REJECT;
    }

    bpf_printk("bpf_sock: cil_sock6_post_bind: Returning SYS_PROCEED");
    return SYS_PROCEED;
}
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_HEALTH_CHECK
static __always_inline int
sock6_pre_bind_v4_in_v6(struct bpf_sock_addr *ctx __maybe_unused)
{
#ifdef ENABLE_IPV4
    struct bpf_sock_addr fake_ctx;
    union v6addr addr6;
    int ret;

    bpf_printk("bpf_sock: sock6_pre_bind_v4_in_v6: Entering");
    ctx_get_v6_address(ctx, &addr6);

    bpf_printk("bpf_sock: sock6_pre_bind_v4_in_v6: Creating fake_ctx with user_ip4=%x, user_port=%u, protocol=%u",
               addr6.p4, ctx_dst_port(ctx), ctx_protocol(ctx));
    memset(&fake_ctx, 0, sizeof(fake_ctx));
    fake_ctx.protocol  = ctx_protocol(ctx);
    fake_ctx.user_ip4  = addr6.p4;
    fake_ctx.user_port = ctx_dst_port(ctx);

    ret = __sock4_pre_bind(&fake_ctx, ctx);
    bpf_printk("bpf_sock: sock6_pre_bind_v4_in_v6: __sock4_pre_bind returned ret=%d", ret);
    if (ret < 0) {
        bpf_printk("bpf_sock: sock6_pre_bind_v4_in_v6: Returning ret=%d", ret);
        return ret;
    }

    bpf_printk("bpf_sock: sock6_pre_bind_v4_in_v6: Building v4-in-v6 address with user_ip4=%x", fake_ctx.user_ip4);
    build_v4_in_v6(&addr6, fake_ctx.user_ip4);
    ctx_set_v6_address(ctx, &addr6);
    ctx_set_port(ctx, (__u16)fake_ctx.user_port);

    bpf_printk("bpf_sock: sock6_pre_bind_v4_in_v6: Returning 0");
    return 0;
#else
    bpf_printk("bpf_sock: sock6_pre_bind_v4_in_v6: ENABLE_IPV4 not defined, returning 0");
    return 0;
#endif /* ENABLE_IPV4 */
}

#ifdef ENABLE_IPV6
static __always_inline void
sock6_auto_bind(struct bpf_sock_addr *ctx)
{
    union v6addr zero = {};

    bpf_printk("bpf_sock: sock6_auto_bind: Setting address to zero and port to 0");
    ctx_set_v6_address(ctx, &zero);
    ctx_set_port(ctx, 0);
}
#endif

static __always_inline int
__sock6_pre_bind(struct bpf_sock_addr *ctx)
{
    __sock_cookie key __maybe_unused;
    struct lb6_health val = {
        .peer = {
            .port       = ctx_dst_port(ctx),
            .proto      = ctx_protocol(ctx),
        },
    };
    int ret = 0;

    bpf_printk("bpf_sock: __sock6_pre_bind: port=%u, proto=%u", val.peer.port, val.peer.proto);
    ctx_get_v6_address(ctx, &val.peer.address);
    if (is_v4_in_v6(&val.peer.address)) {
        bpf_printk("bpf_sock: __sock6_pre_bind: v4-in-v6 address detected, calling sock6_pre_bind_v4_in_v6");
        return sock6_pre_bind_v4_in_v6(ctx);
    }

#ifdef ENABLE_IPV6
    key = get_socket_cookie(ctx);
    bpf_printk("bpf_sock: __sock6_pre_bind: key=%llu", key);
    ret = map_update_elem(&LB6_HEALTH_MAP, &key, &val, 0);
    bpf_printk("bpf_sock: __sock6_pre_bind: map_update_elem returned ret=%d", ret);
    if (!ret) {
        bpf_printk("bpf_sock: __sock6_pre_bind: Map update successful, calling sock6_auto_bind");
        sock6_auto_bind(ctx);
    }
#endif

    bpf_printk("bpf_sock: __sock6_pre_bind: Returning ret=%d", ret);
    return ret;
}

__section("cgroup/bind6")
int cil_sock6_pre_bind(struct bpf_sock_addr *ctx)
{
    int ret = SYS_PROCEED;

    bpf_printk("bpf_sock: cil_sock6_pre_bind: Entering, user_port=%u", ctx->user_port);
    if (!sock_proto_enabled(ctx_protocol(ctx)) || !ctx_in_hostns(ctx, NULL)) {
        bpf_printk("bpf_sock: cil_sock6_pre_bind: Protocol not enabled or not in hostns, returning SYS_PROCEED");
        return ret;
    }

    if (sock_is_health_check(ctx) && __sock6_pre_bind(ctx)) {
        bpf_printk("bpf_sock: cil_sock6_pre_bind: Health check failed, setting retval and returning SYS_REJECT");
        try_set_retval(-ENOBUFS);
        ret = SYS_REJECT;
    }

    bpf_printk("bpf_sock: cil_sock6_pre_bind: Returning ret=%d", ret);
    return ret;
}
#endif /* ENABLE_HEALTH_CHECK */

static __always_inline int
__sock6_xlate_fwd(struct bpf_sock_addr *ctx,
                  const bool udp_only)
{
#ifdef ENABLE_IPV6
    union lb6_affinity_client_id id;
    const bool in_hostns = ctx_in_hostns(ctx, &id.client_cookie);
    struct lb6_backend *backend;
    struct lb6_service *svc;
    __u16 dst_port = ctx_dst_port(ctx);
    __u8 protocol = ctx_protocol(ctx);
    struct lb6_key key = {
        .dport      = dst_port,
#if defined(ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION)
        .proto      = protocol,
#endif
    }, orig_key;
    struct lb6_service *backend_slot;
    bool backend_from_affinity = false;
    __u32 backend_id = 0;
#ifdef ENABLE_L7_LB
    struct lb6_backend l7backend;
#endif

    bpf_printk("bpf_sock: __sock6_xlate_fwd: dst_port=%u, protocol=%u, udp_only=%d", dst_port, protocol, udp_only);

    if (is_defined(ENABLE_SOCKET_LB_HOST_ONLY) && !in_hostns) {
        bpf_printk("bpf_sock: __sock6_xlate_fwd: ENABLE_SOCKET_LB_HOST_ONLY defined and not in hostns, returning -ENXIO");
        return -ENXIO;
    }

    if (!udp_only && !sock_proto_enabled(protocol)) {
        bpf_printk("bpf_sock: __sock6_xlate_fwd: Protocol not enabled, returning -ENOTSUP");
        return -ENOTSUP;
    }

    ctx_get_v6_address(ctx, &key.address);
    memcpy(&orig_key, &key, sizeof(key));
    bpf_printk("bpf_sock: __sock6_xlate_fwd: key address=%x:%x:%x:%x",
               key.address.p1, key.address.p2, key.address.p3, key.address.p4);

    svc = lb6_lookup_service(&key, true);
    bpf_printk("bpf_sock: __sock6_xlate_fwd: lb6_lookup_service returned svc=%p", svc);
    if (!svc) {
        bpf_printk("bpf_sock: __sock6_xlate_fwd: Restoring key protocol=%u", protocol);
        lb6_key_set_protocol(&key, protocol);
        svc = sock6_wildcard_lookup_full(&key, in_hostns);
        bpf_printk("bpf_sock: __sock6_xlate_fwd: sock6_wildcard_lookup_full returned svc=%p", svc);
    }
    if (!svc) {
        bpf_printk("bpf_sock: __sock6_xlate_fwd: No service found, calling sock6_xlate_v4_in_v6");
        return sock6_xlate_v4_in_v6(ctx, udp_only);
    }
    if (svc->count == 0 && !lb6_svc_is_l7loadbalancer(svc)) {
        bpf_printk("bpf_sock: __sock6_xlate_fwd: Service has no backends, returning -EHOSTUNREACH");
        return -EHOSTUNREACH;
    }

    bpf_printk("bpf_sock: __sock6_xlate_fwd: Sending pre-direction trace notification");
    send_trace_sock_notify6(ctx, XLATE_PRE_DIRECTION_FWD, &key.address, bpf_ntohs(dst_port));

    if (sock6_skip_xlate(svc, &orig_key.address)) {
        bpf_printk("bpf_sock: __sock6_xlate_fwd: Skipping translation, returning -EPERM");
        return -EPERM;
    }

#if defined(ENABLE_LOCAL_REDIRECT_POLICY) && defined(HAVE_NETNS_COOKIE)
    if (lb6_svc_is_localredirect(svc) &&
        lb6_skip_xlate_from_ctx_to_svc(get_netns_cookie(ctx), orig_key.address, orig_key.dport)) {
        bpf_printk("bpf_sock: __sock6_xlate_fwd: Local redirect and skip translation, returning -ENXIO");
        return -ENXIO;
    }
#endif /* ENABLE_LOCAL_REDIRECT_POLICY && HAVE_NETNS_COOKIE*/

#ifdef ENABLE_L7_LB
    if (lb6_svc_is_l7loadbalancer(svc)) {
        if (is_defined(HAVE_NETNS_COOKIE) && in_hostns) {
            union v6addr loopback = { .addr[15] = 1, };
            l7backend.address = loopback;
            l7backend.port = (__be16)svc->l7_lb_proxy_port;
            l7backend.proto = 0;
            l7backend.flags = 0;
            backend = &l7backend;
            bpf_printk("bpf_sock: __sock6_xlate_fwd: L7 LB in hostns, using proxy port=%u", svc->l7_lb_proxy_port);
            goto out;
        }
        bpf_printk("bpf_sock: __sock6_xlate_fwd: L7 LB, returning 0 for TC redirect");
        return 0;
    }
#endif /* ENABLE_L7_LB */

    if (lb6_svc_is_affinity(svc)) {
        bpf_printk("bpf_sock: __sock6_xlate_fwd: Service has affinity, looking up backend");
        backend_id = lb6_affinity_backend_id_by_netns(svc, &id);
        backend_from_affinity = true;
        bpf_printk("bpf_sock: __sock6_xlate_fwd: Affinity backend_id=%u", backend_id);

        if (backend_id != 0) {
            backend = __lb6_lookup_backend(backend_id);
            bpf_printk("bpf_sock: __sock6_xlate_fwd: __lb6_lookup_backend returned backend=%p", backend);
            if (!backend) {
                backend_id = 0;
                bpf_printk("bpf_sock: __sock6_xlate_fwd: Backend not found, resetting backend_id");
            }
            barrier();
        }
    }

    if (backend_id == 0) {
        backend_from_affinity = false;
        key.backend_slot = (sock_select_slot(ctx) % svc->count) + 1;
        bpf_printk("bpf_sock: __sock6_xlate_fwd: No affinity, selected backend_slot=%u", key.backend_slot);
        backend_slot = __lb6_lookup_backend_slot(&key);
        bpf_printk("bpf_sock: __sock6_xlate_fwd: __lb6_lookup_backend_slot returned backend_slot=%p", backend_slot);
        if (!backend_slot) {
            bpf_printk("bpf_sock: __sock6_xlate_fwd: No backend slot, updating metrics and returning -EHOSTUNREACH");
            update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND_SLOT);
            return -EHOSTUNREACH;
        }

        backend_id = backend_slot->backend_id;
        backend = __lb6_lookup_backend(backend_id);
        bpf_printk("bpf_sock: __sock6_xlate_fwd: backend_id=%u, backend=%p", backend_id, backend);
    }

    if (!backend) {
        bpf_printk("bpf_sock: __sock6_xlate_fwd: No backend found, updating metrics and returning -EHOSTUNREACH");
        update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
        return -EHOSTUNREACH;
    }
    barrier();

    if (lb6_svc_is_affinity(svc) && !backend_from_affinity) {
        bpf_printk("bpf_sock: __sock6_xlate_fwd: Updating affinity with backend_id=%u", backend_id);
        lb6_update_affinity_by_netns(svc, &id, backend_id);
    }

    bpf_printk("bpf_sock: __sock6_xlate_fwd: Sending post-direction trace notification, backend port=%u", bpf_ntohs(backend->port));
    send_trace_sock_notify6(ctx, XLATE_POST_DIRECTION_FWD, &backend->address, bpf_ntohs(backend->port));

#ifdef ENABLE_L7_LB
out:
#endif
    bpf_printk("bpf_sock: __sock6_xlate_fwd: Updating reverse NAT");
    int ret = sock6_update_revnat(ctx, backend, &orig_key, svc->rev_nat_index);
    if (ret < 0) {
        bpf_printk("bpf_sock: __sock6_xlate_fwd: sock6_update_revnat failed, ret=%d, updating metrics", ret);
        update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
        return -ENOMEM;
    }

    bpf_printk("bpf_sock: __sock6_xlate_fwd: Setting address and port");
    ctx_set_v6_address(ctx, &backend->address);
    ctx_set_port(ctx, backend->port);

    bpf_printk("bpf_sock: __sock6_xlate_fwd: Returning 0");
    return 0;
#else
    bpf_printk("bpf_sock: __sock6_xlate_fwd: ENABLE_IPV6 not defined, calling sock6_xlate_v4_in_v6");
    return sock6_xlate_v4_in_v6(ctx, udp_only);
#endif /* ENABLE_IPV6 */
}

__section("cgroup/connect6")
int cil_sock6_connect(struct bpf_sock_addr *ctx)
{
    int err;

    bpf_printk("bpf_sock: cil_sock6_connect: Entering, user_port=%u", ctx->user_port);

#ifdef ENABLE_HEALTH_CHECK
    if (sock_is_health_check(ctx)) {
        bpf_printk("bpf_sock: cil_sock6_connect: Health check detected, returning SYS_PROCEED");
        return SYS_PROCEED;
    }
#endif /* ENABLE_HEALTH_CHECK */

    err = __sock6_xlate_fwd(ctx, false);
    bpf_printk("bpf_sock: cil_sock6_connect: __sock6_xlate_fwd returned err=%d", err);
    if (err == -EHOSTUNREACH || err == -ENOMEM) {
        bpf_printk("bpf_sock: cil_sock6_connect: Error, setting retval and returning SYS_REJECT");
        try_set_retval(err);
        return SYS_REJECT;
    }

    bpf_printk("bpf_sock: cil_sock6_connect: Returning SYS_PROCEED");
    return SYS_PROCEED;
}

static __always_inline int
sock6_xlate_rev_v4_in_v6(struct bpf_sock_addr *ctx __maybe_unused)
{
#ifdef ENABLE_IPV4
    struct bpf_sock_addr fake_ctx;
    union v6addr addr6;
    int ret;

    bpf_printk("bpf_sock: sock6_xlate_rev_v4_in_v6: Entering");
    ctx_get_v6_address(ctx, &addr6);
    if (!is_v4_in_v6(&addr6)) {
        bpf_printk("bpf_sock: sock6_xlate_rev_v4_in_v6: Not a v4-in-v6 address, returning -ENXIO");
        return -ENXIO;
    }

    bpf_printk("bpf_sock: sock6_xlate_rev_v4_in_v6: Creating fake_ctx with user_ip4=%x, user_port=%u, protocol=%u",
               addr6.p4, ctx_dst_port(ctx), ctx_protocol(ctx));
    memset(&fake_ctx, 0, sizeof(fake_ctx));
    fake_ctx.protocol  = ctx_protocol(ctx);
    fake_ctx.user_ip4  = addr6.p4;
    fake_ctx.user_port = ctx_dst_port(ctx);

    ret = __sock4_xlate_rev(&fake_ctx, ctx);
    bpf_printk("bpf_sock: sock6_xlate_rev_v4_in_v6: __sock4_xlate_rev returned ret=%d", ret);
    if (ret < 0) {
        bpf_printk("bpf_sock: sock6_xlate_rev_v4_in_v6: Returning ret=%d", ret);
        return ret;
    }

    bpf_printk("bpf_sock: sock6_xlate_rev_v4_in_v6: Building v4-in-v6 address with user_ip4=%x", fake_ctx.user_ip4);
    build_v4_in_v6(&addr6, fake_ctx.user_ip4);
    ctx_set_v6_address(ctx, &addr6);
    ctx_set_port(ctx, (__u16)fake_ctx.user_port);

    bpf_printk("bpf_sock: sock6_xlate_rev_v4_in_v6: Returning 0");
    return 0;
#else
    bpf_printk("bpf_sock: sock6_xlate_rev_v4_in_v6: ENABLE_IPV4 not defined, returning -ENXIO");
    return -ENXIO;
#endif /* ENABLE_IPV4 */
}

static __always_inline int
__sock6_xlate_rev(struct bpf_sock_addr *ctx)
{
#ifdef ENABLE_IPV6
    struct ipv6_revnat_tuple key = {};
    struct ipv6_revnat_entry *val;
    __u16 dst_port = ctx_dst_port(ctx);
    __u8 protocol = ctx_protocol(ctx);

    bpf_printk("bpf_sock: __sock6_xlate_rev: dst_port=%u, protocol=%u", dst_port, protocol);

    key.cookie = sock_local_cookie(ctx);
    key.port = dst_port;
    ctx_get_v6_address(ctx, &key.address);
    bpf_printk("bpf_sock: __sock6_xlate_rev: key cookie=%llu, port=%u, address=%x:%x:%x:%x",
               key.cookie, key.port, key.address.p1, key.address.p2, key.address.p3, key.address.p4);

    bpf_printk("bpf_sock: __sock6_xlate_rev: Sending pre-direction trace notification");
    send_trace_sock_notify6(ctx, XLATE_PRE_DIRECTION_REV, &key.address, bpf_ntohs(dst_port));

    val = map_lookup_elem(&LB6_REVERSE_NAT_SK_MAP, &key);
    bpf_printk("bpf_sock: __sock6_xlate_rev: map_lookup_elem returned val=%p", val);
    if (val) {
        struct lb6_service *svc;
        struct lb6_key svc_key = {
            .address    = val->address,
            .dport      = val->port,
#if defined(ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION)
            .proto      = protocol,
#endif
        };

        bpf_printk("bpf_sock: __sock6_xlate_rev: Looking up service with address=%x:%x:%x:%x, dport=%u",
                   svc_key.address.p1, svc_key.address.p2, svc_key.address.p3, svc_key.address.p4, svc_key.dport);
        svc = lb6_lookup_service(&svc_key, true);
        bpf_printk("bpf_sock: __sock6_xlate_rev: lb6_lookup_service returned svc=%p", svc);
        if (!svc) {
            bpf_printk("bpf_sock: __sock6_xlate_rev: Restoring svc_key protocol=%u", protocol);
            lb6_key_set_protocol(&svc_key, protocol);
            svc = sock6_wildcard_lookup_full(&svc_key, ctx_in_hostns(ctx, NULL));
            bpf_printk("bpf_sock: __sock6_xlate_rev: sock6_wildcard_lookup_full returned svc=%p", svc);
        }

        if (!svc || svc->rev_nat_index != val->rev_nat_index ||
            (svc->count == 0 && !lb6_svc_is_l7loadbalancer(svc))) {
            bpf_printk("bpf_sock: __sock6_xlate_rev: Invalid service or stale entry, deleting map entry");
            map_delete_elem(&LB6_REVERSE_NAT_SK_MAP, &key);
            update_metrics(0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);
            return -ENOENT;
        }

        bpf_printk("bpf_sock: __sock6_xlate_rev: Setting address and port");
        ctx_set_v6_address(ctx, &val->address);
        ctx_set_port(ctx, val->port);
        bpf_printk("bpf_sock: __sock6_xlate_rev: Sending post-direction trace notification");
        send_trace_sock_notify6(ctx, XLATE_POST_DIRECTION_REV, &val->address, bpf_ntohs(val->port));
        return 0;
    }
#endif /* ENABLE_IPV6 */

    bpf_printk("bpf_sock: __sock6_xlate_rev: No reverse NAT entry found, calling sock6_xlate_rev_v4_in_v6");
    return sock6_xlate_rev_v4_in_v6(ctx);
}

__section("cgroup/sendmsg6")
int cil_sock6_sendmsg(struct bpf_sock_addr *ctx)
{
    int err;

    bpf_printk("bpf_sock: cil_sock6_sendmsg: Entering, user_port=%u", ctx->user_port);

    err = __sock6_xlate_fwd(ctx, true);
    bpf_printk("bpf_sock: cil_sock6_sendmsg: __sock6_xlate_fwd returned err=%d", err);
    if (err == -EHOSTUNREACH || err == -ENOMEM) {
        bpf_printk("bpf_sock: cil_sock6_sendmsg: Error, setting retval and returning SYS_REJECT");
        try_set_retval(err);
        return SYS_REJECT;
    }

    bpf_printk("bpf_sock: cil_sock6_sendmsg: Returning SYS_PROCEED");
    return SYS_PROCEED;
}

__section("cgroup/recvmsg6")
int cil_sock6_recvmsg(struct bpf_sock_addr *ctx)
{
    bpf_printk("bpf_sock: cil_sock6_recvmsg: Entering, user_port=%u", ctx->user_port);

    int err = __sock6_xlate_rev(ctx);
    bpf_printk("bpf_sock: cil_sock6_recvmsg: __sock6_xlate_rev returned err=%d", err);

    bpf_printk("bpf_sock: cil_sock6_recvmsg: Returning SYS_PROCEED");
    return SYS_PROCEED;
}

#ifdef ENABLE_SOCKET_LB_PEER
__section("cgroup/getpeername6")
int cil_sock6_getpeername(struct bpf_sock_addr *ctx)
{
    bpf_printk("bpf_sock: cil_sock6_getpeername: Entering, user_port=%u", ctx->user_port);

    int err = __sock6_xlate_rev(ctx);
    bpf_printk("bpf_sock: cil_sock6_getpeername: __sock6_xlate_rev returned err=%d", err);

    bpf_printk("bpf_sock: cil_sock6_getpeername: Returning SYS_PROCEED");
    return SYS_PROCEED;
}
#endif /* ENABLE_SOCKET_LB_PEER */

#endif /* ENABLE_IPV6 || ENABLE_IPV4 */

BPF_LICENSE("Dual BSD/GPL");