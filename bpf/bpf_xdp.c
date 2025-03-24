// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>
#include <filter_config.h>

#define IS_BPF_XDP 1

/* WORLD_IPV{4,6}_ID varies based on dualstack being enabled. Real values are
 * written into node_config.h at runtime. */
#define SECLABEL WORLD_ID
#define SECLABEL_IPV4 WORLD_IPV4_ID
#define SECLABEL_IPV6 WORLD_IPV6_ID

#define SKIP_POLICY_MAP 1

/* Controls the inclusion of the CILIUM_CALL_HANDLE_ICMP6_NS section in the
 * bpf_lxc object file.
 */
#define SKIP_ICMPV6_NS_HANDLING

/* Controls the inclusion of the CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED section
 * in the bpf_lxc object file. This is needed for all callers of
 * ipv6_local_delivery, which calls into the IPv6 L3 handling.
 */
#define SKIP_ICMPV6_HOPLIMIT_HANDLING

/* Controls the inclusion of the CILIUM_CALL_SRV6 section in the object file.
 */
#define SKIP_SRV6_HANDLING

/* The XDP datapath does not take care of health probes from the local node,
 * thus do not compile it in.
 */
#undef ENABLE_HEALTH_CHECK

#include "lib/common.h"
#include "lib/maps.h"
#include "lib/eps.h"
#include "lib/events.h"
#include "lib/nodeport.h"

#ifdef ENABLE_PREFILTER
#ifdef CIDR4_FILTER
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lpm_v4_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_HMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} CIDR4_HMAP_NAME __section_maps_btf;

#ifdef CIDR4_LPM_PREFILTER
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v4_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_LMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} CIDR4_LMAP_NAME __section_maps_btf;

#endif /* CIDR4_LPM_PREFILTER */
#endif /* CIDR4_FILTER */

#ifdef CIDR6_FILTER
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lpm_v6_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_HMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} CIDR6_HMAP_NAME __section_maps_btf;

#ifdef CIDR6_LPM_PREFILTER
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v6_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_LMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} CIDR6_LMAP_NAME __section_maps_btf;
#endif /* CIDR6_LPM_PREFILTER */
#endif /* CIDR6_FILTER */
#endif /* ENABLE_PREFILTER */

static __always_inline __maybe_unused int
bpf_xdp_exit(struct __ctx_buff *ctx, const int verdict)
{
    bpf_printk("bpf_xdp: bpf_xdp_exit verdict=%d", verdict);
    if (verdict == CTX_ACT_OK)
        ctx_move_xfer(ctx);

    return verdict;
}

#ifdef ENABLE_IPV4
#ifdef ENABLE_NODEPORT_ACCELERATION
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_NETDEV)
int tail_lb_ipv4(struct __ctx_buff *ctx)
{
    int ret = CTX_ACT_OK;
    __s8 ext_err = 0;

    bpf_printk("bpf_xdp: Entering tail_lb_ipv4");

    if (!ctx_skip_nodeport(ctx)) {
        int l3_off = ETH_HLEN;
        void *data, *data_end;
        struct iphdr *ip4;
        bool __maybe_unused is_dsr = false;

        bpf_printk("bpf_xdp: tail_lb_ipv4: Validating packet data");
        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            ret = DROP_INVALID;
            bpf_printk("bpf_xdp: tail_lb_ipv4: Invalid packet data, ret=%d", ret);
            goto out;
        }

        bpf_printk("bpf_xdp: tail_lb_ipv4: Source IP=%x, Dest IP=%x", ip4->saddr, ip4->daddr);

#if defined(ENABLE_DSR) && !defined(ENABLE_DSR_HYBRID) && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
        {
            int l4_off, inner_l2_off;
            struct genevehdr geneve;
            __sum16 udp_csum;
            __be16 dport;
            __u16 proto;

            bpf_printk("bpf_xdp: tail_lb_ipv4: Checking for GENEVE encapsulation");

            if (ip4->protocol != IPPROTO_UDP) {
                bpf_printk("bpf_xdp: tail_lb_ipv4: Not UDP, skipping GENEVE check");
                goto no_encap;
            }

            bpf_printk("bpf_xdp: tail_lb_ipv4: Protocol is UDP, checking IP options");
            if (ipv4_hdrlen(ip4) != sizeof(*ip4)) {
                bpf_printk("bpf_xdp: tail_lb_ipv4: IP options present, skipping GENEVE");
                goto no_encap;
            }

            l4_off = l3_off + sizeof(*ip4);

            bpf_printk("bpf_xdp: tail_lb_ipv4: Loading UDP destination port");
            if (l4_load_port(ctx, l4_off + UDP_DPORT_OFF, &dport) < 0) {
                ret = DROP_INVALID;
                bpf_printk("bpf_xdp: tail_lb_ipv4: Failed to load UDP port, ret=%d", ret);
                goto out;
            }

            bpf_printk("bpf_xdp: tail_lb_ipv4: UDP dest port=%d", bpf_ntohs(dport));
            if (dport != bpf_htons(TUNNEL_PORT)) {
                bpf_printk("bpf_xdp: tail_lb_ipv4: Not tunnel port, skipping GENEVE");
                goto no_encap;
            }

            bpf_printk("bpf_xdp: tail_lb_ipv4: Loading UDP checksum");
            if (ctx_load_bytes(ctx, l4_off + offsetof(struct udphdr, check),
                               &udp_csum, sizeof(udp_csum)) < 0) {
                ret = DROP_INVALID;
                bpf_printk("bpf_xdp: tail_lb_ipv4: Failed to load UDP checksum, ret=%d", ret);
                goto out;
            }

            bpf_printk("bpf_xdp: tail_lb_ipv4: UDP checksum=%d", udp_csum);
            if (udp_csum != 0) {
                bpf_printk("bpf_xdp: tail_lb_ipv4: Non-zero UDP checksum, skipping GENEVE");
                goto no_encap;
            }

            bpf_printk("bpf_xdp: tail_lb_ipv4: Loading GENEVE header");
            if (ctx_load_bytes(ctx, l4_off + sizeof(struct udphdr), &geneve,
                               sizeof(geneve)) < 0) {
                ret = DROP_INVALID;
                bpf_printk("bpf_xdp: tail_lb_ipv4: Failed to load GENEVE header, ret=%d", ret);
                goto out;
            }

            bpf_printk("bpf_xdp: tail_lb_ipv4: GENEVE protocol_type=%d", bpf_ntohs(geneve.protocol_type));
            if (geneve.protocol_type != bpf_htons(ETH_P_TEB)) {
                bpf_printk("bpf_xdp: tail_lb_ipv4: Invalid GENEVE protocol type, skipping");
                goto no_encap;
            }

            bpf_printk("bpf_xdp: tail_lb_ipv4: GENEVE opt_len=%d", geneve.opt_len);
            if (geneve.opt_len) {
                bpf_printk("bpf_xdp: tail_lb_ipv4: GENEVE options present, skipping");
                goto no_encap;
            }

            inner_l2_off = l4_off + sizeof(struct udphdr) + sizeof(struct genevehdr);

            bpf_printk("bpf_xdp: tail_lb_ipv4: Validating inner Ethernet header");
            if (!validate_ethertype_l2_off(ctx, inner_l2_off, &proto)) {
                bpf_printk("bpf_xdp: tail_lb_ipv4: Invalid inner Ethernet header, skipping");
                goto no_encap;
            }

            bpf_printk("bpf_xdp: tail_lb_ipv4: Inner protocol=%d", bpf_ntohs(proto));
            if (proto != bpf_htons(ETH_P_IP)) {
                bpf_printk("bpf_xdp: tail_lb_ipv4: Inner protocol not IP, skipping");
                goto no_encap;
            }

            l3_off = inner_l2_off + ETH_HLEN;

            bpf_printk("bpf_xdp: tail_lb_ipv4: Revalidating inner IP header");
            if (!revalidate_data_l3_off(ctx, &data, &data_end, &ip4, l3_off)) {
                ret = DROP_INVALID;
                bpf_printk("bpf_xdp: tail_lb_ipv4: Invalid inner IP header, ret=%d", ret);
                goto out;
            }

            bpf_printk("bpf_xdp: tail_lb_ipv4: Inner Source IP=%x, Dest IP=%x", ip4->saddr, ip4->daddr);
        }
no_encap:
#endif /* ENABLE_DSR && !ENABLE_DSR_HYBRID && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE */

        bpf_printk("bpf_xdp: tail_lb_ipv4: Calling nodeport_lb4");
        ret = nodeport_lb4(ctx, ip4, l3_off, UNKNOWN_ID, NULL, &ext_err, &is_dsr);
        bpf_printk("bpf_xdp: tail_lb_ipv4: nodeport_lb4 returned ret=%d, ext_err=%d", ret, ext_err);

        if (ret == NAT_46X64_RECIRC) {
            bpf_printk("bpf_xdp: tail_lb_ipv4: Recirculating to IPv6 handler");
            ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_FROM_NETDEV, &ext_err);
            bpf_printk("bpf_xdp: tail_lb_ipv4: Tail call to IPv6 returned ret=%d, ext_err=%d", ret, ext_err);
        }
    } else {
        bpf_printk("bpf_xdp: tail_lb_ipv4: Skipping NodePort processing");
    }

out:
    if (IS_ERR(ret)) {
        bpf_printk("bpf_xdp: tail_lb_ipv4: Sending drop notification, ret=%d, ext_err=%d", ret, ext_err);
        return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err,
                                          CTX_ACT_DROP, METRIC_INGRESS);
    }

    bpf_printk("bpf_xdp: tail_lb_ipv4: Exiting with ret=%d", ret);
    return bpf_xdp_exit(ctx, ret);
}

static __always_inline int check_v4_lb(struct __ctx_buff *ctx)
{
    __s8 ext_err = 0;
    int ret;

    bpf_printk("bpf_xdp: Entering check_v4_lb");
    ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_NETDEV, &ext_err);
    bpf_printk("bpf_xdp: check_v4_lb: Tail call returned ret=%d, ext_err=%d", ret, ext_err);

    if (IS_ERR(ret)) {
        bpf_printk("bpf_xdp: check_v4_lb: Sending drop notification, ret=%d, ext_err=%d", ret, ext_err);
        return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err, CTX_ACT_DROP,
                                          METRIC_INGRESS);
    }

    bpf_printk("bpf_xdp: check_v4_lb: Exiting with ret=%d", ret);
    return ret;
}
#else
static __always_inline int check_v4_lb(struct __ctx_buff *ctx __maybe_unused)
{
    bpf_printk("bpf_xdp: check_v4_lb: NodePort acceleration disabled, returning OK");
    return CTX_ACT_OK;
}
#endif /* ENABLE_NODEPORT_ACCELERATION */

#ifdef ENABLE_PREFILTER
static __always_inline int check_v4(struct __ctx_buff *ctx)
{
    void *data_end = ctx_data_end(ctx);
    void *data = ctx_data(ctx);
    struct iphdr *ipv4_hdr = data + sizeof(struct ethhdr);
    struct lpm_v4_key pfx __maybe_unused;

    bpf_printk("bpf_xdp: Entering check_v4");

    if (ctx_no_room(ipv4_hdr + 1, data_end)) {
        bpf_printk("bpf_xdp: check_v4: Packet too small for IPv4 header");
        return CTX_ACT_DROP;
    }

    bpf_printk("bpf_xdp: check_v4: Source IP=%x, Dest IP=%x", ipv4_hdr->saddr, ipv4_hdr->daddr);

#ifdef CIDR4_FILTER
    memcpy(pfx.lpm.data, &ipv4_hdr->saddr, sizeof(pfx.addr));
    pfx.lpm.prefixlen = 32;

    bpf_printk("bpf_xdp: check_v4: Looking up source IP in CIDR4_LMAP_NAME");
#ifdef CIDR4_LPM_PREFILTER
    if (map_lookup_elem(&CIDR4_LMAP_NAME, &pfx)) {
        bpf_printk("bpf_xdp: check_v4: Source IP matched in CIDR4_LMAP_NAME, dropping");
        return CTX_ACT_DROP;
    }
#endif /* CIDR4_LPM_PREFILTER */

    bpf_printk("bpf_xdp: check_v4: Looking up source IP in CIDR4_HMAP_NAME");
    if (map_lookup_elem(&CIDR4_HMAP_NAME, &pfx)) {
        bpf_printk("bpf_xdp: check_v4: Source IP matched in CIDR4_HMAP_NAME, dropping");
        return CTX_ACT_DROP;
    }

    bpf_printk("bpf_xdp: check_v4: No prefilter match, proceeding to check_v4_lb");
    return check_v4_lb(ctx);
#else
    bpf_printk("bpf_xdp: check_v4: CIDR4_FILTER disabled, proceeding to check_v4_lb");
    return check_v4_lb(ctx);
#endif /* CIDR4_FILTER */
}
#else
static __always_inline int check_v4(struct __ctx_buff *ctx)
{
    bpf_printk("bpf_xdp: check_v4: ENABLE_PREFILTER disabled, proceeding to check_v4_lb");
    return check_v4_lb(ctx);
}
#endif /* ENABLE_PREFILTER */
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
#ifdef ENABLE_NODEPORT_ACCELERATION
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_NETDEV)
int tail_lb_ipv6(struct __ctx_buff *ctx)
{
    int ret = CTX_ACT_OK;
    __s8 ext_err = 0;

    bpf_printk("bpf_xdp: Entering tail_lb_ipv6");

    if (!ctx_skip_nodeport(ctx)) {
        void *data, *data_end;
        struct ipv6hdr *ip6;
        bool is_dsr = false;

        bpf_printk("bpf_xdp: tail_lb_ipv6: Validating packet data");
        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            ret = DROP_INVALID;
            bpf_printk("bpf_xdp: tail_lb_ipv6: Invalid packet data, ret=%d", ret);
            goto drop_err;
        }

        bpf_printk("bpf_xdp: tail_lb_ipv6: Source IPv6=%x:%x:%x:%x",
                   ip6->saddr.s6_addr32[0], ip6->saddr.s6_addr32[1],
                   ip6->saddr.s6_addr32[2], ip6->saddr.s6_addr32[3]);
        bpf_printk("bpf_xdp: tail_lb_ipv6: Dest IPv6=%x:%x:%x:%x",
                   ip6->daddr.s6_addr32[0], ip6->daddr.s6_addr32[1],
                   ip6->daddr.s6_addr32[2], ip6->daddr.s6_addr32[3]);

        bpf_printk("bpf_xdp: tail_lb_ipv6: Calling nodeport_lb6");
        ret = nodeport_lb6(ctx, ip6, UNKNOWN_ID, NULL, &ext_err, &is_dsr);
        bpf_printk("bpf_xdp: tail_lb_ipv6: nodeport_lb6 returned ret=%d, ext_err=%d", ret, ext_err);

        if (IS_ERR(ret))
            goto drop_err;
    } else {
        bpf_printk("bpf_xdp: tail_lb_ipv6: Skipping NodePort processing");
    }

    bpf_printk("bpf_xdp: tail_lb_ipv6: Exiting with ret=%d", ret);
    return bpf_xdp_exit(ctx, ret);

drop_err:
    bpf_printk("bpf_xdp: tail_lb_ipv6: Sending drop notification, ret=%d, ext_err=%d", ret, ext_err);
    return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err,
                                      CTX_ACT_DROP, METRIC_INGRESS);
}

static __always_inline int check_v6_lb(struct __ctx_buff *ctx)
{
    __s8 ext_err = 0;
    int ret;

    bpf_printk("bpf_xdp: Entering check_v6_lb");
    ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_FROM_NETDEV, &ext_err);
    bpf_printk("bpf_xdp: check_v6_lb: Tail call returned ret=%d, ext_err=%d", ret, ext_err);

    if (IS_ERR(ret)) {
        bpf_printk("bpf_xdp: check_v6_lb: Sending drop notification, ret=%d, ext_err=%d", ret, ext_err);
        return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err, CTX_ACT_DROP,
                                          METRIC_INGRESS);
    }

    bpf_printk("bpf_xdp: check_v6_lb: Exiting with ret=%d", ret);
    return ret;
}
#else
static __always_inline int check_v6_lb(struct __ctx_buff *ctx __maybe_unused)
{
    bpf_printk("bpf_xdp: check_v6_lb: NodePort acceleration disabled, returning OK");
    return CTX_ACT_OK;
}
#endif /* ENABLE_NODEPORT_ACCELERATION */

#ifdef ENABLE_PREFILTER
static __always_inline int check_v6(struct __ctx_buff *ctx)
{
    void *data_end = ctx_data_end(ctx);
    void *data = ctx_data(ctx);
    struct ipv6hdr *ipv6_hdr = data + sizeof(struct ethhdr);
    struct lpm_v6_key pfx __maybe_unused;

    bpf_printk("bpf_xdp: Entering check_v6");

    if (ctx_no_room(ipv6_hdr + 1, data_end)) {
        bpf_printk("bpf_xdp: check_v6: Packet too small for IPv6 header");
        return CTX_ACT_DROP;
    }

    bpf_printk("bpf_xdp: check_v6: Source IPv6=%x:%x:%x:%x",
               ipv6_hdr->saddr.s6_addr32[0], ipv6_hdr->saddr.s6_addr32[1],
               ipv6_hdr->saddr.s6_addr32[2], ipv6_hdr->saddr.s6_addr32[3]);
    bpf_printk("bpf_xdp: check_v6: Dest IPv6=%x:%x:%x:%x",
               ipv6_hdr->daddr.s6_addr32[0], ipv6_hdr->daddr.s6_addr32[1],
               ipv6_hdr->daddr.s6_addr32[2], ipv6_hdr->daddr.s6_addr32[3]);

#ifdef CIDR6_FILTER
    __bpf_memcpy_builtin(pfx.lpm.data, &ipv6_hdr->saddr, sizeof(pfx.addr));
    pfx.lpm.prefixlen = 128;

    bpf_printk("bpf_xdp: check_v6: Looking up source IP in CIDR6_LMAP_NAME");
#ifdef CIDR6_LPM_PREFILTER
    if (map_lookup_elem(&CIDR6_LMAP_NAME, &pfx)) {
        bpf_printk("bpf_xdp: check_v6: Source IP matched in CIDR6_LMAP_NAME, dropping");
        return CTX_ACT_DROP;
    }
#endif /* CIDR6_LPM_PREFILTER */

    bpf_printk("bpf_xdp: check_v6: Looking up source IP in CIDR6_HMAP_NAME");
    if (map_lookup_elem(&CIDR6_HMAP_NAME, &pfx)) {
        bpf_printk("bpf_xdp: check_v6: Source IP matched in CIDR6_HMAP_NAME, dropping");
        return CTX_ACT_DROP;
    }

    bpf_printk("bpf_xdp: check_v6: No prefilter match, proceeding to check_v6_lb");
    return check_v6_lb(ctx);
#else
    bpf_printk("bpf_xdp: check_v6: CIDR6_FILTER disabled, proceeding to check_v6_lb");
    return check_v6_lb(ctx);
#endif /* CIDR6_FILTER */
}
#else
static __always_inline int check_v6(struct __ctx_buff *ctx)
{
    bpf_printk("bpf_xdp: check_v6: ENABLE_PREFILTER disabled, proceeding to check_v6_lb");
    return check_v6_lb(ctx);
}
#endif /* ENABLE_PREFILTER */
#endif /* ENABLE_IPV6 */

static __always_inline int check_filters(struct __ctx_buff *ctx)
{
    int ret = CTX_ACT_OK;
    __u16 proto;

    bpf_printk("bpf_xdp: Entering check_filters");

    if (!validate_ethertype(ctx, &proto)) {
        bpf_printk("bpf_xdp: check_filters: Invalid Ethernet header, passing");
        return CTX_ACT_OK;
    }

    bpf_printk("bpf_xdp: check_filters: Protocol=%d", bpf_ntohs(proto));

    ctx_store_meta(ctx, XFER_MARKER, 0);
    ctx_skip_nodeport_clear(ctx);
    bpf_printk("bpf_xdp: check_filters: Cleared NodePort skip flag");

    switch (proto) {
#ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        bpf_printk("bpf_xdp: check_filters: Processing IPv4 packet");
        ret = check_v4(ctx);
        break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        bpf_printk("bpf_xdp: check_filters: Processing IPv6 packet");
        ret = check_v6(ctx);
        break;
#endif /* ENABLE_IPV6 */
    default:
        bpf_printk("bpf_xdp: check_filters: Unsupported protocol, passing");
        break;
    }

    bpf_printk("bpf_xdp: check_filters: Exiting with ret=%d", ret);
    return bpf_xdp_exit(ctx, ret);
}

__section_entry
int cil_xdp_entry(struct __ctx_buff *ctx)
{
    bpf_printk("bpf_xdp: Entering cil_xdp_entry");
    int ret = check_filters(ctx);
    bpf_printk("bpf_xdp: cil_xdp_entry: Exiting with ret=%d", ret);
    return ret;
}

BPF_LICENSE("Dual BSD/GPL");