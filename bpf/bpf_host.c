// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <ep_config.h>

#define IS_BPF_HOST 1

#define EVENT_SOURCE HOST_EP_ID

/* Host endpoint ID for the template bpf_host object file. Will be replaced
 * at compile-time with the proper host endpoint ID.
 */
#define TEMPLATE_HOST_EP_ID 0xffff

/* These are configuration options which have a default value in their
 * respective header files and must thus be defined beforehand:
 */
/* Pass unknown ICMPv6 NS to stack */
#define ACTION_UNKNOWN_ICMP6_NS CTX_ACT_OK

#ifndef VLAN_FILTER
#define VLAN_FILTER(ifindex, vlan_id) (false)
#endif

#include "lib/common.h"
#include "lib/edt.h"
#include "lib/arp.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/proxy.h"
#include "lib/trace.h"
#include "lib/identity.h"
#include "lib/l3.h"
#include "lib/l4.h"
#include "lib/drop.h"
#include "lib/encap.h"
#include "lib/nat.h"
#include "lib/lb.h"
#include "lib/nodeport.h"
#include "lib/nodeport_egress.h"
#include "lib/eps.h"
#include "lib/host_firewall.h"
#include "lib/egress_gateway.h"
#include "lib/srv6.h"
#include "lib/overloadable.h"
#include "lib/encrypt.h"
#include "lib/wireguard.h"
#include "lib/vxlan.h"
#include <linux/bpf.h>

#undef __uint
#undef __type
#undef __array

#include <bpf/bpf_helpers.h>

#define host_egress_policy_hook(ctx, src_sec_identity, ext_err) CTX_ACT_OK
#define host_wg_encrypt_hook(ctx, proto) wg_maybe_redirect_to_encrypt(ctx, proto)

int tail_handle_ipv6_cont(struct __ctx_buff *ctx, bool from_host);
int handle_ipv6(struct __ctx_buff *ctx, __u32 src_sec_identity, __u32 ipcache_srcid, bool from_host, bool *punt_to_stack, int *ext_err);

/* Bit 0 is skipped for robustness, as it's used in some places to indicate from_host itself. */
#define FROM_HOST_FLAG_NEED_HOSTFW (1 << 1)
#define FROM_HOST_FLAG_HOST_ID (1 << 2)

static __always_inline bool allow_vlan(__u32 __maybe_unused ifindex, __u32 __maybe_unused vlan_id) {
	bool result;
    bpf_printk("bpf_host: allow_vlan: Entering with ifindex=%u, vlan_id=%u", ifindex, vlan_id);
    result = VLAN_FILTER(ifindex, vlan_id);
    bpf_printk("bpf_host: allow_vlan: VLAN_FILTER returned result=%d", result);
	return result;
}

#if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
static __always_inline int rewrite_dmac_to_host(struct __ctx_buff *ctx)
{
    int ret;
    union macaddr cilium_net_mac = CILIUM_NET_MAC;
    bpf_printk("bpf_host: rewrite_dmac_to_host: Rewriting DMAC to %x:%x:%x:%x:%x:%x",
               cilium_net_mac.addr[0], cilium_net_mac.addr[1], cilium_net_mac.addr[2],
               cilium_net_mac.addr[3], cilium_net_mac.addr[4], cilium_net_mac.addr[5]);
    ret = eth_store_daddr(ctx, (__u8 *) &cilium_net_mac.addr, 0);
    if (ret < 0) {
        bpf_printk("bpf_host: rewrite_dmac_to_host: eth_store_daddr failed, ret=%d, returning DROP_WRITE_ERROR", ret);
        return DROP_WRITE_ERROR;
    }
    bpf_printk("bpf_host: rewrite_dmac_to_host: DMAC rewritten successfully, returning CTX_ACT_OK");
    return CTX_ACT_OK;
}

#define SECCTX_FROM_IPCACHE_OK 2
#ifndef SECCTX_FROM_IPCACHE
# define SECCTX_FROM_IPCACHE 0
#endif

static __always_inline bool identity_from_ipcache_ok(void)
{
    bool result;
    bpf_printk("bpf_host: identity_from_ipcache_ok: SECCTX_FROM_IPCACHE=%d", SECCTX_FROM_IPCACHE);
    result = SECCTX_FROM_IPCACHE == SECCTX_FROM_IPCACHE_OK;
    bpf_printk("bpf_host: identity_from_ipcache_ok: Result=%d", result);
    return result;
}
#endif

#ifdef ENABLE_IPV6
static __always_inline __u32
resolve_srcid_ipv6(struct __ctx_buff *ctx, struct ipv6hdr *ip6,
           __u32 srcid_from_ipcache, __u32 *sec_identity,
           const bool from_host)
{
    __u32 src_id = WORLD_IPV6_ID;
    struct remote_endpoint_info *info = NULL;
    union v6addr *src;

    bpf_printk("bpf_host: resolve_srcid_ipv6: srcid_from_ipcache=%u, from_host=%d", srcid_from_ipcache, from_host);
    bpf_printk("bpf_host: resolve_srcid_ipv6: Source IPv6=%x:%x:%x:%x",
               ip6->saddr.s6_addr32[0], ip6->saddr.s6_addr32[1],
               ip6->saddr.s6_addr32[2], ip6->saddr.s6_addr32[3]);

    /* Packets from the proxy will already have a real identity. */
    if (identity_is_reserved(srcid_from_ipcache)) {
        src = (union v6addr *) &ip6->saddr;
        bpf_printk("bpf_host: resolve_srcid_ipv6: Looking up remote endpoint for src=%x:%x:%x:%x",
                   src->addr[0], src->addr[1], src->addr[2], src->addr[3]);
        info = lookup_ip6_remote_endpoint(src, 0);
        if (info) {
            *sec_identity = info->sec_identity;
            bpf_printk("bpf_host: resolve_srcid_ipv6: Found remote endpoint, sec_identity=%u", *sec_identity);
            if (*sec_identity) {
                /* When SNAT is enabled on traffic ingressing
                 * into Cilium, all traffic from the world will
                 * have a source IP of the host. It will only
                 * actually be from the host if "srcid_from_proxy"
                 * (passed into this function) reports the src as
                 * the host. So we can ignore the ipcache if it
                 * reports the source as HOST_ID.
                 */
                if (*sec_identity != HOST_ID) {
                    srcid_from_ipcache = *sec_identity;
                    bpf_printk("bpf_host: resolve_srcid_ipv6: Updated srcid_from_ipcache=%u", srcid_from_ipcache);
                } else {
                    bpf_printk("bpf_host: resolve_srcid_ipv6: sec_identity is HOST_ID, keeping srcid_from_ipcache=%u", srcid_from_ipcache);
                }
            }
        } else {
            bpf_printk("bpf_host: resolve_srcid_ipv6: No remote endpoint found");
        }
        cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
               ((__u32 *) src)[3], srcid_from_ipcache);
    } else {
        bpf_printk("bpf_host: resolve_srcid_ipv6: srcid_from_ipcache=%u is not reserved", srcid_from_ipcache);
    }

    if (from_host) {
        src_id = srcid_from_ipcache;
        bpf_printk("bpf_host: resolve_srcid_ipv6: from_host is true, src_id=%u", src_id);
    } else if (identity_from_ipcache_ok()) {
        src_id = srcid_from_ipcache;
        bpf_printk("bpf_host: resolve_srcid_ipv6: identity_from_ipcache_ok, src_id=%u", src_id);
    } else {
        bpf_printk("bpf_host: resolve_srcid_ipv6: Using default src_id=%u", src_id);
    }

    bpf_printk("bpf_host: resolve_srcid_ipv6: Returning src_id=%u", src_id);
    return src_id;
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ct_buffer6);
    __uint(max_entries, 1);
} CT_TAIL_CALL_BUFFER6 __section_maps_btf;

static __always_inline int
handle_ipv6(struct __ctx_buff *ctx, __u32 secctx __maybe_unused,
        __u32 ipcache_srcid __maybe_unused,
        const bool from_host __maybe_unused,
        bool *punt_to_stack __maybe_unused,
        __s8 *ext_err __maybe_unused)
{
#ifdef ENABLE_HOST_FIREWALL
    struct ct_buffer6 ct_buffer = {};
    bool need_hostfw = false;
    bool is_host_id = false;
#endif /* ENABLE_HOST_FIREWALL */
    void *data, *data_end;
    struct ipv6hdr *ip6;
    int ret;

    bpf_printk("bpf_host: handle_ipv6: secctx=%u, ipcache_srcid=%u, from_host=%d", secctx, ipcache_srcid, from_host);

    if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
        bpf_printk("bpf_host: handle_ipv6: Invalid packet data, returning DROP_INVALID");
        return DROP_INVALID;
    }

    bpf_printk("bpf_host: handle_ipv6: Source IPv6=%x:%x:%x:%x, Dest IPv6=%x:%x:%x:%x",
               ip6->saddr.s6_addr32[0], ip6->saddr.s6_addr32[1],
               ip6->saddr.s6_addr32[2], ip6->saddr.s6_addr32[3],
               ip6->daddr.s6_addr32[0], ip6->daddr.s6_addr32[1],
               ip6->daddr.s6_addr32[2], ip6->daddr.s6_addr32[3]);

    if (is_defined(ENABLE_HOST_FIREWALL) || !from_host) {
        __u8 nexthdr = ip6->nexthdr;
        int hdrlen;

        bpf_printk("bpf_host: handle_ipv6: Checking for ICMPv6, nexthdr=%u", nexthdr);
        hdrlen = ipv6_hdrlen(ctx, &nexthdr);
        if (hdrlen < 0) {
            bpf_printk("bpf_host: handle_ipv6: Invalid IPv6 header length=%d, returning", hdrlen);
            return hdrlen;
        }

        if (likely(nexthdr == IPPROTO_ICMPV6)) {
            bpf_printk("bpf_host: handle_ipv6: Packet is ICMPv6, calling icmp6_host_handle");
            ret = icmp6_host_handle(ctx, ETH_HLEN + hdrlen, ext_err, !from_host);
            bpf_printk("bpf_host: handle_ipv6: icmp6_host_handle returned ret=%d", ret);
            if (ret == SKIP_HOST_FIREWALL) {
                bpf_printk("bpf_host: handle_ipv6: icmp6_host_handle returned SKIP_HOST_FIREWALL, jumping to skip_host_firewall");
                goto skip_host_firewall;
            }
            if (IS_ERR(ret)) {
                bpf_printk("bpf_host: handle_ipv6: icmp6_host_handle returned error=%d, returning", ret);
                return ret;
            }
        }
    }

#ifdef ENABLE_NODEPORT
    if (!from_host) {
        if (!ctx_skip_nodeport(ctx)) {
            bool is_dsr = false;

            bpf_printk("bpf_host: handle_ipv6: Not from host, calling nodeport_lb6");
            ret = nodeport_lb6(ctx, ip6, secctx, punt_to_stack, ext_err, &is_dsr);
            bpf_printk("bpf_host: handle_ipv6: nodeport_lb6 returned ret=%d, punt_to_stack=%d, is_dsr=%d", ret, *punt_to_stack, is_dsr);
            /* nodeport_lb6() returns with TC_ACT_REDIRECT for
             * traffic to L7 LB. Policy enforcement needs to take
             * place after L7 LB has processed the packet, so we
             * return to stack immediately here with
             * TC_ACT_REDIRECT.
             */
            if (ret < 0 || ret == TC_ACT_REDIRECT) {
                bpf_printk("bpf_host: handle_ipv6: nodeport_lb6 error or redirect, returning ret=%d", ret);
                return ret;
            }
            if (*punt_to_stack) {
                bpf_printk("bpf_host: handle_ipv6: Punt to stack required, returning ret=%d", ret);
                return ret;
            }
        } else {
            bpf_printk("bpf_host: handle_ipv6: Skipping NodePort processing");
        }
    }
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_HOST_FIREWALL
    if (from_host) {
        bpf_printk("bpf_host: handle_ipv6: From host, checking egress policy");
        if (ipv6_host_policy_egress_lookup(ctx, secctx, ipcache_srcid, ip6, &ct_buffer)) {
            bpf_printk("bpf_host: handle_ipv6: ipv6_host_policy_egress_lookup returned ret=%d", ct_buffer.ret);
            if (unlikely(ct_buffer.ret < 0)) {
                bpf_printk("bpf_host: handle_ipv6: ipv6_host_policy_egress_lookup failed, returning ret=%d", ct_buffer.ret);
                return ct_buffer.ret;
            }
            need_hostfw = true;
            is_host_id = secctx == HOST_ID;
            bpf_printk("bpf_host: handle_ipv6: Egress policy lookup: need_hostfw=%d, is_host_id=%d", need_hostfw, is_host_id);
        }
    } else if (!ctx_skip_host_fw(ctx)) {
        /* Verifier workaround: R5 invalid mem access 'scalar'. */
        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            bpf_printk("bpf_host: handle_ipv6: Revalidation failed, returning DROP_INVALID");
            return DROP_INVALID;
        }

        bpf_printk("bpf_host: handle_ipv6: Not from host, checking ingress policy");
        if (ipv6_host_policy_ingress_lookup(ctx, ip6, &ct_buffer)) {
            bpf_printk("bpf_host: handle_ipv6: ipv6_host_policy_ingress_lookup returned ret=%d", ct_buffer.ret);
            if (unlikely(ct_buffer.ret < 0)) {
                bpf_printk("bpf_host: handle_ipv6: ipv6_host_policy_ingress_lookup failed, returning ret=%d", ct_buffer.ret);
                return ct_buffer.ret;
            }
            need_hostfw = true;
            bpf_printk("bpf_host: handle_ipv6: Ingress policy lookup: need_hostfw=%d", need_hostfw);
        }
    }
    if (need_hostfw) {
        __u32 zero = 0;

        bpf_printk("bpf_host: handle_ipv6: Updating CT_TAIL_CALL_BUFFER6 for host firewall");
        if (map_update_elem(&CT_TAIL_CALL_BUFFER6, &zero, &ct_buffer, 0) < 0) {
            bpf_printk("bpf_host: handle_ipv6: Failed to update CT_TAIL_CALL_BUFFER6, returning DROP_INVALID_TC_BUFFER");
            return DROP_INVALID_TC_BUFFER;
        }
        bpf_printk("bpf_host: handle_ipv6: CT_TAIL_CALL_BUFFER6 updated successfully");
    }
#endif /* ENABLE_HOST_FIREWALL */

skip_host_firewall:
#ifdef ENABLE_HOST_FIREWALL
    bpf_printk("bpf_host: handle_ipv6: Storing meta: need_hostfw=%d, is_host_id=%d", need_hostfw, is_host_id);
    ctx_store_meta(ctx, CB_FROM_HOST,
               (need_hostfw ? FROM_HOST_FLAG_NEED_HOSTFW : 0) |
               (is_host_id ? FROM_HOST_FLAG_HOST_ID : 0));
#endif /* ENABLE_HOST_FIREWALL */

    bpf_printk("bpf_host: handle_ipv6: Returning CTX_ACT_OK");
    return CTX_ACT_OK;
}

static __always_inline int
handle_ipv6_cont(struct __ctx_buff *ctx, __u32 secctx, const bool from_host,
         __s8 *ext_err __maybe_unused)
{
    struct trace_ctx __maybe_unused trace = {
        .reason = TRACE_REASON_UNKNOWN,
        .monitor = TRACE_PAYLOAD_LEN,
    };
    __u32 __maybe_unused from_host_raw;
    void *data, *data_end;
    struct ipv6hdr *ip6;
    union v6addr *dst;
    int l3_off = ETH_HLEN;
    struct remote_endpoint_info *info = NULL;
    struct endpoint_info *ep;
    int ret;
    __u8 encrypt_key __maybe_unused = 0;
    __u32 magic = MARK_MAGIC_IDENTITY;
    bool from_proxy = false;

    bpf_printk("bpf_host: handle_ipv6_cont: secctx=%u, from_host=%d", secctx, from_host);

    if (from_host && tc_index_from_ingress_proxy(ctx)) {
        from_proxy = true;
        magic = MARK_MAGIC_PROXY_INGRESS;
        bpf_printk("bpf_host: handle_ipv6_cont: Packet from ingress proxy, magic=%u", magic);
    }
    if (from_host && tc_index_from_egress_proxy(ctx)) {
        from_proxy = true;
        magic = MARK_MAGIC_PROXY_EGRESS;
        bpf_printk("bpf_host: handle_ipv6_cont: Packet from egress proxy, magic=%u", magic);
    }

    if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
        bpf_printk("bpf_host: handle_ipv6_cont: Invalid packet data, returning DROP_INVALID");
        return DROP_INVALID;
    }

    bpf_printk("bpf_host: handle_ipv6_cont: Source IPv6=%x:%x:%x:%x, Dest IPv6=%x:%x:%x:%x",
               ip6->saddr.s6_addr32[0], ip6->saddr.s6_addr32[1],
               ip6->saddr.s6_addr32[2], ip6->saddr.s6_addr32[3],
               ip6->daddr.s6_addr32[0], ip6->daddr.s6_addr32[1],
               ip6->daddr.s6_addr32[2], ip6->daddr.s6_addr32[3]);

#ifdef ENABLE_HOST_FIREWALL
    from_host_raw = ctx_load_and_clear_meta(ctx, CB_FROM_HOST);
    bpf_printk("bpf_host: handle_ipv6_cont: from_host_raw=%u", from_host_raw);

    if (from_host_raw & FROM_HOST_FLAG_NEED_HOSTFW) {
        struct ct_buffer6 *ct_buffer;
        __u32 zero = 0;
        __u32 remote_id = WORLD_IPV6_ID;

        bpf_printk("bpf_host: handle_ipv6_cont: Need host firewall, looking up CT_TAIL_CALL_BUFFER6");
        ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER6, &zero);
        if (!ct_buffer) {
            bpf_printk("bpf_host: handle_ipv6_cont: CT_TAIL_CALL_BUFFER6 lookup failed, returning DROP_INVALID_TC_BUFFER");
            return DROP_INVALID_TC_BUFFER;
        }
        if (ct_buffer->tuple.saddr.d1 == 0 && ct_buffer->tuple.saddr.d2 == 0) {
            bpf_printk("bpf_host: handle_ipv6_cont: CT_TAIL_CALL_BUFFER6 tuple.saddr is zero, returning DROP_INVALID_TC_BUFFER");
            return DROP_INVALID_TC_BUFFER;
        }

        if (from_host) {
            bool is_host_id = from_host_raw & FROM_HOST_FLAG_HOST_ID;

            bpf_printk("bpf_host: handle_ipv6_cont: From host, applying egress policy, is_host_id=%d", is_host_id);
            ret = __ipv6_host_policy_egress(ctx, is_host_id, ip6, ct_buffer, &trace, ext_err);
        } else {
            bpf_printk("bpf_host: handle_ipv6_cont: Not from host, applying ingress policy");
            ret = __ipv6_host_policy_ingress(ctx, ip6, ct_buffer, &remote_id, &trace, ext_err);
        }
        bpf_printk("bpf_host: handle_ipv6_cont: Policy enforcement returned ret=%d", ret);
        if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT) {
            bpf_printk("bpf_host: handle_ipv6_cont: Policy enforcement error or redirect, returning ret=%d", ret);
            return ret;
        }
    }
#endif /* ENABLE_HOST_FIREWALL */

/*
 * Perform SRv6 Decap if incoming skb is a known SID.
 * This must tailcall, as the decap could be for inner ipv6 or ipv4 making
 * the remaining path potentially erroneous.
 *
 * Perform this before the ENABLE_HOST_ROUTING check as the decap is not dependent
 * on this feature being enabled or not.
 */
#ifdef ENABLE_SRV6
    if (!from_host) {
        bpf_printk("bpf_host: handle_ipv6_cont: Checking for SRv6 packet");
        if (is_srv6_packet(ip6) && srv6_lookup_sid(&ip6->daddr)) {
            bpf_printk("bpf_host: handle_ipv6_cont: SRv6 packet found, tail calling CILIUM_CALL_SRV6_DECAP");
            ret = tail_call_internal(ctx, CILIUM_CALL_SRV6_DECAP, ext_err);
            bpf_printk("bpf_host: handle_ipv6_cont: tail_call_internal returned ret=%d", ret);
            return ret;
        }
        bpf_printk("bpf_host: handle_ipv6_cont: Not an SRv6 packet");
    }
#endif /* ENABLE_SRV6 */

#ifndef ENABLE_HOST_ROUTING
    /* See the equivalent v4 path for comments */
    if (!from_host) {
        bpf_printk("bpf_host: handle_ipv6_cont: Not from host and ENABLE_HOST_ROUTING disabled, returning CTX_ACT_OK");
        return CTX_ACT_OK;
    }
#endif /* !ENABLE_HOST_ROUTING */

    if (from_host) {
        bpf_printk("bpf_host: handle_ipv6_cont: From host, rewriting DMAC");
        ret = rewrite_dmac_to_host(ctx);
        if (IS_ERR(ret)) {
            bpf_printk("bpf_host: handle_ipv6_cont: rewrite_dmac_to_host failed, ret=%d", ret);
            return ret;
        }

        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            bpf_printk("bpf_host: handle_ipv6_cont: Revalidation failed after DMAC rewrite, returning DROP_INVALID");
            return DROP_INVALID;
        }
    }

    bpf_printk("bpf_host: handle_ipv6_cont: Looking up IPv6 endpoint");
    ep = lookup_ip6_endpoint(ip6);
    if (ep) {
        bpf_printk("bpf_host: handle_ipv6_cont: Endpoint found, flags=%u", ep->flags);
        /* Let through packets to the node-ip so they are
         * processed by the local ip stack.
         */
        if (ep->flags & ENDPOINT_MASK_HOST_DELIVERY) {
            bpf_printk("bpf_host: handle_ipv6_cont: Endpoint requires host delivery, returning CTX_ACT_OK");
            return CTX_ACT_OK;
        }

#ifdef ENABLE_HOST_ROUTING
        /* add L2 header for L2-less interface, such as cilium_wg0 */
        if (!from_host) {
            bool l2_hdr_required = true;

            bpf_printk("bpf_host: handle_ipv6_cont: Adding L2 header for L2-less interface");
            ret = maybe_add_l2_hdr(ctx, ep->ifindex, &l2_hdr_required);
            if (ret != 0) {
                bpf_printk("bpf_host: handle_ipv6_cont: maybe_add_l2_hdr failed, ret=%d", ret);
                return ret;
            }
            if (l2_hdr_required && ETH_HLEN == 0) {
                /* l2 header is added */
                l3_off += __ETH_HLEN;
                bpf_printk("bpf_host: handle_ipv6_cont: L2 header added, updated l3_off=%d", l3_off);
            }
        }
#endif
        bpf_printk("bpf_host: handle_ipv6_cont: Calling ipv6_local_delivery with magic=%u", magic);
        ret = ipv6_local_delivery(ctx, l3_off, secctx, magic, ep, METRIC_INGRESS, from_host, false);
        bpf_printk("bpf_host: handle_ipv6_cont: ipv6_local_delivery returned ret=%d", ret);
        return ret;
    }

    /* Below remainder is only relevant when traffic is pushed via cilium_host.
     * For traffic coming from external, we're done here.
     */
    if (!from_host) {
        bpf_printk("bpf_host: handle_ipv6_cont: Not from host, returning CTX_ACT_OK");
        return CTX_ACT_OK;
    }

    dst = (union v6addr *) &ip6->daddr;
    bpf_printk("bpf_host: handle_ipv6_cont: Looking up remote endpoint for dest IPv6=%x:%x:%x:%x",
               dst->addr[0], dst->addr[1], dst->addr[2], dst->addr[3]);
    info = lookup_ip6_remote_endpoint(dst, 0);
    if (info) {
        bpf_printk("bpf_host: handle_ipv6_cont: Remote endpoint found, sec_identity=%u", info->sec_identity);
    } else {
        bpf_printk("bpf_host: handle_ipv6_cont: No remote endpoint found");
    }

#ifdef ENABLE_IPSEC
    /* See IPv4 comment. */
    if (from_proxy && info) {
        encrypt_key = get_min_encrypt_key(info->key);
        bpf_printk("bpf_host: handle_ipv6_cont: From proxy, encrypt_key=%u", encrypt_key);
    }
#endif

#ifdef TUNNEL_MODE
    if (info && info->flag_skip_tunnel) {
        bpf_printk("bpf_host: handle_ipv6_cont: Skipping tunnel due to flag");
        goto skip_tunnel;
    }

    if (info && info->tunnel_endpoint != 0) {
        bpf_printk("bpf_host: handle_ipv6_cont: Encapsulating and redirecting to tunnel_endpoint=%u", info->tunnel_endpoint);
        ret = encap_and_redirect_with_nodeid(ctx, info->tunnel_endpoint,
                          encrypt_key, secctx, info->sec_identity,
                          &trace);
        bpf_printk("bpf_host: handle_ipv6_cont: encap_and_redirect_with_nodeid returned ret=%d", ret);
        return ret;
    } else {
        struct tunnel_key key = {};

        /* IPv6 lookup key: daddr/96 */
        ipv6_addr_copy(&key.ip6, dst);
        key.ip6.p4 = 0;
        key.family = ENDPOINT_KEY_IPV6;

        bpf_printk("bpf_host: handle_ipv6_cont: Encapsulating and redirecting via netdev");
        ret = encap_and_redirect_netdev(ctx, &key, encrypt_key, secctx, &trace);
        bpf_printk("bpf_host: handle_ipv6_cont: encap_and_redirect_netdev returned ret=%d", ret);
        if (ret != DROP_NO_TUNNEL_ENDPOINT) {
            bpf_printk("bpf_host: handle_ipv6_cont: Returning ret=%d", ret);
            return ret;
        }
        bpf_printk("bpf_host: handle_ipv6_cont: encap_and_redirect_netdev returned DROP_NO_TUNNEL_ENDPOINT");
    }
skip_tunnel:
#endif

    if (!info || (!from_proxy && identity_is_world_ipv6(info->sec_identity))) {
        bpf_printk("bpf_host: handle_ipv6_cont: No remote endpoint or world IPv6 identity, returning DROP_UNROUTABLE");
        return DROP_UNROUTABLE;
    }

#if defined(ENABLE_IPSEC) && !defined(TUNNEL_MODE)
    /* See IPv4 comment. */
    if (from_proxy && info->tunnel_endpoint && encrypt_key) {
        bpf_printk("bpf_host: handle_ipv6_cont: Setting IPsec encryption, tunnel_endpoint=%u", info->tunnel_endpoint);
        ret = set_ipsec_encrypt(ctx, encrypt_key, info->tunnel_endpoint,
                     info->sec_identity, true, false);
        bpf_printk("bpf_host: handle_ipv6_cont: set_ipsec_encrypt returned ret=%d", ret);
        return ret;
    }

    if (from_proxy && !identity_is_cluster(info->sec_identity)) {
        bpf_printk("bpf_host: handle_ipv6_cont: Marking as proxy to world");
        ctx->mark = MARK_MAGIC_PROXY_TO_WORLD;
    }
#endif /* ENABLE_IPSEC && !TUNNEL_MODE */

    bpf_printk("bpf_host: handle_ipv6_cont: Returning CTX_ACT_OK");
    return CTX_ACT_OK;
}

#if defined(ENABLE_IPV6)

static __always_inline int
tail_handle_ipv6_cont(struct __ctx_buff *ctx, bool from_host)
{
    __u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
    int ret;
    __s8 ext_err = 0;

    bpf_printk("bpf_host: tail_handle_ipv6_cont: src_sec_identity=%u, from_host=%d", src_sec_identity, from_host);
    ret = handle_ipv6_cont(ctx, src_sec_identity, from_host, &ext_err);
    bpf_printk("bpf_host: tail_handle_ipv6_cont: handle_ipv6_cont returned ret=%d, ext_err=%d", ret, ext_err);
    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: tail_handle_ipv6_cont: Sending drop notification, ret=%d, ext_err=%d", ret, ext_err);
        ret = send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
                          CTX_ACT_DROP, METRIC_INGRESS);
        bpf_printk("bpf_host: tail_handle_ipv6_cont: send_drop_notify_error_ext returned ret=%d", ret);
        return ret;
    }
    bpf_printk("bpf_host: tail_handle_ipv6_cont: Returning ret=%d", ret);
    return ret;
}
#endif /* ENABLE_IPV6 */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_CONT_FROM_HOST)
static __always_inline
int tail_handle_ipv6_cont_from_host(struct __ctx_buff *ctx)
{
    int ret;
    bpf_printk("bpf_host: tail_handle_ipv6_cont_from_host: Entering");
    ret = tail_handle_ipv6_cont(ctx, true);
    bpf_printk("bpf_host: tail_handle_ipv6_cont_from_host: tail_handle_ipv6_cont returned ret=%d", ret);
    return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_CONT_FROM_NETDEV)
static __always_inline
int tail_handle_ipv6_cont_from_netdev(struct __ctx_buff *ctx)
{
    int ret;
    bpf_printk("bpf_host: tail_handle_ipv6_cont_from_netdev: Entering");
    ret = tail_handle_ipv6_cont(ctx, false);
    bpf_printk("bpf_host: tail_handle_ipv6_cont_from_netdev: tail_handle_ipv6_cont returned ret=%d", ret);
    return ret;
}

static __always_inline int
tail_handle_ipv6(struct __ctx_buff *ctx, __u32 ipcache_srcid, const bool from_host)
{
    __u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
    bool punt_to_stack = false;
    int ret;
    __s8 ext_err = 0;

    bpf_printk("bpf_host: tail_handle_ipv6: ipcache_srcid=%u, from_host=%d, src_sec_identity=%u", ipcache_srcid, from_host, src_sec_identity);

    ret = handle_ipv6(ctx, src_sec_identity, ipcache_srcid, from_host, &punt_to_stack, &ext_err);
    bpf_printk("bpf_host: tail_handle_ipv6: handle_ipv6 returned ret=%d, punt_to_stack=%d, ext_err=%d", ret, punt_to_stack, ext_err);

    /* TC_ACT_REDIRECT is not an error, but it means we should stop here. */
    if (ret == CTX_ACT_OK) {
        if (punt_to_stack) {
            bpf_printk("bpf_host: tail_handle_ipv6: Punt to stack required, returning ret=%d", ret);
            return ret;
        }

        ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
        bpf_printk("bpf_host: tail_handle_ipv6: Stored src_sec_identity=%u in CB_SRC_LABEL", src_sec_identity);

        if (from_host) {
            bpf_printk("bpf_host: tail_handle_ipv6: From host, invoking tail call CILIUM_CALL_IPV6_CONT_FROM_HOST");
            ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
                                     CILIUM_CALL_IPV6_CONT_FROM_HOST,
                                     tail_handle_ipv6_cont_from_host,
                                     &ext_err);
        } else {
            bpf_printk("bpf_host: tail_handle_ipv6: Not from host, invoking tail call CILIUM_CALL_IPV6_CONT_FROM_NETDEV");
            ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
                                     CILIUM_CALL_IPV6_CONT_FROM_NETDEV,
                                     tail_handle_ipv6_cont_from_netdev,
                                     &ext_err);
        }
        bpf_printk("bpf_host: tail_handle_ipv6: invoke_tailcall_if returned ret=%d, ext_err=%d", ret, ext_err);
    }

    /* Catch errors from both handle_ipv6 and invoke_tailcall_if here. */
    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: tail_handle_ipv6: Error occurred, sending drop notification, ret=%d, ext_err=%d", ret, ext_err);
        ret = send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
        bpf_printk("bpf_host: tail_handle_ipv6: send_drop_notify_error_ext returned ret=%d", ret);
        return ret;
    }

    bpf_printk("bpf_host: tail_handle_ipv6: Returning ret=%d", ret);
    return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_HOST)
int tail_handle_ipv6_from_host(struct __ctx_buff *ctx)
{
    __u32 ipcache_srcid = 0;

    bpf_printk("bpf_host: tail_handle_ipv6_from_host: Entering");

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV6)
    ipcache_srcid = ctx_load_and_clear_meta(ctx, CB_IPCACHE_SRC_LABEL);
    bpf_printk("bpf_host: tail_handle_ipv6_from_host: Loaded ipcache_srcid=%u from CB_IPCACHE_SRC_LABEL", ipcache_srcid);
#endif /* defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV6) */

    int ret = tail_handle_ipv6(ctx, ipcache_srcid, true);
    bpf_printk("bpf_host: tail_handle_ipv6_from_host: tail_handle_ipv6 returned ret=%d", ret);
    return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_NETDEV)
int tail_handle_ipv6_from_netdev(struct __ctx_buff *ctx)
{
    bpf_printk("bpf_host: tail_handle_ipv6_from_netdev: Entering");
    int ret = tail_handle_ipv6(ctx, 0, false);
    bpf_printk("bpf_host: tail_handle_ipv6_from_netdev: tail_handle_ipv6 returned ret=%d", ret);
    return ret;
}

#ifdef ENABLE_HOST_FIREWALL
static __always_inline int
handle_to_netdev_ipv6(struct __ctx_buff *ctx, __u32 src_sec_identity,
                      struct trace_ctx *trace, __s8 *ext_err)
{
    void *data, *data_end;
    struct ipv6hdr *ip6;
    __u32 srcid = 0, ipcache_srcid = 0;
    int hdrlen, ret;
    __u8 nexthdr;

    bpf_printk("bpf_host: handle_to_netdev_ipv6: src_sec_identity=%u", src_sec_identity);

    if (!revalidate_data_pull(ctx, &data, &data_end, &ip6)) {
        bpf_printk("bpf_host: handle_to_netdev_ipv6: Invalid packet data, returning DROP_INVALID");
        return DROP_INVALID;
    }

    bpf_printk("bpf_host: handle_to_netdev_ipv6: Source IPv6=%x:%x:%x:%x, Dest IPv6=%x:%x:%x:%x",
               ip6->saddr.s6_addr32[0], ip6->saddr.s6_addr32[1],
               ip6->saddr.s6_addr32[2], ip6->saddr.s6_addr32[3],
               ip6->daddr.s6_addr32[0], ip6->daddr.s6_addr32[1],
               ip6->daddr.s6_addr32[2], ip6->daddr.s6_addr32[3]);

    nexthdr = ip6->nexthdr;
    bpf_printk("bpf_host: handle_to_netdev_ipv6: Checking for ICMPv6, nexthdr=%u", nexthdr);
    hdrlen = ipv6_hdrlen(ctx, &nexthdr);
    if (hdrlen < 0) {
        bpf_printk("bpf_host: handle_to_netdev_ipv6: Invalid IPv6 header length=%d, returning", hdrlen);
        return hdrlen;
    }

    if (likely(nexthdr == IPPROTO_ICMPV6)) {
        bpf_printk("bpf_host: handle_to_netdev_ipv6: Packet is ICMPv6, calling icmp6_host_handle");
        ret = icmp6_host_handle(ctx, ETH_HLEN + hdrlen, ext_err, false);
        bpf_printk("bpf_host: handle_to_netdev_ipv6: icmp6_host_handle returned ret=%d", ret);
        if (ret == SKIP_HOST_FIREWALL) {
            bpf_printk("bpf_host: handle_to_netdev_ipv6: icmp6_host_handle returned SKIP_HOST_FIREWALL, returning CTX_ACT_OK");
            return CTX_ACT_OK;
        }
        if (IS_ERR(ret)) {
            bpf_printk("bpf_host: handle_to_netdev_ipv6: icmp6_host_handle returned error=%d, returning", ret);
            return ret;
        }
    }

    /* The code below only cares about host-originating yes/no,
     * and currently breaks when being passed a fine-grained pod src_sec_identity.
     *
     * Restore old behavior for now, and clean it up once we have tests.
     */
    if (src_sec_identity != HOST_ID) {
        bpf_printk("bpf_host: handle_to_netdev_ipv6: src_sec_identity=%u is not HOST_ID, setting to 0", src_sec_identity);
        src_sec_identity = 0;
    }

    bpf_printk("bpf_host: handle_to_netdev_ipv6: Resolving srcid with src_sec_identity=%u", src_sec_identity);
    srcid = resolve_srcid_ipv6(ctx, ip6, src_sec_identity, &ipcache_srcid, true);
    bpf_printk("bpf_host: handle_to_netdev_ipv6: Resolved srcid=%u, ipcache_srcid=%u", srcid, ipcache_srcid);

    /* to-netdev is attached to the egress path of the native device. */
    bpf_printk("bpf_host: handle_to_netdev_ipv6: Calling ipv6_host_policy_egress");
    ret = ipv6_host_policy_egress(ctx, srcid, ipcache_srcid, ip6, trace, ext_err);
    bpf_printk("bpf_host: handle_to_netdev_ipv6: ipv6_host_policy_egress returned ret=%d", ret);
    return ret;
}
#endif /* ENABLE_HOST_FIREWALL */
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline __u32
resolve_srcid_ipv4(struct __ctx_buff *ctx, struct iphdr *ip4,
           __u32 srcid_from_proxy, __u32 *sec_identity,
           const bool from_host)
{
    __u32 src_id = WORLD_IPV4_ID, srcid_from_ipcache = srcid_from_proxy;
    struct remote_endpoint_info *info = NULL;

    bpf_printk("bpf_host: resolve_srcid_ipv4: srcid_from_proxy=%u, from_host=%d", srcid_from_proxy, from_host);
    bpf_printk("bpf_host: resolve_srcid_ipv4: Source IP=%x, Dest IP=%x", ip4->saddr, ip4->daddr);

    /* Packets from the proxy will already have a real identity. */
    if (identity_is_reserved(srcid_from_ipcache)) {
        bpf_printk("bpf_host: resolve_srcid_ipv4: Looking up remote endpoint for src IP=%x", ip4->saddr);
        info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
        if (info != NULL) {
            *sec_identity = info->sec_identity;
            bpf_printk("bpf_host: resolve_srcid_ipv4: Found remote endpoint, sec_identity=%u", *sec_identity);

            if (*sec_identity) {
                /* When SNAT is enabled on traffic ingressing
                 * into Cilium, all traffic from the world will
                 * have a source IP of the host. It will only
                 * actually be from the host if "srcid_from_proxy"
                 * (passed into this function) reports the src as
                 * the host. So we can ignore the ipcache if it
                 * reports the source as HOST_ID.
                 */
                if (*sec_identity != HOST_ID) {
                    srcid_from_ipcache = *sec_identity;
                    bpf_printk("bpf_host: resolve_srcid_ipv4: Updated srcid_from_ipcache=%u", srcid_from_ipcache);
                } else {
                    bpf_printk("bpf_host: resolve_srcid_ipv4: sec_identity is HOST_ID, keeping srcid_from_ipcache=%u", srcid_from_ipcache);
                }
            }
        } else {
            bpf_printk("bpf_host: resolve_srcid_ipv4: No remote endpoint found");
        }
        cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
               ip4->saddr, srcid_from_ipcache);
    } else {
        bpf_printk("bpf_host: resolve_srcid_ipv4: srcid_from_ipcache=%u is not reserved", srcid_from_ipcache);
    }

    if (from_host) {
        src_id = srcid_from_ipcache;
        bpf_printk("bpf_host: resolve_srcid_ipv4: from_host is true, src_id=%u", src_id);
    } else if (identity_from_ipcache_ok()) {
        src_id = srcid_from_ipcache;
        bpf_printk("bpf_host: resolve_srcid_ipv4: identity_from_ipcache_ok, src_id=%u", src_id);
    } else {
        bpf_printk("bpf_host: resolve_srcid_ipv4: Using default src_id=%u", src_id);
    }

    bpf_printk("bpf_host: resolve_src  src_id=%u", src_id);
    return src_id;
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ct_buffer4);
    __uint(max_entries, 1);
} CT_TAIL_CALL_BUFFER4 __section_maps_btf;

static __always_inline int
handle_ipv4(struct __ctx_buff *ctx, __u32 secctx __maybe_unused,
        __u32 ipcache_srcid __maybe_unused,
        const bool from_host __maybe_unused,
        bool *punt_to_stack __maybe_unused,
        __s8 *ext_err __maybe_unused)
{
#ifdef ENABLE_HOST_FIREWALL
    struct ct_buffer4 ct_buffer = {};
    bool need_hostfw = false;
    bool is_host_id = false;
#endif /* ENABLE_HOST_FIREWALL */
    void *data, *data_end;
    struct iphdr *ip4;

    bpf_printk("bpf_host: handle_ipv4: secctx=%u, ipcache_srcid=%u, from_host=%d", secctx, ipcache_srcid, from_host);

    if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
        bpf_printk("bpf_host: handle_ipv4: Invalid packet data, returning DROP_INVALID");
        return DROP_INVALID;
    }

    bpf_printk("bpf_host: handle_ipv4: Source IP=%x, Dest IP=%x", ip4->saddr, ip4->daddr);

#ifndef ENABLE_IPV4_FRAGMENTS
    if (ipv4_is_fragment(ip4)) {
        bpf_printk("bpf_host: handle_ipv4: Fragmented packet and ENABLE_IPV4_FRAGMENTS disabled, returning DROP_FRAG_NOSUPPORT");
        return DROP_FRAG_NOSUPPORT;
    }
#endif

#ifdef ENABLE_NODEPORT
    if (!from_host) {
        if (!ctx_skip_nodeport(ctx)) {
            bool is_dsr = false;

            bpf_printk("bpf_host: handle_ipv4: Not from host, calling nodeport_lb4");
            int ret = nodeport_lb4(ctx, ip4, ETH_HLEN, secctx, punt_to_stack, ext_err, &is_dsr);
            bpf_printk("bpf_host: handle_ipv4: nodeport_lb4 returned ret=%d, punt_to_stack=%d, is_dsr=%d", ret, *punt_to_stack, is_dsr);
#ifdef ENABLE_IPV6
            if (ret == NAT_46X64_RECIRC) {
                bpf_printk("bpf_host: handle_ipv4: nodeport_lb4 returned NAT_46X64_RECIRC, tail calling CILIUM_CALL_IPV6_FROM_NETDEV");
                ctx_store_meta(ctx, CB_SRC_LABEL, secctx);
                ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_FROM_NETDEV, ext_err);
                bpf_printk("bpf_host: handle_ipv4: tail_call_internal returned ret=%d", ret);
                return ret;
            }
#endif
            if (ret < 0 || ret == TC_ACT_REDIRECT) {
                bpf_printk("bpf_host: handle_ipv4: nodeport_lb4 error or redirect, returning ret=%d", ret);
                return ret;
            }
            if (*punt_to_stack) {
                bpf_printk("bpf_host: handle_ipv4: Punt to stack required, returning ret=%d", ret);
                return ret;
            }
        } else {
            bpf_printk("bpf_host: handle_ipv4: Skipping NodePort processing");
        }
    }
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_HOST_FIREWALL
    if (from_host) {
        bpf_printk("bpf_host: handle_ipv4: From host, checking egress policy");
        if (ipv4_host_policy_egress_lookup(ctx, secctx, ipcache_srcid, ip4, &ct_buffer)) {
            bpf_printk("bpf_host: handle_ipv4: ipv4_host_policy_egress_lookup returned ret=%d", ct_buffer.ret);
            if (unlikely(ct_buffer.ret < 0)) {
                bpf_printk("bpf_host: handle_ipv4: ipv4_host_policy_egress_lookup failed, returning ret=%d", ct_buffer.ret);
                return ct_buffer.ret;
            }
            need_hostfw = true;
            is_host_id = secctx == HOST_ID;
            bpf_printk("bpf_host: handle_ipv4: Egress policy lookup: need_hostfw=%d, is_host_id=%d", need_hostfw, is_host_id);
        }
    } else if (!ctx_skip_host_fw(ctx)) {
        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            bpf_printk("bpf_host: handle_ipv4: Revalidation failed, returning DROP_INVALID");
            return DROP_INVALID;
        }

        bpf_printk("bpf_host: handle_ipv4: Not from host, checking ingress policy");
        if (ipv4_host_policy_ingress_lookup(ctx, ip4, &ct_buffer)) {
            bpf_printk("bpf_host: handle_ipv4: ipv4_host_policy_ingress_lookup returned ret=%d", ct_buffer.ret);
            if (unlikely(ct_buffer.ret < 0)) {
                bpf_printk("bpf_host: handle_ipv4: ipv4_host_policy_ingress_lookup failed, returning ret=%d", ct_buffer.ret);
                return ct_buffer.ret;
            }
            need_hostfw = true;
            bpf_printk("bpf_host: handle_ipv4: Ingress policy lookup: need_hostfw=%d", need_hostfw);
        }
    }
    if (need_hostfw) {
        __u32 zero = 0;

        bpf_printk("bpf_host: handle_ipv4: Updating CT_TAIL_CALL_BUFFER4 for host firewall");
        if (map_update_elem(&CT_TAIL_CALL_BUFFER4, &zero, &ct_buffer, 0) < 0) {
            bpf_printk("bpf_host: handle_ipv4: Failed to update CT_TAIL_CALL_BUFFER4, returning DROP_INVALID_TC_BUFFER");
            return DROP_INVALID_TC_BUFFER;
        }
        bpf_printk("bpf_host: handle_ipv4: CT_TAIL_CALL_BUFFER4 updated successfully");
    }

    bpf_printk("bpf_host: handle_ipv4: Storing meta: need_hostfw=%d, is_host_id=%d", need_hostfw, is_host_id);
    ctx_store_meta(ctx, CB_FROM_HOST,
               (need_hostfw ? FROM_HOST_FLAG_NEED_HOSTFW : 0) |
               (is_host_id ? FROM_HOST_FLAG_HOST_ID : 0));
#endif /* ENABLE_HOST_FIREWALL */

    bpf_printk("bpf_host: handle_ipv4: Returning CTX_ACT_OK");
    return CTX_ACT_OK;
}

static __always_inline int
handle_ipv4_cont(struct __ctx_buff *ctx, __u32 secctx, const bool from_host,
         __s8 *ext_err __maybe_unused)
{
    struct trace_ctx __maybe_unused trace = {
        .reason = TRACE_REASON_UNKNOWN,
        .monitor = TRACE_PAYLOAD_LEN,
    };
    __u32 __maybe_unused from_host_raw;
    void *data, *data_end;
    struct iphdr *ip4;
    struct remote_endpoint_info *info;
    struct endpoint_info *ep;
    int ret;
    __u8 encrypt_key __maybe_unused = 0;
    __u32 magic = MARK_MAGIC_IDENTITY;
    bool from_proxy = false;

    bpf_printk("bpf_host: handle_ipv4_cont: secctx=%u, from_host=%d", secctx, from_host);

    if (from_host && tc_index_from_ingress_proxy(ctx)) {
        from_proxy = true;
        magic = MARK_MAGIC_PROXY_INGRESS;
        bpf_printk("bpf_host: handle_ipv4_cont: Packet from ingress proxy, magic=%u", magic);
    }
    if (from_host && tc_index_from_egress_proxy(ctx)) {
        from_proxy = true;
        magic = MARK_MAGIC_PROXY_EGRESS;
        bpf_printk("bpf_host: handle_ipv4_cont: Packet from egress proxy, magic=%u", magic);
    }

    if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
        bpf_printk("bpf_host: handle_ipv4_cont: Invalid packet data, returning DROP_INVALID");
        return DROP_INVALID;
    }

    bpf_printk("bpf_host: handle_ipv4_cont: Source IP=%x, Dest IP=%x", ip4->saddr, ip4->daddr);

#ifdef ENABLE_HOST_FIREWALL
    from_host_raw = ctx_load_and_clear_meta(ctx, CB_FROM_HOST);
    bpf_printk("bpf_host: handle_ipv4_cont: from_host_raw=%u", from_host_raw);

    if (from_host_raw & FROM_HOST_FLAG_NEED_HOSTFW) {
        struct ct_buffer4 *ct_buffer;
        __u32 zero = 0;
        __u32 remote_id = 0;

        bpf_printk("bpf_host: handle_ipv4_cont: Need host firewall, looking up CT_TAIL_CALL_BUFFER4");
        ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER4, &zero);
        if (!ct_buffer) {
            bpf_printk("bpf_host: handle_ipv4_cont: CT_TAIL_CALL_BUFFER4 lookup failed, returning DROP_INVALID_TC_BUFFER");
            return DROP_INVALID_TC_BUFFER;
        }
        if (ct_buffer->tuple.saddr == 0) {
            bpf_printk("bpf_host: handle_ipv4_cont: CT_TAIL_CALL_BUFFER4 tuple.saddr is zero, returning DROP_INVALID_TC_BUFFER");
            return DROP_INVALID_TC_BUFFER;
        }

        if (from_host) {
            bool is_host_id = from_host_raw & FROM_HOST_FLAG_HOST_ID;

            bpf_printk("bpf_host: handle_ipv4_cont: From host, applying egress policy, is_host_id=%d", is_host_id);
            ret = __ipv4_host_policy_egress(ctx, is_host_id, ip4, ct_buffer, &trace, ext_err);
        } else {
            bpf_printk("bpf_host: handle_ipv4_cont: Not from host, applying ingress policy");
            ret = __ipv4_host_policy_ingress(ctx, ip4, ct_buffer, &remote_id, &trace, ext_err);
        }
        bpf_printk("bpf_host: handle_ipv4_cont: Policy enforcement returned ret=%d", ret);
        if (IS_ERR(ret) || ret == TC_ACT_REDIRECT) {
            bpf_printk("bpf_host: handle_ipv4_cont: Policy enforcement error or redirect, returning ret=%d", ret);
            return ret;
        }
    }
#endif /* ENABLE_HOST_FIREWALL */

#ifndef ENABLE_HOST_ROUTING
    if (!from_host) {
        bpf_printk("bpf_host: handle_ipv4_cont: Not from host and ENABLE_HOST_ROUTING disabled, returning CTX_ACT_OK");
        return CTX_ACT_OK;
    }
#endif /* !ENABLE_HOST_ROUTING */

    if (from_host) {
        bpf_printk("bpf_host: handle_ipv4_cont: From host, rewriting DMAC");
        ret = rewrite_dmac_to_host(ctx);
        if (IS_ERR(ret)) {
            bpf_printk("bpf_host: handle_ipv4_cont: rewrite_dmac_to_host failed, ret=%d", ret);
            return ret;
        }

        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            bpf_printk("bpf_host: handle_ipv4_cont: Revalidation failed after DMAC rewrite, returning DROP_INVALID");
            return DROP_INVALID;
        }
    }

    bpf_printk("bpf_host: handle_ipv4_cont: Looking up IPv4 endpoint");
    ep = lookup_ip4_endpoint(ip4);
    if (ep) {
        int l3_off = ETH_HLEN;

        bpf_printk("bpf_host: handle_ipv4_cont: Endpoint found, flags=%u", ep->flags);
        if (ep->flags & ENDPOINT_MASK_HOST_DELIVERY) {
            bpf_printk("bpf_host: handle_ipv4_cont: Endpoint requires host delivery, returning CTX_ACT_OK");
            return CTX_ACT_OK;
        }

#ifdef ENABLE_HOST_ROUTING
        if (!from_host) {
            bool l2_hdr_required = true;

            bpf_printk("bpf_host: handle_ipv4_cont: Adding L2 header for L2-less interface");
            ret = maybe_add_l2_hdr(ctx, ep->ifindex, &l2_hdr_required);
            if (ret != 0) {
                bpf_printk("bpf_host: handle_ipv4_cont: maybe_add_l2_hdr failed, ret=%d", ret);
                return ret;
            }
            if (l2_hdr_required && ETH_HLEN == 0) {
                l3_off += __ETH_HLEN;
                bpf_printk("bpf_host: handle_ipv4_cont: L2 header added, updated l3_off=%d", l3_off);
                if (!____revalidate_data_pull(ctx, &data, &data_end,
                              (void **)&ip4, sizeof(*ip4),
                              false, l3_off)) {
                    bpf_printk("bpf_host: handle_ipv4_cont: Revalidation failed after L2 header, returning DROP_INVALID");
                    return DROP_INVALID;
                }
            }
        }
#endif

        bpf_printk("bpf_host: handle_ipv4_cont: Calling ipv4_local_delivery with magic=%u", magic);
        ret = ipv4_local_delivery(ctx, l3_off, secctx, magic, ip4, ep, METRIC_INGRESS, from_host, false, 0);
        bpf_printk("bpf_host: handle_ipv4_cont: ipv4_local_delivery returned ret=%d", ret);
        return ret;
    }

    if (!from_host) {
        bpf_printk("bpf_host: handle_ipv4_cont: Not from host, returning CTX_ACT_OK");
        return CTX_ACT_OK;
    }

#ifdef ENABLE_VTEP
    {
        struct vtep_key vkey = {};
        struct vtep_value *vtep;

        vkey.vtep_ip = ip4->daddr & VTEP_MASK;
        bpf_printk("bpf_host: handle_ipv4_cont: Looking up VTEP for vtep_ip=%x", vkey.vtep_ip);
        vtep = map_lookup_elem(&VTEP_MAP, &vkey);
        if (!vtep) {
            bpf_printk("bpf_host: handle_ipv4_cont: No VTEP found, skipping");
            goto skip_vtep;
        }

        if (vtep->vtep_mac && vtep->tunnel_endpoint) {
            bpf_printk("bpf_host: handle_ipv4_cont: VTEP found, vtep_mac=%x:%x:%x:%x:%x:%x, tunnel_endpoint=%u",
                       vtep->vtep_mac[0], vtep->vtep_mac[1], vtep->vtep_mac[2],
                       vtep->vtep_mac[3], vtep->vtep_mac[4], vtep->vtep_mac[5],
                       vtep->tunnel_endpoint);
            if (eth_store_daddr(ctx, (__u8 *)&vtep->vtep_mac, 0) < 0) {
                bpf_printk("bpf_host: handle_ipv4_cont: Failed to set VTEP DMAC, returning DROP_WRITE_ERROR");
                return DROP_WRITE_ERROR;
            }
            bpf_printk("bpf_host: handle_ipv4_cont: Encapsulating and redirecting to VTEP tunnel_endpoint=%u", vtep->tunnel_endpoint);
            ret = __encap_and_redirect_with_nodeid(ctx, vtep->tunnel_endpoint,
                            secctx, WORLD_IPV4_ID,
                            WORLD_IPV4_ID, &trace);
            bpf_printk("bpf_host: handle_ipv4_cont: __encap_and_redirect_with_nodeid returned ret=%d", ret);
            return ret;
        }
    }
skip_vtep:
#endif

    bpf_printk("bpf_host: handle_ipv4_cont: Looking up remote endpoint for dest IP=%x", ip4->daddr);
    info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
    if (info) {
        bpf_printk("bpf_host: handle_ipv4_cont: Remote endpoint found, sec_identity=%u", info->sec_identity);
    } else {
        bpf_printk("bpf_host: handle_ipv4_cont: No remote endpoint found");
    }

#ifdef ENABLE_IPSEC
    if (from_proxy && info) {
        encrypt_key = get_min_encrypt_key(info->key);
        bpf_printk("bpf_host: handle_ipv4_cont: From proxy, encrypt_key=%u", encrypt_key);
    }
#endif

#ifdef TUNNEL_MODE
    if (info && info->flag_skip_tunnel) {
        bpf_printk("bpf_host: handle_ipv4_cont: Skipping tunnel due to flag");
        goto skip_tunnel;
    }

    if (info && info->tunnel_endpoint != 0) {
        bpf_printk("bpf_host: handle_ipv4_cont: Encapsulating and redirecting to tunnel_endpoint=%u", info->tunnel_endpoint);
        ret = encap_and_redirect_with_nodeid(ctx, info->tunnel_endpoint,
                          encrypt_key, secctx, info->sec_identity,
                          &trace);
        bpf_printk("bpf_host: handle_ipv4_cont: encap_and_redirect_with_nodeid returned ret=%d", ret);
        return ret;
    } else {
        struct tunnel_key key = {};

        key.ip4 = ip4->daddr & IPV4_MASK;
        key.family = ENDPOINT_KEY_IPV4;

        cilium_dbg(ctx, DBG_NETDEV_ENCAP4, key.ip4, secctx);
        bpf_printk("bpf_host: handle_ipv4_cont: Encapsulating and redirecting via netdev, key.ip4=%x", key.ip4);
        ret = encap_and_redirect_netdev(ctx, &key, encrypt_key, secctx, &trace);
        bpf_printk("bpf_host: handle_ipv4_cont: encap_and_redirect_netdev returned ret=%d", ret);
        if (ret != DROP_NO_TUNNEL_ENDPOINT) {
            bpf_printk("bpf_host: handle_ipv4_cont: Returning ret=%d", ret);
            return ret;
        }
        bpf_printk("bpf_host: handle_ipv4_cont: encap_and_redirect_netdev returned DROP_NO_TUNNEL_ENDPOINT");
    }
skip_tunnel:
#endif

    if (!info || (!from_proxy && identity_is_world_ipv4(info->sec_identity))) {
        bpf_printk("bpf_host: handle_ipv4_cont: No remote endpoint or world IPv4 identity, returning DROP_UNROUTABLE");
        return DROP_UNROUTABLE;
    }

#if defined(ENABLE_IPSEC) && !defined(TUNNEL_MODE)
    if (from_proxy && info->tunnel_endpoint && encrypt_key) {
        bpf_printk("bpf_host: handle_ipv4_cont: Setting IPsec encryption, tunnel_endpoint=%u", info->tunnel_endpoint);
        ret = set_ipsec_encrypt(ctx, encrypt_key, info->tunnel_endpoint,
                     info->sec_identity, true, false);
        bpf_printk("bpf_host: handle_ipv4_cont: set_ipsec_encrypt returned ret=%d", ret);
        return ret;
    }

    if (from_proxy && !identity_is_cluster(info->sec_identity)) {
        bpf_printk("bpf_host: handle_ipv4_cont: Marking as proxy to world");
        ctx->mark = MARK_MAGIC_PROXY_TO_WORLD;
    }
#endif /* ENABLE_IPSEC && !TUNNEL_MODE */

    bpf_printk("bpf_host: handle_ipv4_cont: Returning CTX_ACT_OK");
    return CTX_ACT_OK;
}

static __always_inline int
tail_handle_ipv4_cont(struct __ctx_buff *ctx, bool from_host)
{
    __u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
    int ret;
    __s8 ext_err = 0;

    bpf_printk("bpf_host: tail_handle_ipv4_cont: from_host=%d, src_sec_identity=%u", from_host, src_sec_identity);

    ret = handle_ipv4_cont(ctx, src_sec_identity, from_host, &ext_err);
    bpf_printk("bpf_host: tail_handle_ipv4_cont: handle_ipv4_cont returned ret=%d, ext_err=%d", ret, ext_err);

    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: tail_handle_ipv4_cont: Error occurred, sending drop notification, ret=%d, ext_err=%d", ret, ext_err);
        ret = send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
        bpf_printk("bpf_host: tail_handle_ipv4_cont: send_drop_notify_error_ext returned ret=%d", ret);
        return ret;
    }

    bpf_printk("bpf_host: tail_handle_ipv4_cont: Returning ret=%d", ret);
    return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_CONT_FROM_HOST)
static __always_inline
int tail_handle_ipv4_cont_from_host(struct __ctx_buff *ctx)
{
    bpf_printk("bpf_host: tail_handle_ipv4_cont_from_host: Entering");
    int ret = tail_handle_ipv4_cont(ctx, true);
    bpf_printk("bpf_host: tail_handle_ipv4_cont_from_host: tail_handle_ipv4_cont returned ret=%d", ret);
    return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_CONT_FROM_NETDEV)
static __always_inline
int tail_handle_ipv4_cont_from_netdev(struct __ctx_buff *ctx)
{
    bpf_printk("bpf_host: tail_handle_ipv4_cont_from_netdev: Entering");
    int ret = tail_handle_ipv4_cont(ctx, false);
    bpf_printk("bpf_host: tail_handle_ipv4_cont_from_netdev: tail_handle_ipv4_cont returned ret=%d", ret);
    return ret;
}

static __always_inline int
tail_handle_ipv4(struct __ctx_buff *ctx, __u32 ipcache_srcid, const bool from_host)
{
    __u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
    bool punt_to_stack = false;
    int ret;
    __s8 ext_err = 0;

    bpf_printk("bpf_host: tail_handle_ipv4: ipcache_srcid=%u, from_host=%d, src_sec_identity=%u", ipcache_srcid, from_host, src_sec_identity);

    ret = handle_ipv4(ctx, src_sec_identity, ipcache_srcid, from_host, &punt_to_stack, &ext_err);
    bpf_printk("bpf_host: tail_handle_ipv4: handle_ipv4 returned ret=%d, punt_to_stack=%d, ext_err=%d", ret, punt_to_stack, ext_err);

    /* TC_ACT_REDIRECT is not an error, but it means we should stop here. */
    if (ret == CTX_ACT_OK) {
        if (punt_to_stack) {
            bpf_printk("bpf_host: tail_handle_ipv4: Punt to stack required, returning ret=%d", ret);
            return ret;
        }

        ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
        bpf_printk("bpf_host: tail_handle_ipv4: Stored src_sec_identity=%u in CB_SRC_LABEL", src_sec_identity);

        if (from_host) {
            bpf_printk("bpf_host: tail_handle_ipv4: From host, invoking tail call CILIUM_CALL_IPV4_CONT_FROM_HOST");
            ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
                                     CILIUM_CALL_IPV4_CONT_FROM_HOST,
                                     tail_handle_ipv4_cont_from_host,
                                     &ext_err);
        } else {
            bpf_printk("bpf_host: tail_handle_ipv4: Not from host, invoking tail call CILIUM_CALL_IPV4_CONT_FROM_NETDEV");
            ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
                                     CILIUM_CALL_IPV4_CONT_FROM_NETDEV,
                                     tail_handle_ipv4_cont_from_netdev,
                                     &ext_err);
        }
        bpf_printk("bpf_host: tail_handle_ipv4: invoke_tailcall_if returned ret=%d, ext_err=%d", ret, ext_err);
    }

    /* Catch errors from both handle_ipv4 and invoke_tailcall_if here. */
    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: tail_handle_ipv4: Error occurred, sending drop notification, ret=%d, ext_err=%d", ret, ext_err);
        ret = send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
        bpf_printk("bpf_host: tail_handle_ipv4: send_drop_notify_error_ext returned ret=%d", ret);
        return ret;
    }

    bpf_printk("bpf_host: tail_handle_ipv4: Returning ret=%d", ret);
    return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_HOST)
int tail_handle_ipv4_from_host(struct __ctx_buff *ctx)
{
    __u32 ipcache_srcid = 0;

    bpf_printk("bpf_host: tail_handle_ipv4_from_host: Entering");

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV4)
    ipcache_srcid = ctx_load_and_clear_meta(ctx, CB_IPCACHE_SRC_LABEL);
    bpf_printk("bpf_host: tail_handle_ipv4_from_host: Loaded ipcache_srcid=%u from CB_IPCACHE_SRC_LABEL", ipcache_srcid);
#endif /* defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV4) */

    int ret = tail_handle_ipv4(ctx, ipcache_srcid, true);
    bpf_printk("bpf_host: tail_handle_ipv4_from_host: tail_handle_ipv4 returned ret=%d", ret);
    return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_NETDEV)
int tail_handle_ipv4_from_netdev(struct __ctx_buff *ctx)
{
    bpf_printk("bpf_host: tail_handle_ipv4_from_netdev: Entering");
    int ret = tail_handle_ipv4(ctx, 0, false);
    bpf_printk("bpf_host: tail_handle_ipv4_from_netdev: tail_handle_ipv4 returned ret=%d", ret);
    return ret;
}

#ifdef ENABLE_HOST_FIREWALL
static __always_inline int
handle_to_netdev_ipv4(struct __ctx_buff *ctx, __u32 src_sec_identity,
                      struct trace_ctx *trace, __s8 *ext_err)
{
    void *data, *data_end;
    struct iphdr *ip4;
    __u32 src_id = 0, ipcache_srcid = 0;

    bpf_printk("bpf_host: handle_to_netdev_ipv4: src_sec_identity=%u", src_sec_identity);

    if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
        bpf_printk("bpf_host: handle_to_netdev_ipv4: Invalid packet data, returning DROP_INVALID");
        return DROP_INVALID;
    }

    bpf_printk("bpf_host: handle_to_netdev_ipv4: Source IP=%x, Dest IP=%x", ip4->saddr, ip4->daddr);

    if (src_sec_identity != HOST_ID) {
        bpf_printk("bpf_host: handle_to_netdev_ipv4: src_sec_identity=%u is not HOST_ID, setting to 0", src_sec_identity);
        src_sec_identity = 0;
    }

    bpf_printk("bpf_host: handle_to_netdev_ipv4: Resolving srcid with src_sec_identity=%u", src_sec_identity);
    src_id = resolve_srcid_ipv4(ctx, ip4, src_sec_identity, &ipcache_srcid, true);
    bpf_printk("bpf_host: handle_to_netdev_ipv4: Resolved src_id=%u, ipcache_srcid=%u", src_id, ipcache_srcid);

    bpf_printk("bpf_host: handle_to_netdev_ipv4: Calling ipv4_host_policy_egress");
    int ret = ipv4_host_policy_egress(ctx, src_id, ipcache_srcid, ip4, trace, ext_err);
    bpf_printk("bpf_host: handle_to_netdev_ipv4: ipv4_host_policy_egress returned ret=%d", ret);
    return ret;
}
#endif /* ENABLE_HOST_FIREWALL */
#endif /* ENABLE_IPV4 */

#if defined(ENABLE_IPSEC) && defined(TUNNEL_MODE)
static __always_inline int
do_netdev_encrypt_encap(struct __ctx_buff *ctx, __be16 proto, __u32 src_id)
{
    struct trace_ctx trace = {
        .reason = TRACE_REASON_ENCRYPTED,
        .monitor = 0,
    };
    struct remote_endpoint_info *ep = NULL;
    void *data, *data_end;
    struct ipv6hdr *ip6 __maybe_unused;
    struct iphdr *ip4 __maybe_unused;

    bpf_printk("bpf_host: do_netdev_encrypt_encap: proto=%x, src_id=%u", proto, src_id);

    if (!eth_is_supported_ethertype(proto)) {
        bpf_printk("bpf_host: do_netdev_encrypt_encap: Unsupported L2 proto=%x, returning DROP_UNSUPPORTED_L2", proto);
        return DROP_UNSUPPORTED_L2;
    }

    switch (proto) {
# ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            bpf_printk("bpf_host: do_netdev_encrypt_encap: Invalid IPv6 packet data, returning DROP_INVALID");
            return DROP_INVALID;
        }
        bpf_printk("bpf_host: do_netdev_encrypt_encap: IPv6 Dest=%x:%x:%x:%x",
                   ip6->daddr.s6_addr32[0], ip6->daddr.s6_addr32[1],
                   ip6->daddr.s6_addr32[2], ip6->daddr.s6_addr32[3]);
        ep = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
        break;
# endif /* ENABLE_IPV6 */
# ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            bpf_printk("bpf_host: do_netdev_encrypt_encap: Invalid IPv4 packet data, returning DROP_INVALID");
            return DROP_INVALID;
        }
        bpf_printk("bpf_host: do_netdev_encrypt_encap: IPv4 Dest=%x", ip4->daddr);
        ep = lookup_ip4_remote_endpoint(ip4->daddr, 0);
        break;
# endif /* ENABLE_IPV4 */
    }

    if (!ep || !ep->tunnel_endpoint) {
        bpf_printk("bpf_host: do_netdev_encrypt_encap: No tunnel endpoint found, returning DROP_NO_TUNNEL_ENDPOINT");
        return DROP_NO_TUNNEL_ENDPOINT;
    }

    bpf_printk("bpf_host: do_netdev_encrypt_encap: Found tunnel_endpoint=%u", ep->tunnel_endpoint);
    ctx->mark = 0;
    bpf_clear_meta(ctx);
    bpf_printk("bpf_host: do_netdev_encrypt_encap: Cleared mark and meta");

    int ret = encap_and_redirect_with_nodeid(ctx, ep->tunnel_endpoint, 0, src_id, 0, &trace);
    bpf_printk("bpf_host: do_netdev_encrypt_encap: encap_and_redirect_with_nodeid returned ret=%d", ret);
    return ret;
}
#endif /* ENABLE_IPSEC && TUNNEL_MODE */

#ifdef ENABLE_L2_ANNOUNCEMENTS
static __always_inline int handle_l2_announcement(struct __ctx_buff *ctx)
{
    union macaddr mac = THIS_INTERFACE_MAC;
    union macaddr smac;
    __be32 sip;
    __be32 tip;
    struct l2_responder_v4_key key;
    struct l2_responder_v4_stats *stats;
    int ret;
    __u32 index = RUNTIME_CONFIG_AGENT_LIVENESS;
    __u64 *time;

    bpf_printk("bpf_host: handle_l2_announcement: Entering");

    time = map_lookup_elem(&CONFIG_MAP, &index);
    if (!time) {
        bpf_printk("bpf_host: handle_l2_announcement: No time found in CONFIG_MAP, returning CTX_ACT_OK");
        return CTX_ACT_OK;
    }

    if (ktime_get_ns() - (*time) > L2_ANNOUNCEMENTS_MAX_LIVENESS) {
        bpf_printk("bpf_host: handle_l2_announcement: Agent not active, time diff=%llu, returning CTX_ACT_OK",
                   ktime_get_ns() - (*time));
        return CTX_ACT_OK;
    }

    if (!arp_validate(ctx, &mac, &smac, &sip, &tip)) {
        bpf_printk("bpf_host: handle_l2_announcement: ARP validation failed, returning CTX_ACT_OK");
        return CTX_ACT_OK;
    }

    bpf_printk("bpf_host: handle_l2_announcement: ARP validated, sip=%x, tip=%x", sip, tip);
    bpf_printk("bpf_host: handle_l2_announcement: Source MAC=%x:%x:%x:%x:%x:%x",
               smac.addr[0], smac.addr[1], smac.addr[2],
               smac.addr[3], smac.addr[4], smac.addr[5]);

    key.ip4 = tip;
    key.ifindex = ctx->ingress_ifindex;
    bpf_printk("bpf_host: handle_l2_announcement: Looking up L2_RESPONDER_MAP4 with ip4=%x, ifindex=%u", key.ip4, key.ifindex);
    stats = map_lookup_elem(&L2_RESPONDER_MAP4, &key);
    if (!stats) {
        bpf_printk("bpf_host: handle_l2_announcement: No stats found in L2_RESPONDER_MAP4, returning CTX_ACT_OK");
        return CTX_ACT_OK;
    }

    bpf_printk("bpf_host: handle_l2_announcement: Calling arp_respond with tip=%x, sip=%x", tip, sip);
    ret = arp_respond(ctx, &mac, tip, &smac, sip, 0);
    bpf_printk("bpf_host: handle_l2_announcement: arp_respond returned ret=%d", ret);

    if (ret == CTX_ACT_REDIRECT) {
        __sync_fetch_and_add(&stats->responses_sent, 1);
        bpf_printk("bpf_host: handle_l2_announcement: Incremented responses_sent in stats");
    }

    bpf_printk("bpf_host: handle_l2_announcement: Returning ret=%d", ret);
    return ret;
}
#endif

static __always_inline int
do_netdev(struct __ctx_buff *ctx, __u16 proto, __u32 __maybe_unused identity,
          enum trace_point obs_point, const bool __maybe_unused from_host)
{
    struct trace_ctx trace = {
        .reason = TRACE_REASON_UNKNOWN,
        .monitor = TRACE_PAYLOAD_LEN,
    };
    __u32 __maybe_unused ipcache_srcid = 0;
    void __maybe_unused *data, *data_end;
    struct ipv6hdr __maybe_unused *ip6;
    struct iphdr __maybe_unused *ip4;
    int __maybe_unused hdrlen = 0;
    __u8 __maybe_unused next_proto = 0;
    __s8 __maybe_unused ext_err = 0;
    int ret;

    bpf_printk("bpf_host: do_netdev: proto=%x, identity=%u, obs_point=%d, from_host=%d", proto, identity, obs_point, from_host);

    bpf_clear_meta(ctx);
    bpf_printk("bpf_host: do_netdev: Cleared meta");

    switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER || \
     defined ENABLE_L2_ANNOUNCEMENTS
    case bpf_htons(ETH_P_ARP):
        bpf_printk("bpf_host: do_netdev: Processing ARP packet");
        send_trace_notify(ctx, obs_point, UNKNOWN_ID, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
                          ctx->ingress_ifindex, trace.reason, trace.monitor);
        #ifdef ENABLE_L2_ANNOUNCEMENTS
            bpf_printk("bpf_host: do_netdev: Calling handle_l2_announcement");
            ret = handle_l2_announcement(ctx);
            bpf_printk("bpf_host: do_netdev: handle_l2_announcement returned ret=%d", ret);
        #else
            ret = CTX_ACT_OK;
            bpf_printk("bpf_host: do_netdev: ENABLE_L2_ANNOUNCEMENTS not defined, returning CTX_ACT_OK");
        #endif
        break;
# endif
#ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        if (!revalidate_data_pull(ctx, &data, &data_end, &ip6)) {
            bpf_printk("bpf_host: do_netdev: Invalid IPv6 packet data, sending drop notification");
            ret = send_drop_notify_error(ctx, identity, DROP_INVALID,
                                         CTX_ACT_DROP, METRIC_INGRESS);
            bpf_printk("bpf_host: do_netdev: send_drop_notify_error returned ret=%d", ret);
            return ret;
        }

        bpf_printk("bpf_host: do_netdev: IPv6 Source=%x:%x:%x:%x, Dest=%x:%x:%x:%x",
                   ip6->saddr.s6_addr32[0], ip6->saddr.s6_addr32[1],
                   ip6->saddr.s6_addr32[2], ip6->saddr.s6_addr32[3],
                   ip6->daddr.s6_addr32[0], ip6->daddr.s6_addr32[1],
                   ip6->daddr.s6_addr32[2], ip6->daddr.s6_addr32[3]);

        identity = resolve_srcid_ipv6(ctx, ip6, identity, &ipcache_srcid, from_host);
        bpf_printk("bpf_host: do_netdev: Resolved identity=%u, ipcache_srcid=%u", identity, ipcache_srcid);
        ctx_store_meta(ctx, CB_SRC_LABEL, identity);
        bpf_printk("bpf_host: do_netdev: Stored identity=%u in CB_SRC_LABEL", identity);

# if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV6)
        if (from_host) {
            ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, ipcache_srcid);
            bpf_printk("bpf_host: do_netdev: Stored ipcache_srcid=%u in CB_IPCACHE_SRC_LABEL", ipcache_srcid);
        }
# endif /* defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV6) */

# ifdef ENABLE_WIREGUARD
        if (!from_host) {
            next_proto = ip6->nexthdr;
            hdrlen = ipv6_hdrlen(ctx, &next_proto);
            bpf_printk("bpf_host: do_netdev: IPv6 next_proto=%u, hdrlen=%d", next_proto, hdrlen);
            if (likely(hdrlen > 0) &&
                ctx_is_wireguard(ctx, ETH_HLEN + hdrlen, next_proto, ipcache_srcid)) {
                trace.reason = TRACE_REASON_ENCRYPTED;
                bpf_printk("bpf_host: do_netdev: Packet is WireGuard, setting trace.reason to TRACE_REASON_ENCRYPTED");
            }
        }
# endif /* ENABLE_WIREGUARD */

        bpf_printk("bpf_host: do_netdev: Sending trace notification for IPv6");
        send_trace_notify(ctx, obs_point, ipcache_srcid, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
                          ctx->ingress_ifindex, trace.reason, trace.monitor);

        bpf_printk("bpf_host: do_netdev: Tail calling %s for IPv6",
                   from_host ? "CILIUM_CALL_IPV6_FROM_HOST" : "CILIUM_CALL_IPV6_FROM_NETDEV");
        ret = tail_call_internal(ctx, from_host ? CILIUM_CALL_IPV6_FROM_HOST :
                                                  CILIUM_CALL_IPV6_FROM_NETDEV,
                                 &ext_err);
        bpf_printk("bpf_host: do_netdev: tail_call_internal returned ret=%d, ext_err=%d", ret, ext_err);
        ret = send_drop_notify_error_ext(ctx, identity, ret, ext_err,
                                         CTX_ACT_OK, METRIC_INGRESS);
        bpf_printk("bpf_host: do_netdev: send_drop_notify_error_ext returned ret=%d", ret);
        return ret;
#endif
#ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
            bpf_printk("bpf_host: do_netdev: Invalid IPv4 packet data, sending drop notification");
            ret = send_drop_notify_error(ctx, identity, DROP_INVALID,
                                         CTX_ACT_DROP, METRIC_INGRESS);
            bpf_printk("bpf_host: do_netdev: send_drop_notify_error returned ret=%d", ret);
            return ret;
        }

        bpf_printk("bpf_host: do_netdev: IPv4 Source=%x, Dest=%x", ip4->saddr, ip4->daddr);

        identity = resolve_srcid_ipv4(ctx, ip4, identity, &ipcache_srcid, from_host);
        bpf_printk("bpf_host: do_netdev: Resolved identity=%u, ipcache_srcid=%u", identity, ipcache_srcid);
        ctx_store_meta(ctx, CB_SRC_LABEL, identity);
        bpf_printk("bpf_host: do_netdev: Stored identity=%u in CB_SRC_LABEL", identity);

# if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV4)
        if (from_host) {
            ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, ipcache_srcid);
            bpf_printk("bpf_host: do_netdev: Stored ipcache_srcid=%u in CB_IPCACHE_SRC_LABEL", ipcache_srcid);
        }
# endif /* defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV4) */

#ifdef ENABLE_WIREGUARD
        if (!from_host) {
            next_proto = ip4->protocol;
            hdrlen = ipv4_hdrlen(ip4);
            bpf_printk("bpf_host: do_netdev: IPv4 next_proto=%u, hdrlen=%d", next_proto, hdrlen);
            if (ctx_is_wireguard(ctx, ETH_HLEN + hdrlen, next_proto, ipcache_srcid)) {
                trace.reason = TRACE_REASON_ENCRYPTED;
                bpf_printk("bpf_host: do_netdev: Packet is WireGuard, setting trace.reason to TRACE_REASON_ENCRYPTED");
            }
        }
#endif /* ENABLE_WIREGUARD */

        bpf_printk("bpf_host: do_netdev: Sending trace notification for IPv4");
        send_trace_notify(ctx, obs_point, ipcache_srcid, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
                          ctx->ingress_ifindex, trace.reason, trace.monitor);

        bpf_printk("bpf_host: do_netdev: Tail calling %s for IPv4",
                   from_host ? "CILIUM_CALL_IPV4_FROM_HOST" : "CILIUM_CALL_IPV4_FROM_NETDEV");
        ret = tail_call_internal(ctx, from_host ? CILIUM_CALL_IPV4_FROM_HOST :
                                                  CILIUM_CALL_IPV4_FROM_NETDEV,
                                 &ext_err);
        bpf_printk("bpf_host: do_netdev: tail_call_internal returned ret=%d, ext_err=%d", ret, ext_err);
        ret = send_drop_notify_error_ext(ctx, identity, ret, ext_err,
                                         CTX_ACT_OK, METRIC_INGRESS);
        bpf_printk("bpf_host: do_netdev: send_drop_notify_error_ext returned ret=%d", ret);
        return ret;
#endif /* ENABLE_IPV4 */
    default:
        bpf_printk("bpf_host: do_netdev: Unknown protocol=%x", proto);
        send_trace_notify(ctx, obs_point, UNKNOWN_ID, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
                          ctx->ingress_ifindex, trace.reason, trace.monitor);
#ifdef ENABLE_HOST_FIREWALL
        bpf_printk("bpf_host: do_netdev: ENABLE_HOST_FIREWALL enabled, sending drop notification for unknown L3");
        ret = send_drop_notify_error(ctx, identity, DROP_UNKNOWN_L3,
                                     CTX_ACT_DROP, METRIC_INGRESS);
        bpf_printk("bpf_host: do_netdev: send_drop_notify_error returned ret=%d", ret);
#else
        ret = CTX_ACT_OK;
        bpf_printk("bpf_host: do_netdev: ENABLE_HOST_FIREWALL not enabled, passing unknown traffic to stack, returning CTX_ACT_OK");
#endif /* ENABLE_HOST_FIREWALL */
        break;
    }

    bpf_printk("bpf_host: do_netdev: Returning ret=%d", ret);
    return ret;
}

__section_entry
int cil_from_netdev(struct __ctx_buff *ctx)
{
    __u32 src_id = UNKNOWN_ID;
    __be16 proto = 0;

#ifdef ENABLE_NODEPORT_ACCELERATION
    __u32 flags = ctx_get_xfer(ctx, XFER_FLAGS);
    bpf_printk("bpf_host: cil_from_netdev: XFER_FLAGS=%u", flags);
#endif
    int ret;

    bpf_printk("bpf_host: cil_from_netdev: Entering");

    if (ctx->vlan_present) {
        __u32 vlan_id = ctx->vlan_tci & 0xfff;
        bpf_printk("bpf_host: cil_from_netdev: VLAN present, vlan_id=%u", vlan_id);

        if (vlan_id) {
            bpf_printk("bpf_host: cil_from_netdev: Checking VLAN filter for vlan_id=%u", vlan_id);
            if (allow_vlan(ctx->ifindex, vlan_id)) {
                bpf_printk("bpf_host: cil_from_netdev: VLAN allowed, returning CTX_ACT_OK");
                return CTX_ACT_OK;
            }

            ret = DROP_VLAN_FILTERED;
            bpf_printk("bpf_host: cil_from_netdev: VLAN filtered, ret=%d, proceeding to drop", ret);
            goto drop_err;
        }
    }

    ctx_skip_nodeport_clear(ctx);
    bpf_printk("bpf_host: cil_from_netdev: Cleared NodePort skip flag");

#ifdef ENABLE_NODEPORT_ACCELERATION
    if (flags & XFER_PKT_NO_SVC) {
        ctx_skip_nodeport_set(ctx);
        bpf_printk("bpf_host: cil_from_netdev: XFER_PKT_NO_SVC set, skipping NodePort");
    }

#ifdef HAVE_ENCAP
    if (flags & XFER_PKT_SNAT_DONE) {
        ctx_snat_done_set(ctx);
        bpf_printk("bpf_host: cil_from_netdev: XFER_PKT_SNAT_DONE set, marking SNAT as done");
    }
#endif
#endif

    if (!validate_ethertype(ctx, &proto)) {
#ifdef ENABLE_HOST_FIREWALL
        ret = DROP_UNSUPPORTED_L2;
        bpf_printk("bpf_host: cil_from_netdev: Unsupported L2, ret=%d, proceeding to drop", ret);
        goto drop_err;
#else
        bpf_printk("bpf_host: cil_from_netdev: Unsupported L2, sending trace notification to stack");
        send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
                          TRACE_EP_ID_UNKNOWN,
                          TRACE_IFINDEX_UNKNOWN, TRACE_REASON_UNKNOWN, 0);
        bpf_printk("bpf_host: cil_from_netdev: Passing unknown traffic to stack, returning CTX_ACT_OK");
        return CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */
    }

#ifdef ENABLE_IPSEC
    bpf_printk("bpf_host: cil_from_netdev: Calling do_decrypt with proto=%x", proto);
    do_decrypt(ctx, proto);
    if (ctx->mark == MARK_MAGIC_DECRYPT) {
        bpf_printk("bpf_host: cil_from_netdev: Packet needs decryption, returning CTX_ACT_OK");
        return CTX_ACT_OK;
    }
    bpf_printk("bpf_host: cil_from_netdev: No decryption needed or already decrypted");
#endif

    bpf_printk("bpf_host: cil_from_netdev: Calling do_netdev with proto=%x", proto);
    ret = do_netdev(ctx, proto, UNKNOWN_ID, TRACE_FROM_NETWORK, false);
    bpf_printk("bpf_host: cil_from_netdev: do_netdev returned ret=%d", ret);
    return ret;

drop_err:
    bpf_printk("bpf_host: cil_from_netdev: Sending drop notification, ret=%d", ret);
    ret = send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP, METRIC_INGRESS);
    bpf_printk("bpf_host: cil_from_netdev: send_drop_notify_error returned ret=%d", ret);
    return ret;
}

__section_entry
int cil_from_host(struct __ctx_buff *ctx)
{
    enum trace_point obs_point = TRACE_FROM_HOST;
    __u32 identity = UNKNOWN_ID;
    int ret __maybe_unused;
    __be16 proto = 0;
    __u32 magic;

    bpf_printk("bpf_host: cil_from_host: Entering");

    edt_set_aggregate(ctx, 0);
    bpf_printk("bpf_host: cil_from_host: Disabled EDT rate-limiting");

    if (!validate_ethertype(ctx, &proto)) {
        __u32 dst_sec_identity = UNKNOWN_ID;
        __u32 src_sec_identity = HOST_ID;

#ifdef ENABLE_HOST_FIREWALL
        bpf_printk("bpf_host: cil_from_host: Unsupported L2, sending drop notification");
        ret = send_drop_notify(ctx, src_sec_identity, dst_sec_identity,
                               TRACE_EP_ID_UNKNOWN, DROP_UNSUPPORTED_L2,
                               CTX_ACT_DROP, METRIC_EGRESS);
        bpf_printk("bpf_host: cil_from_host: send_drop_notify returned ret=%d", ret);
        return ret;
#else
        bpf_printk("bpf_host: cil_from_host: Unsupported L2, sending trace notification to stack");
        send_trace_notify(ctx, TRACE_TO_STACK, src_sec_identity, dst_sec_identity,
                          TRACE_EP_ID_UNKNOWN,
                          TRACE_IFINDEX_UNKNOWN, TRACE_REASON_UNKNOWN, 0);
        bpf_printk("bpf_host: cil_from_host: Passing unknown traffic to stack, returning CTX_ACT_OK");
        return CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */
    }

    bpf_printk("bpf_host: cil_from_host: Inheriting identity from host");
    magic = inherit_identity_from_host(ctx, &identity);
    bpf_printk("bpf_host: cil_from_host: Inherited magic=%u, identity=%u", magic, identity);

    if (magic == MARK_MAGIC_PROXY_INGRESS || magic == MARK_MAGIC_PROXY_EGRESS) {
        obs_point = TRACE_FROM_PROXY;
        bpf_printk("bpf_host: cil_from_host: Packet from proxy, setting obs_point to TRACE_FROM_PROXY");
    }

#if defined(ENABLE_L7_LB)
    if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
        bpf_printk("bpf_host: cil_from_host: Packet from proxy egress EPID, tail calling egress policy with identity=%u", identity);
        ret = tail_call_egress_policy(ctx, (__u16)identity);
        bpf_printk("bpf_host: cil_from_host: tail_call_egress_policy returned ret=%d", ret);
        ret = send_drop_notify_error(ctx, UNKNOWN_ID, ret, CTX_ACT_DROP, METRIC_EGRESS);
        bpf_printk("bpf_host: cil_from_host: send_drop_notify_error returned ret=%d", ret);
        return ret;
    }
#endif

#ifdef ENABLE_IPSEC
    if (magic == MARK_MAGIC_ENCRYPT) {
        ret = CTX_ACT_OK;

        bpf_printk("bpf_host: cil_from_host: magic=MARK_MAGIC_ENCRYPT, sending trace notification");
        send_trace_notify(ctx, TRACE_FROM_STACK, identity, UNKNOWN_ID,
                          TRACE_EP_ID_UNKNOWN,
                          ctx->ingress_ifindex, TRACE_REASON_ENCRYPTED, 0);

# ifdef TUNNEL_MODE
        bpf_printk("bpf_host: cil_from_host: Calling do_netdev_encrypt_encap with proto=%x, identity=%u", proto, identity);
        ret = do_netdev_encrypt_encap(ctx, proto, identity);
        bpf_printk("bpf_host: cil_from_host: do_netdev_encrypt_encap returned ret=%d", ret);
        if (IS_ERR(ret)) {
            bpf_printk("bpf_host: cil_from_host: Error in do_netdev_encrypt_encap, sending drop notification, ret=%d", ret);
            ret = send_drop_notify_error(ctx, identity, ret, CTX_ACT_DROP, METRIC_EGRESS);
            bpf_printk("bpf_host: cil_from_host: send_drop_notify_error returned ret=%d", ret);
            return ret;
        }
# endif /* TUNNEL_MODE */
        bpf_printk("bpf_host: cil_from_host: Returning ret=%d", ret);
        return ret;
    }
#endif /* ENABLE_IPSEC */

    bpf_printk("bpf_host: cil_from_host: Calling do_netdev with proto=%x, identity=%u, obs_point=%d", proto, identity, obs_point);
    ret = do_netdev(ctx, proto, identity, obs_point, true);
    bpf_printk("bpf_host: cil_from_host: do_netdev returned ret=%d", ret);
    return ret;
}

/*
 * to-netdev is attached as a tc egress filter to one or more physical devices
 * managed by Cilium (e.g., eth0).
 */
__section_entry
int cil_to_netdev(struct __ctx_buff *ctx)
{
    __u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;
    __u32 dst_sec_identity = UNKNOWN_ID;
    __u32 src_sec_identity = UNKNOWN_ID;
    struct trace_ctx trace = {
        .reason = TRACE_REASON_UNKNOWN,
        .monitor = 0,
    };
    __be16 __maybe_unused proto = 0;
    __u32 vlan_id;
    int ret = CTX_ACT_OK;
    __s8 ext_err = 0;

    bpf_printk("bpf_host: cil_to_netdev: Entering, magic=%u", magic);

    bpf_clear_meta(ctx);
    bpf_printk("bpf_host: cil_to_netdev: Cleared meta");

    if (magic == MARK_MAGIC_HOST || magic == MARK_MAGIC_OVERLAY) {
        src_sec_identity = HOST_ID;
        bpf_printk("bpf_host: cil_to_netdev: magic is MARK_MAGIC_HOST or MARK_MAGIC_OVERLAY, src_sec_identity=%u", src_sec_identity);
    } else if (magic == MARK_MAGIC_IDENTITY) {
        src_sec_identity = get_identity(ctx);
        bpf_printk("bpf_host: cil_to_netdev: magic is MARK_MAGIC_IDENTITY, src_sec_identity=%u", src_sec_identity);
    } else {
        bpf_printk("bpf_host: cil_to_netdev: Unknown magic value, src_sec_identity remains %u", src_sec_identity);
    }

    if (ctx->vlan_present) {
        vlan_id = ctx->vlan_tci & 0xfff;
        bpf_printk("bpf_host: cil_to_netdev: VLAN present, vlan_id=%u", vlan_id);

        if (vlan_id) {
            bpf_printk("bpf_host: cil_to_netdev: Checking VLAN filter for vlan_id=%u", vlan_id);
            if (allow_vlan(ctx->ifindex, vlan_id)) {
                bpf_printk("bpf_host: cil_to_netdev: VLAN allowed, returning CTX_ACT_OK");
                return CTX_ACT_OK;
            }

            ret = DROP_VLAN_FILTERED;
            bpf_printk("bpf_host: cil_to_netdev: VLAN filtered, ret=%d, proceeding to drop", ret);
            goto drop_err;
        }
    }

#if defined(ENABLE_L7_LB)
    if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
        __u32 lxc_id = get_epid(ctx);

        bpf_printk("bpf_host: cil_to_netdev: magic=MARK_MAGIC_PROXY_EGRESS_EPID, lxc_id=%u", lxc_id);
        ctx->mark = 0;
        bpf_printk("bpf_host: cil_to_netdev: Cleared mark");
        bpf_printk("bpf_host: cil_to_netdev: Tail calling egress policy with lxc_id=%u", lxc_id);
        ret = tail_call_egress_policy(ctx, (__u16)lxc_id);
        bpf_printk("bpf_host: cil_to_netdev: tail_call_egress_policy returned ret=%d", ret);
        goto drop_err;
    }
#endif

    bpf_printk("bpf_host: cil_to_netdev: Validating ethertype");
    validate_ethertype(ctx, &proto);
    bpf_printk("bpf_host: cil_to_netdev: proto=%x", proto);

#ifdef ENABLE_HOST_FIREWALL
    if (ctx_snat_done(ctx)) {
        bpf_printk("bpf_host: cil_to_netdev: SNAT done, skipping host firewall");
        goto skip_host_firewall;
    }

    if (!eth_is_supported_ethertype(proto)) {
        ret = DROP_UNSUPPORTED_L2;
        bpf_printk("bpf_host: cil_to_netdev: Unsupported L2 proto=%x, ret=%d, proceeding to drop", proto, ret);
        goto drop_err;
    }

    bpf_printk("bpf_host: cil_to_netdev: Processing proto=%x", proto);
    switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
    case bpf_htons(ETH_P_ARP):
        ret = CTX_ACT_OK;
        bpf_printk("bpf_host: cil_to_netdev: ARP packet, returning CTX_ACT_OK");
        break;
# endif
# ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        bpf_printk("bpf_host: cil_to_netdev: IPv6 packet, calling handle_to_netdev_ipv6");
        ret = handle_to_netdev_ipv6(ctx, src_sec_identity, &trace, &ext_err);
        bpf_printk("bpf_host: cil_to_netdev: handle_to_netdev_ipv6 returned ret=%d, ext_err=%d", ret, ext_err);
        break;
# endif
# ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        bpf_printk("bpf_host: cil_to_netdev: IPv4 packet, calling handle_to_netdev_ipv4");
        ret = handle_to_netdev_ipv4(ctx, src_sec_identity, &trace, &ext_err);
        bpf_printk("bpf_host: cil_to_netdev: handle_to_netdev_ipv4 returned ret=%d, ext_err=%d", ret, ext_err);
        break;
# endif
    default:
        ret = DROP_UNKNOWN_L3;
        bpf_printk("bpf_host: cil_to_netdev: Unknown L3 proto=%x, ret=%d", proto, ret);
        break;
    }

    if (ret == CTX_ACT_REDIRECT) {
        bpf_printk("bpf_host: cil_to_netdev: Redirect required, returning ret=%d", ret);
        return ret;
    }

    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: cil_to_netdev: Error occurred, ret=%d, proceeding to drop", ret);
        goto drop_err;
    }

skip_host_firewall:
#endif /* ENABLE_HOST_FIREWALL */

    bpf_printk("bpf_host: cil_to_netdev: Calling host_egress_policy_hook");
    ret = host_egress_policy_hook(ctx, src_sec_identity, &ext_err);
    bpf_printk("bpf_host: cil_to_netdev: host_egress_policy_hook returned ret=%d, ext_err=%d", ret, ext_err);
    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: cil_to_netdev: Error in host_egress_policy_hook, ret=%d, proceeding to drop", ret);
        goto drop_err;
    }

#if defined(ENABLE_BANDWIDTH_MANAGER)
    bpf_printk("bpf_host: cil_to_netdev: Scheduling departure with EDT");
    ret = edt_sched_departure(ctx, proto);
    if (ret == CTX_ACT_DROP) {
        bpf_printk("bpf_host: cil_to_netdev: EDT rate-limiting dropped packet, updating metrics");
        update_metrics(ctx_full_len(ctx), METRIC_EGRESS, -DROP_EDT_HORIZON);
        bpf_printk("bpf_host: cil_to_netdev: Returning ret=%d due to EDT drop", ret);
        return ret;
    }
    bpf_printk("bpf_host: cil_to_netdev: edt_sched_departure returned ret=%d", ret);
#endif

#if defined(ENABLE_ENCRYPTED_OVERLAY)
    if (ctx_is_overlay(ctx) && get_identity(ctx) == ENCRYPTED_OVERLAY_ID) {
        bpf_printk("bpf_host: cil_to_netdev: Overlay traffic with ENCRYPTED_OVERLAY_ID, encrypting and redirecting");
        ret = encrypt_overlay_and_redirect(ctx);
        bpf_printk("bpf_host: cil_to_netdev: encrypt_overlay_and_redirect returned ret=%d", ret);
        if (ret == CTX_ACT_REDIRECT) {
            bpf_printk("bpf_host: cil_to_netdev: Redirecting to stack, sending trace notification");
            send_trace_notify(ctx, TRACE_TO_STACK, src_sec_identity,
                              dst_sec_identity,
                              TRACE_EP_ID_UNKNOWN, THIS_INTERFACE_IFINDEX,
                              TRACE_REASON_ENCRYPT_OVERLAY, 0);
            bpf_printk("bpf_host: cil_to_netdev: Returning ret=%d", ret);
            return ret;
        }
        if (IS_ERR(ret)) {
            bpf_printk("bpf_host: cil_to_netdev: Error in encrypt_overlay_and_redirect, ret=%d, proceeding to drop", ret);
            goto drop_err;
        }
    }
#endif /* ENABLE_ENCRYPTED_OVERLAY */

#ifdef ENABLE_WIREGUARD
    if (!ctx_mark_is_wireguard(ctx)) {
        bpf_printk("bpf_host: cil_to_netdev: Packet not marked as WireGuard, calling host_wg_encrypt_hook");
        ret = host_wg_encrypt_hook(ctx, proto);
        bpf_printk("bpf_host: cil_to_netdev: host_wg_encrypt_hook returned ret=%d", ret);
        if (ret == CTX_ACT_REDIRECT) {
            bpf_printk("bpf_host: cil_to_netdev: Redirect required by WireGuard, returning ret=%d", ret);
            return ret;
        } else if (IS_ERR(ret)) {
            bpf_printk("bpf_host: cil_to_netdev: Error in host_wg_encrypt_hook, ret=%d, proceeding to drop", ret);
            goto drop_err;
        }
    } else {
        trace.reason |= TRACE_REASON_ENCRYPTED;
        bpf_printk("bpf_host: cil_to_netdev: Packet already encrypted by WireGuard, setting trace.reason to TRACE_REASON_ENCRYPTED");
    }

#if defined(ENCRYPTION_STRICT_MODE)
    if (!strict_allow(ctx, proto)) {
        ret = DROP_UNENCRYPTED_TRAFFIC;
        bpf_printk("bpf_host: cil_to_netdev: Strict mode: unencrypted traffic not allowed, ret=%d, proceeding to drop", ret);
        goto drop_err;
    }
#endif /* ENCRYPTION_STRICT_MODE */
#endif /* ENABLE_WIREGUARD */

#ifdef ENABLE_HEALTH_CHECK
    bpf_printk("bpf_host: cil_to_netdev: Handling health check");
    ret = lb_handle_health(ctx, proto);
    bpf_printk("bpf_host: cil_to_netdev: lb_handle_health returned ret=%d", ret);
    if (ret != CTX_ACT_OK) {
        bpf_printk("bpf_host: cil_to_netdev: Health check result not OK, proceeding to exit");
        goto exit;
    }
#endif

#ifdef ENABLE_EGRESS_GATEWAY_COMMON
    {
        void *data, *data_end;
        struct iphdr *ip4;
        struct ipv4_ct_tuple tuple = {};
        int l4_off;
        struct remote_endpoint_info *info;
        struct endpoint_info *src_ep;
        bool is_reply;

        if (src_sec_identity == HOST_ID) {
            bpf_printk("bpf_host: cil_to_netdev: src_sec_identity is HOST_ID, skipping egress gateway");
            goto skip_egress_gateway;
        }

        if (proto != bpf_htons(ETH_P_IP)) {
            bpf_printk("bpf_host: cil_to_netdev: proto=%x is not IPv4, skipping egress gateway", proto);
            goto skip_egress_gateway;
        }

        if (ctx_egw_done(ctx)) {
            bpf_printk("bpf_host: cil_to_netdev: Egress gateway already done, skipping");
            goto skip_egress_gateway;
        }

        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            ret = DROP_INVALID;
            bpf_printk("bpf_host: cil_to_netdev: Invalid IPv4 packet data, ret=%d, proceeding to drop", ret);
            goto drop_err;
        }

        bpf_printk("bpf_host: cil_to_netdev: IPv4 Source=%x, Dest=%x", ip4->saddr, ip4->daddr);

        tuple.nexthdr = ip4->protocol;
        tuple.daddr = ip4->daddr;
        tuple.saddr = ip4->saddr;

        l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
        bpf_printk("bpf_host: cil_to_netdev: Extracting ports, l4_off=%d", l4_off);
        ret = ct_extract_ports4(ctx, ip4, l4_off, CT_EGRESS, &tuple, NULL);
        bpf_printk("bpf_host: cil_to_netdev: ct_extract_ports4 returned ret=%d", ret);
        if (IS_ERR(ret)) {
            if (ret == DROP_CT_UNKNOWN_PROTO) {
                bpf_printk("bpf_host: cil_to_netdev: Unknown CT protocol, skipping egress gateway");
                goto skip_egress_gateway;
            }
            bpf_printk("bpf_host: cil_to_netdev: Error in ct_extract_ports4, ret=%d, proceeding to drop", ret);
            goto drop_err;
        }

        bpf_printk("bpf_host: cil_to_netdev: Checking if packet is a reply");
        is_reply = ct_is_reply4(get_ct_map4(&tuple), &tuple);
        bpf_printk("bpf_host: cil_to_netdev: is_reply=%d", is_reply);
        if (is_reply) {
            bpf_printk("bpf_host: cil_to_netdev: Packet is a reply, skipping egress gateway");
            goto skip_egress_gateway;
        }

        bpf_printk("bpf_host: cil_to_netdev: Looking up source endpoint for IP=%x", ip4->saddr);
        src_ep = __lookup_ip4_endpoint(ip4->saddr);
        if (src_ep) {
            src_sec_identity = src_ep->sec_id;
            bpf_printk("bpf_host: cil_to_netdev: Source endpoint found, src_sec_identity=%u", src_sec_identity);
        }

        bpf_printk("bpf_host: cil_to_netdev: Looking up remote endpoint for dest IP=%x", ip4->daddr);
        info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
        if (info && info->sec_identity) {
            dst_sec_identity = info->sec_identity;
            bpf_printk("bpf_host: cil_to_netdev: Remote endpoint found, dst_sec_identity=%u", dst_sec_identity);
        }

        bpf_printk("bpf_host: cil_to_netdev: Reversing CT tuple");
        __ipv4_ct_tuple_reverse(&tuple);
        bpf_printk("bpf_host: cil_to_netdev: Handling egress gateway packet");
        ret = egress_gw_handle_packet(ctx, &tuple, src_sec_identity, dst_sec_identity, &trace);
        bpf_printk("bpf_host: cil_to_netdev: egress_gw_handle_packet returned ret=%d", ret);
        if (IS_ERR(ret)) {
            bpf_printk("bpf_host: cil_to_netdev: Error in egress_gw_handle_packet, ret=%d, proceeding to drop", ret);
            goto drop_err;
        }

        if (ret != CTX_ACT_OK) {
            bpf_printk("bpf_host: cil_to_netdev: egress_gw_handle_packet returned non-OK, returning ret=%d", ret);
            return ret;
        }
    }
skip_egress_gateway:
#endif

#ifdef ENABLE_NODEPORT
    if (!ctx_snat_done(ctx) && !ctx_is_overlay(ctx) && !ctx_mark_is_wireguard(ctx)) {
        bpf_printk("bpf_host: cil_to_netdev: Handling NAT forwarding");
        ret = handle_nat_fwd(ctx, 0, proto, false, &trace, &ext_err);
        bpf_printk("bpf_host: cil_to_netdev: handle_nat_fwd returned ret=%d, ext_err=%d", ret, ext_err);
        if (ret == CTX_ACT_REDIRECT) {
            bpf_printk("bpf_host: cil_to_netdev: Redirect required by NAT, returning ret=%d", ret);
            return ret;
        }
    } else {
        bpf_printk("bpf_host: cil_to_netdev: Skipping NAT forwarding: SNAT done=%d, is_overlay=%d, is_wireguard=%d",
                   ctx_snat_done(ctx), ctx_is_overlay(ctx), ctx_mark_is_wireguard(ctx));
    }
#endif

#ifdef ENABLE_HEALTH_CHECK
exit:
#endif
    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: cil_to_netdev: Error occurred, ret=%d, proceeding to drop", ret);
        goto drop_err;
    }

    bpf_printk("bpf_host: cil_to_netdev: Sending trace notification to network");
    send_trace_notify(ctx, TRACE_TO_NETWORK, src_sec_identity, dst_sec_identity,
                      TRACE_EP_ID_UNKNOWN,
                      THIS_INTERFACE_IFINDEX, trace.reason, trace.monitor);

    bpf_printk("bpf_host: cil_to_netdev: Returning ret=%d", ret);
    return ret;

drop_err:
    bpf_printk("bpf_host: cil_to_netdev: Sending drop notification, ret=%d, ext_err=%d", ret, ext_err);
    ret = send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
                                     CTX_ACT_DROP, METRIC_EGRESS);
    bpf_printk("bpf_host: cil_to_netdev: send_drop_notify_error_ext returned ret=%d", ret);
    return ret;
}

/*
 * to-host is attached as a tc ingress filter to both the 'cilium_host' and
 * 'cilium_net' devices if present.
 */
__section_entry
int cil_to_host(struct __ctx_buff *ctx)
{
    __u32 magic = ctx_load_meta(ctx, CB_PROXY_MAGIC);
    __u16 __maybe_unused proto = 0;
    struct trace_ctx trace = {
        .reason = TRACE_REASON_UNKNOWN,
        .monitor = 0,
    };
    int ret = CTX_ACT_OK;
    bool traced = false;
    __u32 src_id = 0;
    __s8 ext_err = 0;

    bpf_printk("bpf_host: cil_to_host: Entering, CB_PROXY_MAGIC=%u", magic);

    if (((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) ||
        ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_TO_PROXY)) {
        magic = ctx->mark;
        bpf_printk("bpf_host: cil_to_host: Using ctx->mark=%u as magic", magic);
    }

    if ((magic & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) {
        ctx->mark = magic;
        src_id = ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY);
        bpf_printk("bpf_host: cil_to_host: magic=MARK_MAGIC_ENCRYPT, src_id=%u", src_id);
    } else if ((magic & 0xFFFF) == MARK_MAGIC_TO_PROXY) {
        __be16 port = magic >> 16;
        traced = true;

        bpf_printk("bpf_host: cil_to_host: magic=MARK_MAGIC_TO_PROXY, port=%u, traced=%d", port, traced);
        ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);
        bpf_printk("bpf_host: cil_to_host: Cleared CB_PROXY_MAGIC");
        bpf_printk("bpf_host: cil_to_host: Redirecting to proxy, port=%u", port);
        ret = ctx_redirect_to_proxy_first(ctx, port);
        bpf_printk("bpf_host: cil_to_host: ctx_redirect_to_proxy_first returned ret=%d", ret);
        goto out;
    }

#ifdef ENABLE_IPSEC
    bpf_printk("bpf_host: cil_to_host: Changing packet type to PACKET_HOST for IPsec");
    ctx_change_type(ctx, PACKET_HOST);

# ifdef ENABLE_NODEPORT
    if ((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_ENCRYPT) {
        bpf_printk("bpf_host: cil_to_host: mark is not MARK_MAGIC_ENCRYPT, skipping IPsec NodePort revdnat");
        goto skip_ipsec_nodeport_revdnat;
    }

    bpf_printk("bpf_host: cil_to_host: Validating ethertype for IPsec NodePort");
    if (!validate_ethertype(ctx, &proto)) {
        bpf_printk("bpf_host: cil_to_host: Invalid ethertype, skipping IPsec NodePort revdnat");
        goto skip_ipsec_nodeport_revdnat;
    }

    bpf_printk("bpf_host: cil_to_host: Handling NAT forwarding for IPsec, proto=%x", proto);
    ret = handle_nat_fwd(ctx, 0, proto, true, &trace, &ext_err);
    bpf_printk("bpf_host: cil_to_host: handle_nat_fwd returned ret=%d, ext_err=%d", ret, ext_err);
    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: cil_to_host: Error in handle_nat_fwd, ret=%d, proceeding to out", ret);
        goto out;
    }

skip_ipsec_nodeport_revdnat:
# endif /* ENABLE_NODEPORT */
#endif /* ENABLE_IPSEC */

#ifdef ENABLE_HOST_FIREWALL
    bpf_printk("bpf_host: cil_to_host: Validating ethertype for host firewall");
    if (!validate_ethertype(ctx, &proto)) {
        ret = DROP_UNSUPPORTED_L2;
        bpf_printk("bpf_host: cil_to_host: Unsupported L2, ret=%d, proceeding to out", ret);
        goto out;
    }

    bpf_printk("bpf_host: cil_to_host: Processing proto=%x", proto);
    switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
    case bpf_htons(ETH_P_ARP):
        ret = CTX_ACT_OK;
        bpf_printk("bpf_host: cil_to_host: ARP packet, returning CTX_ACT_OK");
        break;
# endif
# ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        ctx_store_meta(ctx, CB_SRC_LABEL, src_id);
        ctx_store_meta(ctx, CB_TRACED, traced);
        bpf_printk("bpf_host: cil_to_host: IPv6 packet, stored src_id=%u, traced=%d", src_id, traced);
        bpf_printk("bpf_host: cil_to_host: Tail calling CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY");
        ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY, &ext_err);
        bpf_printk("bpf_host: cil_to_host: tail_call_internal returned ret=%d, ext_err=%d", ret, ext_err);
        break;
# endif
# ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        ctx_store_meta(ctx, CB_SRC_LABEL, src_id);
        ctx_store_meta(ctx, CB_TRACED, traced);
        bpf_printk("bpf_host: cil_to_host: IPv4 packet, stored src_id=%u, traced=%d", src_id, traced);
        bpf_printk("bpf_host: cil_to_host: Tail calling CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY");
        ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY, &ext_err);
        bpf_printk("bpf_host: cil_to_host: tail_call_internal returned ret=%d, ext_err=%d", ret, ext_err);
        break;
# endif
    default:
        ret = DROP_UNKNOWN_L3;
        bpf_printk("bpf_host: cil_to_host: Unknown L3 proto=%x, ret=%d", proto, ret);
        break;
    }
#else
    ret = CTX_ACT_OK;
    bpf_printk("bpf_host: cil_to_host: ENABLE_HOST_FIREWALL not enabled, returning CTX_ACT_OK");
#endif /* ENABLE_HOST_FIREWALL */

out:
    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: cil_to_host: Error occurred, ret=%d, sending drop notification", ret);
        ret = send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
        bpf_printk("bpf_host: cil_to_host: send_drop_notify_error_ext returned ret=%d", ret);
        return ret;
    }

    if (!traced) {
        bpf_printk("bpf_host: cil_to_host: Sending trace notification to stack");
        send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
                          TRACE_EP_ID_UNKNOWN,
                          CILIUM_HOST_IFINDEX, trace.reason, trace.monitor);
    }

    bpf_printk("bpf_host: cil_to_host: Returning ret=%d", ret);
    return ret;
}

#if defined(ENABLE_HOST_FIREWALL)
#ifdef ENABLE_IPV6
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY)
static __always_inline
int tail_ipv6_host_policy_ingress(struct __ctx_buff *ctx)
{
    struct trace_ctx trace = {
        .reason = TRACE_REASON_UNKNOWN,
        .monitor = 0,
    };
    __u32 src_id = ctx_load_meta(ctx, CB_SRC_LABEL);
    bool traced = ctx_load_meta(ctx, CB_TRACED);
    int ret;
    __s8 ext_err = 0;

    bpf_printk("bpf_host: tail_ipv6_host_policy_ingress: src_id=%u, traced=%d", src_id, traced);

    bpf_printk("bpf_host: tail_ipv6_host_policy_ingress: Applying IPv6 ingress policy");
    ret = ipv6_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
    bpf_printk("bpf_host: tail_ipv6_host_policy_ingress: ipv6_host_policy_ingress returned ret=%d, ext_err=%d", ret, ext_err);

    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: tail_ipv6_host_policy_ingress: Error occurred, ret=%d, sending drop notification", ret);
        ret = send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
        bpf_printk("bpf_host: tail_ipv6_host_policy_ingress: send_drop_notify_error_ext returned ret=%d", ret);
        return ret;
    }

    if (!traced) {
        bpf_printk("bpf_host: tail_ipv6_host_policy_ingress: Sending trace notification to stack");
        send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
                          TRACE_EP_ID_UNKNOWN,
                          CILIUM_HOST_IFINDEX, trace.reason, trace.monitor);
    }

    bpf_printk("bpf_host: tail_ipv6_host_policy_ingress: Returning ret=%d", ret);
    return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY)
static __always_inline
int tail_ipv4_host_policy_ingress(struct __ctx_buff *ctx)
{
    struct trace_ctx trace = {
        .reason = TRACE_REASON_UNKNOWN,
        .monitor = TRACE_PAYLOAD_LEN,
    };
    __u32 src_id = ctx_load_meta(ctx, CB_SRC_LABEL);
    bool traced = ctx_load_meta(ctx, CB_TRACED);
    int ret;
    __s8 ext_err = 0;

    bpf_printk("bpf_host: tail_ipv4_host_policy_ingress: src_id=%u, traced=%d", src_id, traced);

    bpf_printk("bpf_host: tail_ipv4_host_policy_ingress: Applying IPv4 ingress policy");
    ret = ipv4_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
    bpf_printk("bpf_host: tail_ipv4_host_policy_ingress: ipv4_host_policy_ingress returned ret=%d, ext_err=%d", ret, ext_err);

    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: tail_ipv4_host_policy_ingress: Error occurred, ret=%d, sending drop notification", ret);
        ret = send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
        bpf_printk("bpf_host: tail_ipv4_host_policy_ingress: send_drop_notify_error_ext returned ret=%d", ret);
        return ret;
    }

    if (!traced) {
        bpf_printk("bpf_host: tail_ipv4_host_policy_ingress: Sending trace notification to stack");
        send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
                          TRACE_EP_ID_UNKNOWN,
                          CILIUM_HOST_IFINDEX, trace.reason, trace.monitor);
    }

    bpf_printk("bpf_host: tail_ipv4_host_policy_ingress: Returning ret=%d", ret);
    return ret;
}
#endif /* ENABLE_IPV4 */

static __always_inline int
to_host_from_lxc(struct __ctx_buff *ctx)
{
    int ret = CTX_ACT_OK;
    __s8 ext_err = 0;
    __u16 proto = 0;

    bpf_printk("bpf_host: to_host_from_lxc: Entering");

    bpf_printk("bpf_host: to_host_from_lxc: Validating ethertype");
    if (!validate_ethertype(ctx, &proto)) {
        ret = DROP_UNSUPPORTED_L2;
        bpf_printk("bpf_host: to_host_from_lxc: Unsupported L2, ret=%d, proceeding to out", ret);
        goto out;
    }

    bpf_printk("bpf_host: to_host_from_lxc: Processing proto=%x", proto);
    switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
    case bpf_htons(ETH_P_ARP):
        ret = CTX_ACT_OK;
        bpf_printk("bpf_host: to_host_from_lxc: ARP packet, returning CTX_ACT_OK");
        break;
# endif
# ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        ctx_store_meta(ctx, CB_SRC_LABEL, 0);
        ctx_store_meta(ctx, CB_TRACED, 1);
        bpf_printk("bpf_host: to_host_from_lxc: IPv6 packet, stored CB_SRC_LABEL=0, CB_TRACED=1");
        bpf_printk("bpf_host: to_host_from_lxc: Invoking tail call CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY");
        ret = invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
                                            is_defined(ENABLE_IPV6)),
                                      is_defined(DEBUG)),
                                 CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY,
                                 tail_ipv6_host_policy_ingress,
                                 &ext_err);
        bpf_printk("bpf_host: to_host_from_lxc: invoke_tailcall_if returned ret=%d, ext_err=%d", ret, ext_err);
        break;
# endif
# ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        ctx_store_meta(ctx, CB_SRC_LABEL, 0);
        ctx_store_meta(ctx, CB_TRACED, 1);
        bpf_printk("bpf_host: to_host_from_lxc: IPv4 packet, stored CB_SRC_LABEL=0, CB_TRACED=1");
        bpf_printk("bpf_host: to_host_from_lxc: Invoking tail call CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY");
        ret = invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
                                            is_defined(ENABLE_IPV6)),
                                      is_defined(DEBUG)),
                                 CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY,
                                 tail_ipv4_host_policy_ingress,
                                 &ext_err);
        bpf_printk("bpf_host: to_host_from_lxc: invoke_tailcall_if returned ret=%d, ext_err=%d", ret, ext_err);
        break;
# endif
    default:
        ret = DROP_UNKNOWN_L3;
        bpf_printk("bpf_host: to_host_from_lxc: Unknown L3 proto=%x, ret=%d", proto, ret);
        break;
    }

out:
    if (IS_ERR(ret)) {
        bpf_printk("bpf_host: to_host_from_lxc: Error occurred, ret=%d, sending drop notification", ret);
        ret = send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
        bpf_printk("bpf_host: to_host_from_lxc: send_drop_notify_error_ext returned ret=%d", ret);
        return ret;
    }

    bpf_printk("bpf_host: to_host_from_lxc: Returning ret=%d", ret);
    return ret;
}

static __always_inline int
from_host_to_lxc(struct __ctx_buff *ctx, __s8 *ext_err)
{
    struct trace_ctx trace = {
        .reason = TRACE_REASON_UNKNOWN,
        .monitor = 0,
    };
    int ret = CTX_ACT_OK;
    void *data, *data_end;
    struct iphdr *ip4 __maybe_unused;
    struct ipv6hdr *ip6 __maybe_unused;
    __u16 proto = 0;

    bpf_printk("bpf_host: from_host_to_lxc: Entering");

    bpf_printk("bpf_host: from_host_to_lxc: Validating ethertype");
    if (!validate_ethertype(ctx, &proto)) {
        ret = DROP_UNSUPPORTED_L2;
        bpf_printk("bpf_host: from_host_to_lxc: Unsupported L2, returning ret=%d", ret);
        return ret;
    }

    bpf_printk("bpf_host: from_host_to_lxc: Processing proto=%x", proto);
    switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
    case bpf_htons(ETH_P_ARP):
        ret = CTX_ACT_OK;
        bpf_printk("bpf_host: from_host_to_lxc: ARP packet, returning CTX_ACT_OK");
        break;
# endif
# ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            ret = DROP_INVALID;
            bpf_printk("bpf_host: from_host_to_lxc: Invalid IPv6 packet data, returning ret=%d", ret);
            return ret;
        }
        bpf_printk("bpf_host: from_host_to_lxc: IPv6 Source=%x:%x:%x:%x, Dest=%x:%x:%x:%x",
                   ip6->saddr.s6_addr32[0], ip6->saddr.s6_addr32[1],
                   ip6->saddr.s6_addr32[2], ip6->saddr.s6_addr32[3],
                   ip6->daddr.s6_addr32[0], ip6->daddr.s6_addr32[1],
                   ip6->daddr.s6_addr32[2], ip6->daddr.s6_addr32[3]);
        bpf_printk("bpf_host: from_host_to_lxc: Applying IPv6 egress policy");
        ret = ipv6_host_policy_egress(ctx, HOST_ID, 0, ip6, &trace, ext_err);
        bpf_printk("bpf_host: from_host_to_lxc: ipv6_host_policy_egress returned ret=%d, ext_err=%d", ret, *ext_err);
        break;
# endif
# ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            ret = DROP_INVALID;
            bpf_printk("bpf_host: from_host_to_lxc: Invalid IPv4 packet data, returning ret=%d", ret);
            return ret;
        }
        bpf_printk("bpf_host: from_host_to_lxc: IPv4 Source=%x, Dest=%x", ip4->saddr, ip4->daddr);
        bpf_printk("bpf_host: from_host_to_lxc: Applying IPv4 egress policy");
        ret = ipv4_host_policy_egress(ctx, HOST_ID, 0, ip4, &trace, ext_err);
        bpf_printk("bpf_host: from_host_to_lxc: ipv4_host_policy_egress returned ret=%d, ext_err=%d", ret, *ext_err);
        break;
# endif
    default:
        ret = DROP_UNKNOWN_L3;
        bpf_printk("bpf_host: from_host_to_lxc: Unknown L3 proto=%x, returning ret=%d", proto, ret);
        break;
    }

    bpf_printk("bpf_host: from_host_to_lxc: Returning ret=%d", ret);
    return ret;
}
#endif /* ENABLE_HOST_FIREWALL */

__section_entry
int handle_lxc_traffic(struct __ctx_buff *ctx __maybe_unused)
{
#ifdef ENABLE_HOST_FIREWALL
    bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
    __u32 lxc_id;
    int ret;
    __s8 ext_err = 0;

    bpf_printk("bpf_host: handle_lxc_traffic: Entering, from_host=%d", from_host);

    if (from_host) {
        bpf_printk("bpf_host: handle_lxc_traffic: From host, calling from_host_to_lxc");
        ret = from_host_to_lxc(ctx, &ext_err);
        bpf_printk("bpf_host: handle_lxc_traffic: from_host_to_lxc returned ret=%d, ext_err=%d", ret, ext_err);
        if (IS_ERR(ret)) {
            bpf_printk("bpf_host: handle_lxc_traffic: Error in from_host_to_lxc, sending drop notification, ret=%d", ret);
            ret = send_drop_notify_error_ext(ctx, HOST_ID, ret, ext_err,
                                             CTX_ACT_DROP, METRIC_EGRESS);
            bpf_printk("bpf_host: handle_lxc_traffic: send_drop_notify_error_ext returned ret=%d", ret);
            return ret;
        }

        lxc_id = ctx_load_meta(ctx, CB_DST_ENDPOINT_ID);
        bpf_printk("bpf_host: handle_lxc_traffic: lxc_id=%u", lxc_id);
        ctx_store_meta(ctx, CB_SRC_LABEL, HOST_ID);
        bpf_printk("bpf_host: handle_lxc_traffic: Stored HOST_ID in CB_SRC_LABEL");
        bpf_printk("bpf_host: handle_lxc_traffic: Tail calling policy with lxc_id=%u", lxc_id);
        ret = tail_call_policy(ctx, (__u16)lxc_id);
        bpf_printk("bpf_host: handle_lxc_traffic: tail_call_policy returned ret=%d", ret);
        ret = send_drop_notify_error(ctx, HOST_ID, ret, CTX_ACT_DROP, METRIC_EGRESS);
        bpf_printk("bpf_host: handle_lxc_traffic: send_drop_notify_error returned ret=%d", ret);
        return ret;
    }

    bpf_printk("bpf_host: handle_lxc_traffic: Not from host, calling to_host_from_lxc");
    ret = to_host_from_lxc(ctx);
    bpf_printk("bpf_host: handle_lxc_traffic: to_host_from_lxc returned ret=%d", ret);
    return ret;
#else
    bpf_printk("bpf_host: handle_lxc_traffic: ENABLE_HOST_FIREWALL not enabled, returning 0");
    return 0;
#endif /* ENABLE_HOST_FIREWALL */
}

BPF_LICENSE("Dual BSD/GPL");