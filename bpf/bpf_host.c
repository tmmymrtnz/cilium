// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <ep_config.h>

#define IS_BPF_HOST 1
#define EVENT_SOURCE HOST_EP_ID
#define TEMPLATE_HOST_EP_ID 0xffff
#define ACTION_UNKNOWN_ICMP6_NS CTX_ACT_OK

#ifndef VLAN_FILTER
# define VLAN_FILTER(ifindex, vlan_id) return false;
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
#include <linux/tcp.h>

#define host_egress_policy_hook(ctx, src_sec_identity, ext_err) CTX_ACT_OK
#define host_wg_encrypt_hook(ctx, proto) wg_maybe_redirect_to_encrypt(ctx, proto)

#define FROM_HOST_FLAG_NEED_HOSTFW (1 << 1)
#define FROM_HOST_FLAG_HOST_ID (1 << 2)

/* helper to pack 6 bytes into a 48‑bit value */
#define PACK_MAC(mac)                                                        \
  ((unsigned long long)(mac)[0] << 40 | (unsigned long long)(mac)[1] << 32 | \
   (unsigned long long)(mac)[2] << 24 | (unsigned long long)(mac)[3] << 16 | \
   (unsigned long long)(mac)[4] <<  8 | (unsigned long long)(mac)[5])

/* single call, only 2 varargs (_s and _d) */
#define PRINT_MAC_PAIR(prefix, smac, dmac) do {                              \
    unsigned long long _s = PACK_MAC(smac);                                  \
    unsigned long long _d = PACK_MAC(dmac);                                  \
    trace_printk(prefix                                                       \
                 " SMAC=%012llx DMAC=%012llx\n",                              \
                 sizeof(prefix                                               \
                        " SMAC=%012llx DMAC=%012llx\n"),                      \
                 _s, _d);                                                     \
} while (0)

/* Pack 8 bytes starting at ptr into a __u64 (big-endian) */
#define PACK_U64(ptr) (                                                       \
    (__u64)((__u8*)(ptr))[0] << 56 | (__u64)((__u8*)(ptr))[1] << 48 |         \
    (__u64)((__u8*)(ptr))[2] << 40 | (__u64)((__u8*)(ptr))[3] << 32 |         \
    (__u64)((__u8*)(ptr))[4] << 24 | (__u64)((__u8*)(ptr))[5] << 16 |         \
    (__u64)((__u8*)(ptr))[6] <<  8 | (__u64)((__u8*)(ptr))[7]                \
)

/* Pack 4 bytes starting at ptr into a __u32 (big-endian) */
#define PACK_U32(ptr) (                                                       \
    (__u32)((__u8*)(ptr))[0] << 24 | (__u32)((__u8*)(ptr))[1] << 16 |         \
    (__u32)((__u8*)(ptr))[2] <<  8 | (__u32)((__u8*)(ptr))[3]                \
)

/* Print bytes [0..15] of `epk` in one go (idx, hi64, lo64) */
#define PRINT_EPK_RAW_HEAD(idx, epk) do {                                      \
    __u64 _h0 = PACK_U64(&((epk).ip4));    /* bytes 0–7  */                    \
    __u64 _h1 = PACK_U64((__u8*)&(epk) + 8); /* bytes 8–15 */                  \
    trace_printk(                                                              \
      "epk[%d]: raw_head=%016llx%016llx\n",                                     \
      sizeof("epk[0]: raw_head=00000000000000000000000000000000\n"),           \
      (idx), _h0, _h1                                                          \
    );                                                                         \
} while (0)

/* Print bytes [16..19] of `epk` (idx, tail32) */
#define PRINT_EPK_RAW_TAIL(idx, epk) do {                                      \
    __u32 _t = PACK_U32((__u8*)&(epk) + 16); /* bytes 16–19 */                 \
    trace_printk(                                                              \
      "epk[%d]: raw_tail=%08x\n",                                              \
      sizeof("epk[0]: raw_tail=00000000\n"),                                   \
      (idx), _t                                                               \
    );                                                                         \
} while (0)

__attribute__((unused))
static __always_inline int
bpf_clone_redirect(void *ctx, __u32 ifindex, __u64 flags)
{
    /* cast the helper number to the correct signature and call it */
    return (int) ((__u64 (*)(void *, __u32, __u64))
                   (unsigned long)BPF_FUNC_clone_redirect)
                  (ctx, ifindex, flags);
}

#ifndef BPF_SKB_STORE_BYTES_HELPER_H
#define BPF_SKB_STORE_BYTES_HELPER_H

/* helper number */
#ifndef BPF_FUNC_skb_store_bytes
# define BPF_FUNC_skb_store_bytes 38
#endif

__attribute__((unused))
static __always_inline int
bpf_skb_store_bytes(void *ctx, __u32 offset,
                    const void *from, __u32 len, __u64 flags)
{
    long ret;
    register long r1 asm("r1") = (long)ctx;
    register long r2 asm("r2") = (long)offset;
    register long r3 asm("r3") = (long)from;
    register long r4 asm("r4") = (long)len;
    register long r5 asm("r5") = (long)flags;
    /* 
     * clang-for-BPF will lower this into exactly:
     *   r0 = call BPF_FUNC_skb_store_bytes(r1,…,r5)
     */
    asm volatile (
        "call %c[fn]\n"
        : "=r"(ret)
        : [fn] "i"(BPF_FUNC_skb_store_bytes),
          "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
        : "r0","r1","r2","r3","r4","r5","memory"
    );
    return (int)ret;
}

#endif /* BPF_SKB_STORE_BYTES_HELPER_H */

#ifndef BPF_FUNC_l3_csum_replace
# define BPF_FUNC_l3_csum_replace 10
#endif
#ifndef BPF_FUNC_l4_csum_replace
# define BPF_FUNC_l4_csum_replace 11
#endif

__attribute__((unused))
static __always_inline long
bpf_l3_csum_replace(void *ctx, __u32 offset,
                    __u64 from, __u64 to, __u64 size)
{
    long ret;
    register long r1 asm("r1") = (long)ctx;
    register long r2 asm("r2") = (long)offset;
    register long r3 asm("r3") = (long)from;
    register long r4 asm("r4") = (long)to;
    register long r5 asm("r5") = (long)size;
    asm volatile (
        "call %c[fn]\n"
        : "=r"(ret)
        : [fn] "i"(BPF_FUNC_l3_csum_replace),
          "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
        : "r0","r1","r2","r3","r4","r5","memory"
    );
    return ret;
}

__attribute__((unused))
static __always_inline long
bpf_l4_csum_replace(void *ctx, __u32 offset,
                    __u64 from, __u64 to, __u64 flags)
{
    long ret;
    register long r1 asm("r1") = (long)ctx;
    register long r2 asm("r2") = (long)offset;
    register long r3 asm("r3") = (long)from;
    register long r4 asm("r4") = (long)to;
    register long r5 asm("r5") = (long)flags;
    asm volatile (
        "call %c[fn]\n"
        : "=r"(ret)
        : [fn] "i"(BPF_FUNC_l4_csum_replace),
          "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
        : "r0","r1","r2","r3","r4","r5","memory"
    );
    return ret;
}

static __always_inline bool allow_vlan(__u32 __maybe_unused ifindex, __u32 __maybe_unused vlan_id) {
    VLAN_FILTER(ifindex, vlan_id);
}

#if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
static __always_inline int rewrite_dmac_to_host(struct __ctx_buff *ctx)
{
    union macaddr cilium_net_mac = CILIUM_NET_MAC;
    struct ethhdr *eth;
    void *data, *data_end;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("rewrite_dmac_to_host: invalid eth data\n",
                    sizeof("rewrite_dmac_to_host: invalid eth data\n"));
        return DROP_INVALID;
    }

    PRINT_MAC_PAIR("rewrite_dmac_to_host: ", eth->h_source, eth->h_dest);

    if (eth_store_daddr(ctx, (__u8 *) &cilium_net_mac.addr, 0) < 0) {
        trace_printk("rewrite_dmac_to_host: failed to write destination MAC\n",
                    sizeof("rewrite_dmac_to_host: failed to write destination MAC\n"));
        return DROP_WRITE_ERROR;
    }

    trace_printk("rewrite_dmac_to_host: returning CTX_ACT_OK new_DMAC=%pm\n",
                sizeof("rewrite_dmac_to_host: returning CTX_ACT_OK new_DMAC=%pm\n"),
                cilium_net_mac.addr);
    return CTX_ACT_OK;
}


#define SECCTX_FROM_IPCACHE_OK 2
#ifndef SECCTX_FROM_IPCACHE
# define SECCTX_FROM_IPCACHE 0
#endif

static __always_inline bool identity_from_ipcache_ok(void)
{
    return SECCTX_FROM_IPCACHE == SECCTX_FROM_IPCACHE_OK;
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

    trace_printk("resolve_srcid_ipv6: entry srcid_from_ipcache=%u from_host=%d\n",
        sizeof("resolve_srcid_ipv6: entry srcid_from_ipcache=%u from_host=%d\n"),
        srcid_from_ipcache, from_host);
    
    trace_printk("resolve_srcid_ipv6: src_ip=%pI6 dst_ip=%pI6\n",
        sizeof("resolve_srcid_ipv6: src_ip=%pI6 dst_ip=%pI6\n"),
        &ip6->saddr, &ip6->daddr);    

    if (identity_is_reserved(srcid_from_ipcache)) {
        src = (union v6addr *) &ip6->saddr;
        info = lookup_ip6_remote_endpoint(src, 0);
        if (info) {
            *sec_identity = info->sec_identity;
            trace_printk("resolve_srcid_ipv6: found info sec_identity=%u\n",
                        sizeof("resolve_srcid_ipv6: found info sec_identity=%u\n"),
                        *sec_identity);
            if (*sec_identity && *sec_identity != HOST_ID)
                srcid_from_ipcache = *sec_identity;
        }
        cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
                   ((__u32 *) src)[3], srcid_from_ipcache);
    }

    if (from_host)
        src_id = srcid_from_ipcache;
    else if (identity_from_ipcache_ok())
        src_id = srcid_from_ipcache;

    trace_printk("resolve_srcid_ipv6: returning src_id=%u\n",
                sizeof("resolve_srcid_ipv6: returning src_id=%u\n"),
                src_id);
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
#endif
    void *data, *data_end;
    struct ipv6hdr *ip6;
    struct ethhdr *eth;
    struct tcphdr *tcp __maybe_unused;
    int ret;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("handle_ipv6: invalid eth data\n",
                    sizeof("handle_ipv6: invalid eth data\n"));
        return DROP_INVALID;
    }

    if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
        trace_printk("handle_ipv6: invalid ip6 data\n",
                    sizeof("handle_ipv6: invalid ip6 data\n"));
        return DROP_INVALID;
    }

    trace_printk("handle_ipv6: entry secctx=%u ipcache_srcid=%u from_host=%d\n",
        sizeof("handle_ipv6: entry secctx=%u ipcache_srcid=%u from_host=%d\n"),
        secctx, ipcache_srcid, from_host);

    PRINT_MAC_PAIR("handle_ipv6: ", eth->h_source, eth->h_dest);
    
    trace_printk("handle_ipv6: src_ip=%pI6 dst_ip=%pI6\n",
            sizeof("handle_ipv6: src_ip=%pI6 dst_ip=%pI6\n"),
            &ip6->saddr, &ip6->daddr);

    if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
        (void *)tcp + sizeof(*tcp) <= data_end) {
        trace_printk("handle_ipv6: TCP seq=%u\n",
                    sizeof("handle_ipv6: TCP seq=%u\n"),
                    bpf_ntohl(tcp->seq));
    }

    if (is_defined(ENABLE_HOST_FIREWALL) || !from_host) {
        __u8 nexthdr = ip6->nexthdr;
        int hdrlen;

        hdrlen = ipv6_hdrlen(ctx, &nexthdr);
        if (hdrlen < 0) {
            trace_printk("handle_ipv6: invalid header length %d\n",
                        sizeof("handle_ipv6: invalid header length %d\n"),
                        hdrlen);
            return hdrlen;
        }

        if (likely(nexthdr == IPPROTO_ICMPV6)) {
            trace_printk("handle_ipv6: handling ICMPv6\n",
                        sizeof("handle_ipv6: handling ICMPv6\n"));
            ret = icmp6_host_handle(ctx, ETH_HLEN + hdrlen, ext_err, !from_host);
            if (ret == SKIP_HOST_FIREWALL) {
                trace_printk("handle_ipv6: skipping host firewall\n",
                            sizeof("handle_ipv6: skipping host firewall\n"));
                goto skip_host_firewall;
            }
            if (IS_ERR(ret)) {
                trace_printk("handle_ipv6: ICMPv6 error ret=%d\n",
                            sizeof("handle_ipv6: ICMPv6 error ret=%d\n"),
                            ret);
                return ret;
            }
        }
    }

#ifdef ENABLE_NODEPORT
    if (!from_host) {
        if (!ctx_skip_nodeport(ctx)) {
            bool is_dsr = false;
            trace_printk("handle_ipv6: entering nodeport_lb6\n",
                        sizeof("handle_ipv6: entering nodeport_lb6\n"));
            ret = nodeport_lb6(ctx, ip6, secctx, punt_to_stack, ext_err, &is_dsr);
            if (ret < 0 || ret == TC_ACT_REDIRECT) {
                trace_printk("handle_ipv6: nodeport_lb6 returned %d\n",
                            sizeof("handle_ipv6: nodeport_lb6 returned %d\n"),
                            ret);
                return ret;
            }
            if (*punt_to_stack) {
                trace_printk("handle_ipv6: punt to stack\n",
                            sizeof("handle_ipv6: punt to stack\n"));
                return ret;
            }
        }
    }
#endif

#ifdef ENABLE_HOST_FIREWALL
    if (from_host) {
        if (ipv6_host_policy_egress_lookup(ctx, secctx, ipcache_srcid, ip6, &ct_buffer)) {
            trace_printk("handle_ipv6: need egress policy check\n",
                        sizeof("handle_ipv6: need egress policy check\n"));
            if (unlikely(ct_buffer.ret < 0)) {
                trace_printk("handle_ipv6: egress lookup failed ret=%d\n",
                            sizeof("handle_ipv6: egress lookup failed ret=%d\n"),
                            ct_buffer.ret);
                return ct_buffer.ret;
            }
            need_hostfw = true;
            is_host_id = secctx == HOST_ID;
        }
    } else if (!ctx_skip_host_fw(ctx)) {
        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            trace_printk("handle_ipv6: invalid data in host fw check\n",
                        sizeof("handle_ipv6: invalid data in host fw check\n"));
            return DROP_INVALID;
        }
        if (ipv6_host_policy_ingress_lookup(ctx, ip6, &ct_buffer)) {
            trace_printk("handle_ipv6: need ingress policy check\n",
                        sizeof("handle_ipv6: need ingress policy check\n"));
            if (unlikely(ct_buffer.ret < 0)) {
                trace_printk("handle_ipv6: ingress lookup failed ret=%d\n",
                            sizeof("handle_ipv6: ingress lookup failed ret=%d\n"),
                            ct_buffer.ret);
                return ct_buffer.ret;
            }
            need_hostfw = true;
        }
    }
    if (need_hostfw) {
        __u32 zero = 0;
        if (map_update_elem(&CT_TAIL_CALL_BUFFER6, &zero, &ct_buffer, 0) < 0) {
            trace_printk("handle_ipv6: failed to update tail call buffer\n",
                        sizeof("handle_ipv6: failed to update tail call buffer\n"));
            return DROP_INVALID_TC_BUFFER;
        }
        trace_printk("handle_ipv6: updated tail call buffer for hostfw\n",
                    sizeof("handle_ipv6: updated tail call buffer for hostfw\n"));
    }
#endif

skip_host_firewall:
#ifdef ENABLE_HOST_FIREWALL
    ctx_store_meta(ctx, CB_FROM_HOST,
                  (need_hostfw ? FROM_HOST_FLAG_NEED_HOSTFW : 0) |
                  (is_host_id ? FROM_HOST_FLAG_HOST_ID : 0));
#endif

    trace_printk("handle_ipv6: returning CTX_ACT_OK\n",
                sizeof("handle_ipv6: returning CTX_ACT_OK\n"));
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
    struct ethhdr *eth;
    struct tcphdr *tcp __maybe_unused;
    union v6addr *dst;
    int l3_off = ETH_HLEN;
    struct remote_endpoint_info *info = NULL;
    struct endpoint_info *ep;
    int ret;
    __u8 encrypt_key __maybe_unused = 0;
    __u32 magic = MARK_MAGIC_IDENTITY;
    bool from_proxy = false;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("handle_ipv6_cont: invalid eth data\n",
                    sizeof("handle_ipv6_cont: invalid eth data\n"));
        return DROP_INVALID;
    }

    if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
        trace_printk("handle_ipv6_cont: invalid ip6 data\n",
                    sizeof("handle_ipv6_cont: invalid ip6 data\n"));
        return DROP_INVALID;
    }

    trace_printk("handle_ipv6_cont: entry secctx=%u from_host=%d\n",
        sizeof("handle_ipv6_cont: entry secctx=%u from_host=%d\n"),
        secctx, from_host);

    PRINT_MAC_PAIR("handle_ipv6_cont: ", eth->h_source, eth->h_dest);

    trace_printk("handle_ipv6_cont: src_ip=%pI6 dst_ip=%pI6\n",
            sizeof("handle_ipv6_cont: src_ip=%pI6 dst_ip=%pI6\n"),
            &ip6->saddr, &ip6->daddr);

    if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
        (void *)tcp + sizeof(*tcp) <= data_end) {
        trace_printk("handle_ipv6_cont: TCP seq=%u\n",
                    sizeof("handle_ipv6_cont: TCP seq=%u\n"),
                    bpf_ntohl(tcp->seq));
    }

    if (from_host && tc_index_from_ingress_proxy(ctx)) {
        from_proxy = true;
        magic = MARK_MAGIC_PROXY_INGRESS;
        trace_printk("handle_ipv6_cont: from ingress proxy\n",
                    sizeof("handle_ipv6_cont: from ingress proxy\n"));
    }
    if (from_host && tc_index_from_egress_proxy(ctx)) {
        from_proxy = true;
        magic = MARK_MAGIC_PROXY_EGRESS;
        trace_printk("handle_ipv6_cont: from egress proxy\n",
                    sizeof("handle_ipv6_cont: from egress proxy\n"));
    }

#ifdef ENABLE_HOST_FIREWALL
    from_host_raw = ctx_load_and_clear_meta(ctx, CB_FROM_HOST);

    if (from_host_raw & FROM_HOST_FLAG_NEED_HOSTFW) {
        struct ct_buffer6 *ct_buffer;
        __u32 zero = 0;
        __u32 remote_id = WORLD_IPV6_ID;

        ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER6, &zero);
        if (!ct_buffer) {
            trace_printk("handle_ipv6_cont: invalid tail call buffer\n",
                        sizeof("handle_ipv6_cont: invalid tail call buffer\n"));
            return DROP_INVALID_TC_BUFFER;
        }
        if (ct_buffer->tuple.saddr.d1 == 0 && ct_buffer->tuple.saddr.d2 == 0) {
            trace_printk("handle_ipv6_cont: zeroed tail call buffer\n",
                        sizeof("handle_ipv6_cont: zeroed tail call buffer\n"));
            return DROP_INVALID_TC_BUFFER;
        }

        if (from_host) {
            bool is_host_id = from_host_raw & FROM_HOST_FLAG_HOST_ID;
            trace_printk("handle_ipv6_cont: processing egress policy is_host_id=%d\n",
                        sizeof("handle_ipv6_cont: processing egress policy is_host_id=%d\n"),
                        is_host_id);
            ret = __ipv6_host_policy_egress(ctx, is_host_id, ip6, ct_buffer, &trace,
                            ext_err);
        } else {
            trace_printk("handle_ipv6_cont: processing ingress policy\n",
                        sizeof("handle_ipv6_cont: processing ingress policy\n"));
            ret = __ipv6_host_policy_ingress(ctx, ip6, ct_buffer, &remote_id, &trace,
                             ext_err);
        }
        if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT) {
            trace_printk("handle_ipv6_cont: policy processing returned %d\n",
                        sizeof("handle_ipv6_cont: policy processing returned %d\n"),
                        ret);
            return ret;
        }
    }
#endif

#ifdef ENABLE_SRV6
    if (!from_host) {
        if (is_srv6_packet(ip6) && srv6_lookup_sid(&ip6->daddr)) {
            trace_printk("handle_ipv6_cont: SRv6 packet, redirecting to decap\n",
                        sizeof("handle_ipv6_cont: SRv6 packet, redirecting to decap\n"));
            return tail_call_internal(ctx, CILIUM_CALL_SRV6_DECAP, ext_err);
        }
    }
#endif

#ifndef ENABLE_HOST_ROUTING
    if (!from_host) {
        trace_printk("handle_ipv6_cont: no host routing, returning OK\n",
                    sizeof("handle_ipv6_cont: no host routing, returning OK\n"));
        return CTX_ACT_OK;
    }
#endif

    if (from_host) {
        ret = rewrite_dmac_to_host(ctx);
        if (IS_ERR(ret)) {
            trace_printk("handle_ipv6_cont: rewrite_dmac_to_host error ret=%d\n",
                        sizeof("handle_ipv6_cont: rewrite_dmac_to_host error ret=%d\n"),
                        ret);
            return ret;
        }
        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            trace_printk("handle_ipv6_cont: invalid data after rewrite\n",
                        sizeof("handle_ipv6_cont: invalid data after rewrite\n"));
            return DROP_INVALID;
        }
        if (!revalidate_data(ctx, &data, &data_end, &eth)) {
            trace_printk("handle_ipv6_cont: invalid eth data after rewrite\n",
                        sizeof("handle_ipv6_cont: invalid eth data after rewrite\n"));
            return DROP_INVALID;
        }
        PRINT_MAC_PAIR("handle_ipv6_cont: after rewrite: ", eth->h_source, eth->h_dest);
    }

    ep = lookup_ip6_endpoint(ip6);
    if (ep) {
        trace_printk("handle_ipv6_cont: found local endpoint\n",
                    sizeof("handle_ipv6_cont: found local endpoint\n"));
        if (ep->flags & ENDPOINT_MASK_HOST_DELIVERY)
            return CTX_ACT_OK;

#ifdef ENABLE_HOST_ROUTING
        if (!from_host) {
            bool l2_hdr_required = true;
            ret = maybe_add_l2_hdr(ctx, ep->ifindex, &l2_hdr_required);
            if (ret != 0) {
                trace_printk("handle_ipv6_cont: failed to add L2 header ret=%d\n",
                            sizeof("handle_ipv6_cont: failed to add L2 header ret=%d\n"),
                            ret);
                return ret;
            }
            if (l2_hdr_required && ETH_HLEN == 0) {
                l3_off += __ETH_HLEN;
                trace_printk("handle_ipv6_cont: L2 header added, l3_off=%d\n",
                            sizeof("handle_ipv6_cont: L2 header added, l3_off=%d\n"),
                            l3_off);
            }
        }
#endif
        trace_printk("handle_ipv6_cont: performing local delivery\n",
                    sizeof("handle_ipv6_cont: performing local delivery\n"));
        return ipv6_local_delivery(ctx, l3_off, secctx, magic, ep,
                                  METRIC_INGRESS, from_host, false);
    }

    if (!from_host) {
        trace_printk("handle_ipv6_cont: not from host, returning OK\n",
                    sizeof("handle_ipv6_cont: not from host, returning OK\n"));
        return CTX_ACT_OK;
    }

    dst = (union v6addr *) &ip6->daddr;
    info = lookup_ip6_remote_endpoint(dst, 0);

#ifdef ENABLE_IPSEC
    if (from_proxy && info) {
        encrypt_key = get_min_encrypt_key(info->key);
        trace_printk("handle_ipv6_cont: IPsec encrypt_key=%u\n",
                    sizeof("handle_ipv6_cont: IPsec encrypt_key=%u\n"),
                    encrypt_key);
    }
#endif

#ifdef TUNNEL_MODE
    if (info && info->flag_skip_tunnel)
        goto skip_tunnel;

    if (info && info->tunnel_endpoint != 0) {
        trace_printk("handle_ipv6_cont: redirecting to tunnel endpoint=%u\n",
                    sizeof("handle_ipv6_cont: redirecting to tunnel endpoint=%u\n"),
                    info->tunnel_endpoint);
        return encap_and_redirect_with_nodeid(ctx, info->tunnel_endpoint,
                                              encrypt_key, secctx, info->sec_identity,
                                              &trace);
    } else {
        struct tunnel_key key = {};
        ipv6_addr_copy(&key.ip6, dst);
        key.ip6.p4 = 0;
        key.family = ENDPOINT_KEY_IPV6;
        trace_printk("handle_ipv6_cont: attempting netdev encap\n",
                    sizeof("handle_ipv6_cont: attempting netdev encap\n"));
        ret = encap_and_redirect_netdev(ctx, &key, encrypt_key, secctx, &trace);
        if (ret != DROP_NO_TUNNEL_ENDPOINT) {
            trace_printk("handle_ipv6_cont: encap_and_redirect_netdev returned %d\n",
                        sizeof("handle_ipv6_cont: encap_and_redirect_netdev returned %d\n"),
                        ret);
            return ret;
        }
    }
skip_tunnel:
#endif

    if (!info || (!from_proxy && identity_is_world_ipv6(info->sec_identity))) {
        trace_printk("handle_ipv6_cont: dropping as unroutable\n",
                    sizeof("handle_ipv6_cont: dropping as unroutable\n"));
        return DROP_UNROUTABLE;
    }

#if defined(ENABLE_IPSEC) && !defined(TUNNEL_MODE)
    if (from_proxy && info->tunnel_endpoint && encrypt_key) {
        trace_printk("handle_ipv6_cont: setting IPsec encrypt\n",
                    sizeof("handle_ipv6_cont: setting IPsec encrypt\n"));
        return set_ipsec_encrypt(ctx, encrypt_key, info->tunnel_endpoint,
                                info->sec_identity, true, false);
    }
    if (from_proxy && !identity_is_cluster(info->sec_identity)) {
        ctx->mark = MARK_MAGIC_PROXY_TO_WORLD;
        trace_printk("handle_ipv6_cont: marking as proxy to world\n",
                    sizeof("handle_ipv6_cont: marking as proxy to world\n"));
    }
#endif

    trace_printk("handle_ipv6_cont: returning CTX_ACT_OK\n",
                sizeof("handle_ipv6_cont: returning CTX_ACT_OK\n"));
    return CTX_ACT_OK;
}

static __always_inline int
tail_handle_ipv6_cont(struct __ctx_buff *ctx, bool from_host)
{
    __u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
    int ret;
    __s8 ext_err = 0;

    trace_printk("tail_handle_ipv6_cont: entry from_host=%d src_sec_identity=%u\n",
                sizeof("tail_handle_ipv6_cont: entry from_host=%d src_sec_identity=%u\n"),
                from_host, src_sec_identity);

    ret = handle_ipv6_cont(ctx, src_sec_identity, from_host, &ext_err);
    if (IS_ERR(ret)) {
        trace_printk("tail_handle_ipv6_cont: error ret=%d ext_err=%d\n",
                    sizeof("tail_handle_ipv6_cont: error ret=%d ext_err=%d\n"),
                    ret, ext_err);
        return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
    }

    trace_printk("tail_handle_ipv6_cont: returning ret=%d\n",
                sizeof("tail_handle_ipv6_cont: returning ret=%d\n"),
                ret);
    return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_CONT_FROM_HOST)
static __always_inline
int tail_handle_ipv6_cont_from_host(struct __ctx_buff *ctx)
{
    return tail_handle_ipv6_cont(ctx, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_CONT_FROM_NETDEV)
static __always_inline
int tail_handle_ipv6_cont_from_netdev(struct __ctx_buff *ctx)
{
    return tail_handle_ipv6_cont(ctx, false);
}

static __always_inline int
tail_handle_ipv6(struct __ctx_buff *ctx, __u32 ipcache_srcid, const bool from_host)
{
    __u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
    bool punt_to_stack = false;
    int ret;
    __s8 ext_err = 0;

    trace_printk("tail_handle_ipv6: entry ipcache_srcid=%u from_host=%d\n",
                sizeof("tail_handle_ipv6: entry ipcache_srcid=%u from_host=%d\n"),
                ipcache_srcid, from_host);

    ret = handle_ipv6(ctx, src_sec_identity, ipcache_srcid, from_host,
                     &punt_to_stack, &ext_err);

    if (ret == CTX_ACT_OK) {
        if (punt_to_stack) {
            trace_printk("tail_handle_ipv6: punt to stack\n",
                        sizeof("tail_handle_ipv6: punt to stack\n"));
            return ret;
        }

        ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
        if (from_host) {
            trace_printk("tail_handle_ipv6: invoking tail call from host\n",
                        sizeof("tail_handle_ipv6: invoking tail call from host\n"));
            ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
                                    CILIUM_CALL_IPV6_CONT_FROM_HOST,
                                    tail_handle_ipv6_cont_from_host,
                                    &ext_err);
        } else {
            trace_printk("tail_handle_ipv6: invoking tail call from netdev\n",
                        sizeof("tail_handle_ipv6: invoking tail call from netdev\n"));
            ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
                                    CILIUM_CALL_IPV6_CONT_FROM_NETDEV,
                                    tail_handle_ipv6_cont_from_netdev,
                                    &ext_err);
        }
    }

    if (IS_ERR(ret)) {
        trace_printk("tail_handle_ipv6: error ret=%d ext_err=%d\n",
                    sizeof("tail_handle_ipv6: error ret=%d ext_err=%d\n"),
                    ret, ext_err);
        return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
    }

    trace_printk("tail_handle_ipv6: returning ret=%d\n",
                sizeof("tail_handle_ipv6: returning ret=%d\n"),
                ret);
    return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_HOST)
int tail_handle_ipv6_from_host(struct __ctx_buff *ctx)
{
    __u32 ipcache_srcid = 0;

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV6)
    ipcache_srcid = ctx_load_and_clear_meta(ctx, CB_IPCACHE_SRC_LABEL);
#endif

    return tail_handle_ipv6(ctx, ipcache_srcid, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_NETDEV)
int tail_handle_ipv6_from_netdev(struct __ctx_buff *ctx)
{
    return tail_handle_ipv6(ctx, 0, false);
}

# ifdef ENABLE_HOST_FIREWALL
static __always_inline int
handle_to_netdev_ipv6(struct __ctx_buff *ctx, __u32 src_sec_identity,
              struct trace_ctx *trace, __s8 *ext_err)
{
    void *data, *data_end;
    struct ipv6hdr *ip6;
    struct ethhdr *eth;
    struct tcphdr *tcp __maybe_unused;
    __u32 srcid = 0, ipcache_srcid = 0;
    int hdrlen, ret;
    __u8 nexthdr;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("handle_to_netdev_ipv6: invalid eth data\n",
                    sizeof("handle_to_netdev_ipv6: invalid eth data\n"));
        return DROP_INVALID;
    }

    if (!revalidate_data_pull(ctx, &data, &data_end, &ip6)) {
        trace_printk("handle_to_netdev_ipv6: invalid ip6 data\n",
                    sizeof("handle_to_netdev_ipv6: invalid ip6 data\n"));
        return DROP_INVALID;
    }
    trace_printk("handle_to_netdev_ipv6: entry src_sec_identity=%u\n",
        sizeof("handle_to_netdev_ipv6: entry src_sec_identity=%u\n"),
        src_sec_identity);

    PRINT_MAC_PAIR("handle_to_netdev_ipv6: ", eth->h_source, eth->h_dest);

    trace_printk("handle_to_netdev_ipv6: src_ip=%pI6 dst_ip=%pI6\n",
            sizeof("handle_to_netdev_ipv6: src_ip=%pI6 dst_ip=%pI6\n"),
            &ip6->saddr, &ip6->daddr);

    if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
        (void *)tcp + sizeof(*tcp) <= data_end) {
        trace_printk("handle_to_netdev_ipv6: TCP seq=%u\n",
                    sizeof("handle_to_netdev_ipv6: TCP seq=%u\n"),
                    bpf_ntohl(tcp->seq));
    }

    nexthdr = ip6->nexthdr;
    hdrlen = ipv6_hdrlen(ctx, &nexthdr);
    if (hdrlen < 0) {
        trace_printk("handle_to_netdev_ipv6: invalid header length %d\n",
                    sizeof("handle_to_netdev_ipv6: invalid header length %d\n"),
                    hdrlen);
        return hdrlen;
    }

    if (likely(nexthdr == IPPROTO_ICMPV6)) {
        trace_printk("handle_to_netdev_ipv6: handling ICMPv6\n",
                    sizeof("handle_to_netdev_ipv6: handling ICMPv6\n"));
        ret = icmp6_host_handle(ctx, ETH_HLEN + hdrlen, ext_err, false);
        if (ret == SKIP_HOST_FIREWALL) {
            trace_printk("handle_to_netdev_ipv6: skipping host firewall\n",
                        sizeof("handle_to_netdev_ipv6: skipping host firewall\n"));
            return CTX_ACT_OK;
        }
        if (IS_ERR(ret)) {
            trace_printk("handle_to_netdev_ipv6: ICMPv6 error ret=%d\n",
                        sizeof("handle_to_netdev_ipv6: ICMPv6 error ret=%d\n"),
                        ret);
            return ret;
        }
    }

    if (src_sec_identity != HOST_ID)
        src_sec_identity = 0;

    srcid = resolve_srcid_ipv6(ctx, ip6, src_sec_identity,
                              &ipcache_srcid, true);
    trace_printk("handle_to_netdev_ipv6: resolved srcid=%u ipcache_srcid=%u\n",
                sizeof("handle_to_netdev_ipv6: resolved srcid=%u ipcache_srcid=%u\n"),
                srcid, ipcache_srcid);

    ret = ipv6_host_policy_egress(ctx, srcid, ipcache_srcid, ip6, trace, ext_err);
    trace_printk("handle_to_netdev_ipv6: returning ret=%d\n",
                sizeof("handle_to_netdev_ipv6: returning ret=%d\n"),
                ret);
    return ret;
}
#endif
#endif

#ifdef ENABLE_IPV4
static __always_inline __u32
resolve_srcid_ipv4(struct __ctx_buff *ctx, struct iphdr *ip4,
           __u32 srcid_from_proxy, __u32 *sec_identity,
           const bool from_host)
{
    __u32 src_id = WORLD_IPV4_ID, srcid_from_ipcache = srcid_from_proxy;
    struct remote_endpoint_info *info = NULL;

    trace_printk("resolve_srcid_ipv4: entry srcid_from_proxy=%u from_host=%d\n",
        sizeof("resolve_srcid_ipv4: entry srcid_from_proxy=%u from_host=%d\n"),
        srcid_from_proxy, from_host);

    trace_printk("resolve_srcid_ipv4: src_ip=%pI4 dst_ip=%pI4\n",
            sizeof("resolve_srcid_ipv4: src_ip=%pI4 dst_ip=%pI4\n"),
            &ip4->saddr, &ip4->daddr);

    if (identity_is_reserved(srcid_from_ipcache)) {
        info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
        if (info != NULL) {
            *sec_identity = info->sec_identity;
            trace_printk("resolve_srcid_ipv4: found info sec_identity=%u\n",
                        sizeof("resolve_srcid_ipv4: found info sec_identity=%u\n"),
                        *sec_identity);
            if (*sec_identity && *sec_identity != HOST_ID)
                srcid_from_ipcache = *sec_identity;
        }
        cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
                   ip4->saddr, srcid_from_ipcache);
    }

    if (from_host)
        src_id = srcid_from_ipcache;
    else if (identity_from_ipcache_ok())
        src_id = srcid_from_ipcache;

    trace_printk("resolve_srcid_ipv4: returning src_id=%u\n",
                sizeof("resolve_srcid_ipv4: returning src_id=%u\n"),
                src_id);
    return src_id;
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ct_buffer4);
    __uint(max_entries, 1);
} CT_TAIL_CALL_BUFFER4 __section_maps_btf;

static __always_inline int
handle_ipv4(struct __ctx_buff *ctx,
            __u32 secctx __maybe_unused,
            __u32 ipcache_srcid __maybe_unused,
            const bool from_host __maybe_unused,
            bool *punt_to_stack __maybe_unused,
            __s8 *ext_err __maybe_unused)
{
    /* common locals */
    void             *data;
    void             *data_end;
    struct ethhdr    *eth;
    struct iphdr     *ip4;
    struct tcphdr    *tcp;
    int               ret __maybe_unused;
#ifdef ENABLE_NODEPORT
    /* for NodePort + UDP duplication */
    bool              is_dsr;
    int               l4_off;
    int               idx;
    struct dup_backends_key    dbk;
    struct dup_backends_value *dbv;
    union macaddr     host_mac;
#endif
#ifdef ENABLE_HOST_FIREWALL
    /* for host-firewall */
    struct ct_buffer4 ct_buffer;
    bool              need_hostfw;
    bool              is_host_id;
#endif

    /* 1) Parse L2/L3 headers */
    if (!revalidate_data(ctx, &data, &data_end, &eth))
        return DROP_INVALID;
    if (!revalidate_data(ctx, &data, &data_end, &ip4))
        return DROP_INVALID;

    trace_printk("handle_ipv4: entry secctx=%u from_host=%d\n",
                sizeof("handle_ipv4: entry secctx=%u from_host=%d\n"),
                secctx, from_host);
    PRINT_MAC_PAIR("handle_ipv4: ", eth->h_source, eth->h_dest);
    trace_printk("handle_ipv4: src_ip=%pI4 dst_ip=%pI4\n",
                sizeof("handle_ipv4: src_ip=%pI4 dst_ip=%pI4\n"),
                &ip4->saddr, &ip4->daddr);

    /* 2) Optionally log TCP sequence */
    if (ip4->protocol == IPPROTO_TCP) {
        if (revalidate_data(ctx, &data, &data_end, &tcp) &&
            ((void *)tcp + sizeof(*tcp) <= data_end)) {
            trace_printk("handle_ipv4: TCP seq=%u\n",
                        sizeof("handle_ipv4: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
    }

#ifndef ENABLE_IPV4_FRAGMENTS
    if (ipv4_is_fragment(ip4))
        return DROP_FRAG_NOSUPPORT;
#endif

    /* 3) NodePort / service LB with UDP fan-out */
#ifdef ENABLE_NODEPORT
    if (!ctx_skip_nodeport(ctx)) {
        ret = nodeport_lb4(ctx,
                            ip4,
                            ETH_HLEN,
                            secctx,
                            punt_to_stack,
                            ext_err,
                            &is_dsr);

        /*
            * If NodePort wants to redirect a UDP packet,
            * clone it to all entries in dup_backends:
            */
        if (ret == TC_ACT_REDIRECT && ip4->protocol == IPPROTO_UDP) {
            l4_off   = ETH_HLEN + ipv4_hdrlen(ip4);
            host_mac = THIS_INTERFACE_MAC;
            for (idx = 0; idx < MAX_DUP_BACKENDS; idx++) {
                dbk.idx = (__u32)idx;
                dbv      = map_lookup_elem(&dup_backends, &dbk);
                if (dbv == NULL || dbv->ip == 0 || dbv->ifindex == 0)
                    continue;

                /* rewrite IPv4 dst + L3 csum */
                bpf_skb_store_bytes(ctx,
                                    ETH_HLEN + offsetof(struct iphdr, daddr),
                                    &dbv->ip,
                                    sizeof(dbv->ip),
                                    0);
                bpf_l3_csum_replace(ctx,
                                    ETH_HLEN + offsetof(struct iphdr, check),
                                    0,               /* old val ignored */
                                    dbv->ip,
                                    sizeof(dbv->ip));

                /* rewrite UDP csum */
                bpf_l4_csum_replace(ctx,
                                    l4_off + offsetof(struct udphdr, check),
                                    0,
                                    dbv->ip,
                                    sizeof(dbv->ip));

                /* patch Ethernet MACs */
                bpf_skb_store_bytes(ctx,
                                    offsetof(struct ethhdr, h_dest),
                                    dbv->mac,
                                    ETH_ALEN,
                                    0);
                bpf_skb_store_bytes(ctx,
                                    offsetof(struct ethhdr, h_source),
                                    host_mac.addr,
                                    ETH_ALEN,
                                    0);

                trace_printk("dup_backends cloning idx=%d ifidx=%u\n",
                            sizeof("dup_backends cloning idx=%d ifidx=%u\n"),
                            idx, dbv->ifindex);
                bpf_clone_redirect(ctx,
                                    dbv->ifindex,
                                    BPF_F_INGRESS);
            }

            /* honor redirect or drop from nodeport_lb4() */
            if (ret < 0 || ret == TC_ACT_REDIRECT)
                return ret;
            if (*punt_to_stack)
                return ret;
        }
    }
#endif
#ifdef ENABLE_HOST_FIREWALL
    if (from_host) {
        if (ipv4_host_policy_egress_lookup(ctx, secctx, ipcache_srcid, ip4, &ct_buffer)) {
            trace_printk("handle_ipv4: need egress policy check\n",
                        sizeof("handle_ipv4: need egress policy check\n"));
            if (unlikely(ct_buffer.ret < 0)) {
                trace_printk("handle_ipv4: egress lookup failed ret=%d\n",
                            sizeof("handle_ipv4: egress lookup failed ret=%d\n"),
                            ct_buffer.ret);
                return ct_buffer.ret;
            }
            need_hostfw = true;
            is_host_id = secctx == HOST_ID;
        }
    } else if (!ctx_skip_host_fw(ctx)) {
        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            trace_printk("handle_ipv4: invalid data in host fw check\n",
                        sizeof("handle_ipv4: invalid data in host fw check\n"));
            return DROP_INVALID;
        }
        if (ipv4_host_policy_ingress_lookup(ctx, ip4, &ct_buffer)) {
            trace_printk("handle_ipv4: need ingress policy check\n",
                        sizeof("handle_ipv4: need ingress policy check\n"));
            if (unlikely(ct_buffer.ret < 0)) {
                trace_printk("handle_ipv4: ingress lookup failed ret=%d\n",
                            sizeof("handle_ipv4: ingress lookup failed ret=%d\n"),
                            ct_buffer.ret);
                return ct_buffer.ret;
            }
            need_hostfw = true;
        }
    }
    if (need_hostfw) {
        __u32 zero = 0;
        if (map_update_elem(&CT_TAIL_CALL_BUFFER4, &zero, &ct_buffer, 0) < 0) {
            trace_printk("handle_ipv4: failed to update tail call buffer\n",
                        sizeof("handle_ipv4: failed to update tail call buffer\n"));
            return DROP_INVALID_TC_BUFFER;
        }
        trace_printk("handle_ipv4: updated tail call buffer for hostfw\n",
                    sizeof("handle_ipv4: updated tail call buffer for hostfw\n"));
    }

    ctx_store_meta(ctx, CB_FROM_HOST,
                  (need_hostfw ? FROM_HOST_FLAG_NEED_HOSTFW : 0) |
                  (is_host_id ? FROM_HOST_FLAG_HOST_ID : 0));
#endif

    trace_printk("handle_ipv4: returning CTX_ACT_OK\n",
                sizeof("handle_ipv4: returning CTX_ACT_OK\n"));
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
    struct ethhdr *eth;
    struct tcphdr *tcp __maybe_unused;
    struct remote_endpoint_info *info;
    struct endpoint_info *ep;
    int ret;
    __u8 encrypt_key __maybe_unused = 0;
    __u32 magic = MARK_MAGIC_IDENTITY;
    bool from_proxy = false;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("handle_ipv4_cont: invalid eth data\n",
                    sizeof("handle_ipv4_cont: invalid eth data\n"));
        return DROP_INVALID;
    }

    if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
        trace_printk("handle_ipv4_cont: invalid ip4 data\n",
                    sizeof("handle_ipv4_cont: invalid ip4 data\n"));
        return DROP_INVALID;
    }

    trace_printk("handle_ipv4_cont: entry secctx=%u from_host=%d\n",
        sizeof("handle_ipv4_cont: entry secctx=%u from_host=%d\n"),
        secctx, from_host);

    PRINT_MAC_PAIR("handle_ipv4_cont: ", eth->h_source, eth->h_dest);

    trace_printk("handle_ipv4_cont: src_ip=%pI4 dst_ip=%pI4\n",
            sizeof("handle_ipv4_cont: src_ip=%pI4 dst_ip=%pI4\n"),
            &ip4->saddr, &ip4->daddr);


    if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
        (void *)tcp + sizeof(*tcp) <= data_end) {
        trace_printk("handle_ipv4_cont: TCP seq=%u\n",
                    sizeof("handle_ipv4_cont: TCP seq=%u\n"),
                    bpf_ntohl(tcp->seq));
    }

    if (from_host && tc_index_from_ingress_proxy(ctx)) {
        from_proxy = true;
        magic = MARK_MAGIC_PROXY_INGRESS;
        trace_printk("handle_ipv4_cont: from ingress proxy\n",
                    sizeof("handle_ipv4_cont: from ingress proxy\n"));
    }
    if (from_host && tc_index_from_egress_proxy(ctx)) {
        from_proxy = true;
        magic = MARK_MAGIC_PROXY_EGRESS;
        trace_printk("handle_ipv4_cont: from egress proxy\n",
                    sizeof("handle_ipv4_cont: from egress proxy\n"));
    }

#ifdef ENABLE_HOST_FIREWALL
    from_host_raw = ctx_load_and_clear_meta(ctx, CB_FROM_HOST);

    if (from_host_raw & FROM_HOST_FLAG_NEED_HOSTFW) {
        struct ct_buffer4 *ct_buffer;
        __u32 zero = 0;
        __u32 remote_id = 0;

        ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER4, &zero);
        if (!ct_buffer) {
            trace_printk("handle_ipv4_cont: invalid tail call buffer\n",
                        sizeof("handle_ipv4_cont: invalid tail call buffer\n"));
            return DROP_INVALID_TC_BUFFER;
        }
        if (ct_buffer->tuple.saddr == 0) {
            trace_printk("handle_ipv4_cont: zeroed tail call buffer\n",
                        sizeof("handle_ipv4_cont: zeroed tail call buffer\n"));
            return DROP_INVALID_TC_BUFFER;
        }

        if (from_host) {
            bool is_host_id = from_host_raw & FROM_HOST_FLAG_HOST_ID;
            trace_printk("handle_ipv4_cont: processing egress policy is_host_id=%d\n",
                        sizeof("handle_ipv4_cont: processing egress policy is_host_id=%d\n"),
                        is_host_id);
            ret = __ipv4_host_policy_egress(ctx, is_host_id, ip4, ct_buffer, &trace,
                            ext_err);
        } else {
            trace_printk("handle_ipv4_cont: processing ingress policy\n",
                        sizeof("handle_ipv4_cont: processing ingress policy\n"));
            ret = __ipv4_host_policy_ingress(ctx, ip4, ct_buffer, &remote_id, &trace,
                             ext_err);
        }
        if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT) {
            trace_printk("handle_ipv4_cont: policy processing returned %d\n",
                        sizeof("handle_ipv4_cont: policy processing returned %d\n"),
                        ret);
            return ret;
        }
    }
#endif

#ifndef ENABLE_HOST_ROUTING
    if (!from_host) {
        trace_printk("handle_ipv4_cont: no host routing, returning OK\n",
                    sizeof("handle_ipv4_cont: no host routing, returning OK\n"));
        return CTX_ACT_OK;
    }
#endif

    if (from_host) {
        ret = rewrite_dmac_to_host(ctx);
        if (IS_ERR(ret)) {
            trace_printk("handle_ipv4_cont: rewrite_dmac_to_host error ret=%d\n",
                        sizeof("handle_ipv4_cont: rewrite_dmac_to_host error ret=%d\n"),
                        ret);
            return ret;
        }
        if (!revalidate_data(ctx, &data, &data_end, &eth)) {
            trace_printk("handle_ipv4_cont: invalid eth data after rewrite\n",
                        sizeof("handle_ipv4_cont: invalid eth data after rewrite\n"));
            return DROP_INVALID;
        }
        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            trace_printk("handle_ipv4_cont: invalid ip4 data after rewrite\n",
                        sizeof("handle_ipv4_cont: invalid ip4 data after rewrite\n"));
            return DROP_INVALID;
        }
        PRINT_MAC_PAIR("handle_ipv4_cont: after rewrite: ", eth->h_source, eth->h_dest);
    }

    ep = lookup_ip4_endpoint(ip4);
    if (ep) {
        int l3_off = ETH_HLEN;
        trace_printk("handle_ipv4_cont: found local endpoint\n",
                    sizeof("handle_ipv4_cont: found local endpoint\n"));
        if (ep->flags & ENDPOINT_MASK_HOST_DELIVERY)
            return CTX_ACT_OK;

#ifdef ENABLE_HOST_ROUTING
        if (!from_host) {
            bool l2_hdr_required = true;
            ret = maybe_add_l2_hdr(ctx, ep->ifindex, &l2_hdr_required);
            if (ret != 0) {
                trace_printk("handle_ipv4_cont: failed to add L2 header ret=%d\n",
                            sizeof("handle_ipv4_cont: failed to add L2 header ret=%d\n"),
                            ret);
                return ret;
            }
            if (l2_hdr_required && ETH_HLEN == 0) {
                l3_off += __ETH_HLEN;
                if (!____revalidate_data_pull(ctx, &data, &data_end,
                                              (void **)&ip4, sizeof(*ip4),
                                              false, l3_off)) {
                    trace_printk("handle_ipv4_cont: invalid data after L2 header\n",
                                sizeof("handle_ipv4_cont: invalid data after L2 header\n"));
                    return DROP_INVALID;
                }
                trace_printk("handle_ipv4_cont: L2 header added, l3_off=%d\n",
                            sizeof("handle_ipv4_cont: L2 header added, l3_off=%d\n"),
                            l3_off);
            }
        }
#endif
        trace_printk("handle_ipv4_cont: performing local delivery\n",
                    sizeof("handle_ipv4_cont: performing local delivery\n"));
        return ipv4_local_delivery(ctx, l3_off, secctx, magic, ip4, ep,
                                  METRIC_INGRESS, from_host, false, 0);
    }

    if (!from_host) {
        trace_printk("handle_ipv4_cont: not from host, returning OK\n",
                    sizeof("handle_ipv4_cont: not from host, returning OK\n"));
        return CTX_ACT_OK;
    }

#ifdef ENABLE_VTEP
    {
        struct vtep_key vkey = {};
        struct vtep_value *vtep;

        vkey.vtep_ip = ip4->daddr & VTEP_MASK;
        vtep = map_lookup_elem(&VTEP_MAP, &vkey);
        if (!vtep)
            goto skip_vtep;

        if (vtep->vtep_mac && vtep->tunnel_endpoint) {
            trace_printk("handle_ipv4_cont: handling VTEP\n",
                        sizeof("handle_ipv4_cont: handling VTEP\n"));
            if (eth_store_daddr(ctx, (__u8 *)&vtep->vtep_mac, 0) < 0) {
                trace_printk("handle_ipv4_cont: VTEP MAC write error\n",
                            sizeof("handle_ipv4_cont: VTEP MAC write error\n"));
                return DROP_WRITE_ERROR;
            }
            ret = __encap_and_redirect_with_nodeid(ctx, vtep->tunnel_endpoint,
                                                  secctx, WORLD_IPV4_ID,
                                                  WORLD_IPV4_ID, &trace);
            trace_printk("handle_ipv4_cont: VTEP redirect returned %d\n",
                        sizeof("handle_ipv4_cont: VTEP redirect returned %d\n"),
                        ret);
            return ret;
        }
    }
skip_vtep:
#endif

    info = lookup_ip4_remote_endpoint(ip4->daddr, 0);

#ifdef ENABLE_IPSEC
    if (from_proxy && info) {
        encrypt_key = get_min_encrypt_key(info->key);
        trace_printk("handle_ipv4_cont: IPsec encrypt_key=%u\n",
                    sizeof("handle_ipv4_cont: IPsec encrypt_key=%u\n"),
                    encrypt_key);
    }
#endif

#ifdef TUNNEL_MODE
    if (info && info->flag_skip_tunnel)
        goto skip_tunnel;

    if (info && info->tunnel_endpoint != 0) {
        trace_printk("handle_ipv4_cont: redirecting to tunnel endpoint=%u\n",
                    sizeof("handle_ipv4_cont: redirecting to tunnel endpoint=%u\n"),
                    info->tunnel_endpoint);
        return encap_and_redirect_with_nodeid(ctx, info->tunnel_endpoint,
                                              encrypt_key, secctx, info->sec_identity,
                                              &trace);
    } else {
        struct tunnel_key key = {};
        key.ip4 = ip4->daddr & IPV4_MASK;
        key.family = ENDPOINT_KEY_IPV4;
        trace_printk("handle_ipv4_cont: attempting netdev encap\n",
                    sizeof("handle_ipv4_cont: attempting netdev encap\n"));
        cilium_dbg(ctx, DBG_NETDEV_ENCAP4, key.ip4, secctx);
        ret = encap_and_redirect_netdev(ctx, &key, encrypt_key, secctx, &trace);
        if (ret != DROP_NO_TUNNEL_ENDPOINT) {
            trace_printk("handle_ipv4_cont: encap_and_redirect_netdev returned %d\n",
                        sizeof("handle_ipv4_cont: encap_and_redirect_netdev returned %d\n"),
                        ret);
            return ret;
        }
    }
skip_tunnel:
#endif

    if (!info || (!from_proxy && identity_is_world_ipv4(info->sec_identity))) {
        trace_printk("handle_ipv4_cont: dropping as unroutable\n",
                    sizeof("handle_ipv4_cont: dropping as unroutable\n"));
        return DROP_UNROUTABLE;
    }

#if defined(ENABLE_IPSEC) && !defined(TUNNEL_MODE)
    if (from_proxy && info->tunnel_endpoint && encrypt_key) {
        trace_printk("handle_ipv4_cont: setting IPsec encrypt\n",
                    sizeof("handle_ipv4_cont: setting IPsec encrypt\n"));
        return set_ipsec_encrypt(ctx, encrypt_key, info->tunnel_endpoint,
                                info->sec_identity, true, false);
    }
    if (from_proxy && !identity_is_cluster(info->sec_identity)) {
        ctx->mark = MARK_MAGIC_PROXY_TO_WORLD;
        trace_printk("handle_ipv4_cont: marking as proxy to world\n",
                    sizeof("handle_ipv4_cont: marking as proxy to world\n"));
    }
#endif

    trace_printk("handle_ipv4_cont: returning CTX_ACT_OK\n",
                sizeof("handle_ipv4_cont: returning CTX_ACT_OK\n"));
    return CTX_ACT_OK;
}

static __always_inline int
tail_handle_ipv4_cont(struct __ctx_buff *ctx, bool from_host)
{
    __u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
    int ret;
    __s8 ext_err = 0;

    trace_printk("tail_handle_ipv4_cont: entry from_host=%d src_sec_identity=%u\n",
                sizeof("tail_handle_ipv4_cont: entry from_host=%d src_sec_identity=%u\n"),
                from_host, src_sec_identity);

    ret = handle_ipv4_cont(ctx, src_sec_identity, from_host, &ext_err);
    if (IS_ERR(ret)) {
        trace_printk("tail_handle_ipv4_cont: error ret=%d ext_err=%d\n",
                    sizeof("tail_handle_ipv4_cont: error ret=%d ext_err=%d\n"),
                    ret, ext_err);
        return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
    }

    trace_printk("tail_handle_ipv4_cont: returning ret=%d\n",
                sizeof("tail_handle_ipv4_cont: returning ret=%d\n"),
                ret);
    return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_CONT_FROM_HOST)
static __always_inline
int tail_handle_ipv4_cont_from_host(struct __ctx_buff *ctx)
{
    return tail_handle_ipv4_cont(ctx, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_CONT_FROM_NETDEV)
static __always_inline
int tail_handle_ipv4_cont_from_netdev(struct __ctx_buff *ctx)
{
    return tail_handle_ipv4_cont(ctx, false);
}

static __always_inline int
tail_handle_ipv4(struct __ctx_buff *ctx, __u32 ipcache_srcid, const bool from_host)
{
    __u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
    bool punt_to_stack = false;
    int ret;
    __s8 ext_err = 0;

    trace_printk("tail_handle_ipv4: entry ipcache_srcid=%u from_host=%d\n",
                sizeof("tail_handle_ipv4: entry ipcache_srcid=%u from_host=%d\n"),
                ipcache_srcid, from_host);

    ret = handle_ipv4(ctx, src_sec_identity, ipcache_srcid, from_host,
                     &punt_to_stack, &ext_err);

    if (ret == CTX_ACT_OK) {
        if (punt_to_stack) {
            trace_printk("tail_handle_ipv4: punt to stack\n",
                        sizeof("tail_handle_ipv4: punt to stack\n"));
            return ret;
        }

        ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
        if (from_host) {
            trace_printk("tail_handle_ipv4: invoking tail call from host\n",
                        sizeof("tail_handle_ipv4: invoking tail call from host\n"));
            ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
                                    CILIUM_CALL_IPV4_CONT_FROM_HOST,
                                    tail_handle_ipv4_cont_from_host,
                                    &ext_err);
        } else {
            trace_printk("tail_handle_ipv4: invoking tail call from netdev\n",
                        sizeof("tail_handle_ipv4: invoking tail call from netdev\n"));
            ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
                                    CILIUM_CALL_IPV4_CONT_FROM_NETDEV,
                                    tail_handle_ipv4_cont_from_netdev,
                                    &ext_err);
        }
    }

    if (IS_ERR(ret)) {
        trace_printk("tail_handle_ipv4: error ret=%d ext_err=%d\n",
                    sizeof("tail_handle_ipv4: error ret=%d ext_err=%d\n"),
                    ret, ext_err);
        return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
    }

    trace_printk("tail_handle_ipv4: returning ret=%d\n",
                sizeof("tail_handle_ipv4: returning ret=%d\n"),
                ret);
    return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_HOST)
int tail_handle_ipv4_from_host(struct __ctx_buff *ctx)
{
    __u32 ipcache_srcid = 0;

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV4)
    ipcache_srcid = ctx_load_and_clear_meta(ctx, CB_IPCACHE_SRC_LABEL);
#endif

    return tail_handle_ipv4(ctx, ipcache_srcid, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_NETDEV)
int tail_handle_ipv4_from_netdev(struct __ctx_buff *ctx)
{
    return tail_handle_ipv4(ctx, 0, false);
}

#ifdef ENABLE_HOST_FIREWALL
static __always_inline int
handle_to_netdev_ipv4(struct __ctx_buff *ctx, __u32 src_sec_identity,
              struct trace_ctx *trace, __s8 *ext_err)
{
    void *data, *data_end;
    struct iphdr *ip4;
    struct ethhdr *eth;
    struct tcphdr *tcp __maybe_unused;
    __u32 src_id = 0, ipcache_srcid = 0;
    int ret;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("handle_to_netdev_ipv4: invalid eth data\n",
                    sizeof("handle_to_netdev_ipv4: invalid eth data\n"));
        return DROP_INVALID;
    }

    if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
        trace_printk("handle_to_netdev_ipv4: invalid ip4 data\n",
                    sizeof("handle_to_netdev_ipv4: invalid ip4 data\n"));
        return DROP_INVALID;
    }

    trace_printk("handle_to_netdev_ipv4: entry src_sec_identity=%u\n",
        sizeof("handle_to_netdev_ipv4: entry src_sec_identity=%u\n"),
        src_sec_identity);

    PRINT_MAC_PAIR("handle_to_netdev_ipv4: ", eth->h_source, eth->h_dest);

    trace_printk("handle_to_netdev_ipv4: src_ip=%pI4 dst_ip=%pI4\n",
            sizeof("handle_to_netdev_ipv4: src_ip=%pI4 dst_ip=%pI4\n"),
            &ip4->saddr, &ip4->daddr);

    if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
        (void *)tcp + sizeof(*tcp) <= data_end) {
        trace_printk("handle_to_netdev_ipv4: TCP seq=%u\n",
                    sizeof("handle_to_netdev_ipv4: TCP seq=%u\n"),
                    bpf_ntohl(tcp->seq));
    }

    if (src_sec_identity != HOST_ID)
        src_sec_identity = 0;

    src_id = resolve_srcid_ipv4(ctx, ip4, src_sec_identity,
                               &ipcache_srcid, true);
    trace_printk("handle_to_netdev_ipv4: resolved src_id=%u ipcache_srcid=%u\n",
                sizeof("handle_to_netdev_ipv4: resolved src_id=%u ipcache_srcid=%u\n"),
                src_id, ipcache_srcid);

    ret = ipv4_host_policy_egress(ctx, src_id, ipcache_srcid, ip4, trace, ext_err);
    trace_printk("handle_to_netdev_ipv4: returning ret=%d\n",
                sizeof("handle_to_netdev_ipv4: returning ret=%d\n"),
                ret);
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
    struct ethhdr *eth;
    struct ipv6hdr *ip6 __maybe_unused;
    struct iphdr *ip4 __maybe_unused;
    struct tcphdr *tcp __maybe_unused;
    int ret;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("do_netdev_encrypt_encap: invalid eth data\n",
                    sizeof("do_netdev_encrypt_encap: invalid eth data\n"));
        return DROP_INVALID;
    }

    PRINT_MAC_PAIR("do_netdev_encrypt_encap: ", eth->h_source, eth->h_dest);

    if (!eth_is_supported_ethertype(proto)) {
        trace_printk("do_netdev_encrypt_encap: unsupported L2 proto=%u\n",
                    sizeof("do_netdev_encrypt_encap: unsupported L2 proto=%u\n"),
                    proto);
        return DROP_UNSUPPORTED_L2;
    }

    switch (proto) {
# ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            trace_printk("do_netdev_encrypt_encap: invalid IPv6 data\n",
                        sizeof("do_netdev_encrypt_encap: invalid IPv6 data\n"));
            return DROP_INVALID;
        }
        trace_printk("do_netdev_encrypt_encap: IPv6 src_ip=%pI6 dst_ip=%pI6\n",
                    sizeof("do_netdev_encrypt_encap: IPv6 src_ip=%pI6 dst_ip=%pI6\n"),
                    &ip6->saddr, &ip6->daddr);
        if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("do_netdev_encrypt_encap: TCP seq=%u\n",
                        sizeof("do_netdev_encrypt_encap: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
        ep = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
        trace_printk("do_netdev_encrypt_encap: IPv6 endpoint lookup %s\n",
                    sizeof("do_netdev_encrypt_encap: IPv6 endpoint lookup %s\n"),
                    ep ? "succeeded" : "failed");
        break;
# endif /* ENABLE_IPV6 */
# ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            trace_printk("do_netdev_encrypt_encap: invalid IPv4 data\n",
                        sizeof("do_netdev_encrypt_encap: invalid IPv4 data\n"));
            return DROP_INVALID;
        }
        trace_printk("do_netdev_encrypt_encap: IPv4 src_ip=%pI4 dst_ip=%pI4\n",
                    sizeof("do_netdev_encrypt_encap: IPv4 src_ip=%pI4 dst_ip=%pI4\n"),
                    &ip4->saddr, &ip4->daddr);
        if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("do_netdev_encrypt_encap: TCP seq=%u\n",
                        sizeof("do_netdev_encrypt_encap: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
        ep = lookup_ip4_remote_endpoint(ip4->daddr, 0);
        trace_printk("do_netdev_encrypt_encap: IPv4 endpoint lookup %s\n",
                    sizeof("do_netdev_encrypt_encap: IPv4 endpoint lookup %s\n"),
                    ep ? "succeeded" : "failed");
        break;
# endif /* ENABLE_IPV4 */
    }

    if (!ep || !ep->tunnel_endpoint) {
        trace_printk("do_netdev_encrypt_encap: no tunnel endpoint\n",
                    sizeof("do_netdev_encrypt_encap: no tunnel endpoint\n"));
        return DROP_NO_TUNNEL_ENDPOINT;
    }

    ctx->mark = 0;
    bpf_clear_meta(ctx);
    ret = encap_and_redirect_with_nodeid(ctx, ep->tunnel_endpoint, 0,
                                        src_id, 0, &trace);
    trace_printk("do_netdev_encrypt_encap: returning ret=%d\n",
                sizeof("do_netdev_encrypt_encap: returning ret=%d\n"),
                ret);
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

    trace_printk("handle_l2_announcement: entry\n",
                sizeof("handle_l2_announcement: entry\n"));

    time = map_lookup_elem(&CONFIG_MAP, &index);
    if (!time) {
        trace_printk("handle_l2_announcement: no config time\n",
                    sizeof("handle_l2_announcement: no config time\n"));
        return CTX_ACT_OK;
    }

    if (ktime_get_ns() - (*time) > L2_ANNOUNCEMENTS_MAX_LIVENESS) {
        trace_printk("handle_l2_announcement: agent not active\n",
                    sizeof("handle_l2_announcement: agent not active\n"));
        return CTX_ACT_OK;
    }

    if (!arp_validate(ctx, &mac, &smac, &sip, &tip)) {
        trace_printk("handle_l2_announcement: ARP validation failed SMAC=%pm SIP=%pI4 TIP=%pI4\n",
                    sizeof("handle_l2_announcement: ARP validation failed SMAC=%pm SIP=%pI4 TIP=%pI4\n"),
                    smac.addr, &sip, &tip);
        return CTX_ACT_OK;
    }

    trace_printk("handle_l2_announcement: ARP validated SMAC=%pm SIP=%pI4 TIP=%pI4\n",
                sizeof("handle_l2_announcement: ARP validated SMAC=%pm SIP=%pI4 TIP=%pI4\n"),
                smac.addr, &sip, &tip);

    key.ip4 = tip;
    key.ifindex = ctx->ingress_ifindex;
    stats = map_lookup_elem(&L2_RESPONDER_MAP4, &key);
    if (!stats) {
        trace_printk("handle_l2_announcement: no stats entry TIP=%pI4 ifindex=%u\n",
                    sizeof("handle_l2_announcement: no stats entry TIP=%pI4 ifindex=%u\n"),
                    &tip, key.ifindex);
        return CTX_ACT_OK;
    }

    ret = arp_respond(ctx, &mac, tip, &smac, sip, 0);
    if (ret == CTX_ACT_REDIRECT) {
        __sync_fetch_and_add(&stats->responses_sent, 1);
        trace_printk("handle_l2_announcement: ARP response sent DMAC=%pm DIP=%pI4\n",
                    sizeof("handle_l2_announcement: ARP response sent DMAC=%pm DIP=%pI4\n"),
                    mac.addr, &tip);
    }

    trace_printk("handle_l2_announcement: returning ret=%d\n",
                sizeof("handle_l2_announcement: returning ret=%d\n"),
                ret);
    return ret;
};
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
    struct ethhdr *eth;
    struct ipv6hdr __maybe_unused *ip6;
    struct iphdr __maybe_unused *ip4;
    struct tcphdr *tcp __maybe_unused;
    int __maybe_unused hdrlen = 0;
    __u8 __maybe_unused next_proto = 0;
    __s8 __maybe_unused ext_err = 0;
    int ret;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("do_netdev: invalid eth data\n",
                    sizeof("do_netdev: invalid eth data\n"));
        return DROP_INVALID;
    }

    trace_printk("do_netdev: entry proto=%u identity=%u from_host=%d\n",
        sizeof("do_netdev: entry proto=%u identity=%u from_host=%d\n"),
        proto, identity, from_host);

    PRINT_MAC_PAIR("do_netdev: ", eth->h_source, eth->h_dest);

    bpf_clear_meta(ctx);

    switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER || \
     defined ENABLE_L2_ANNOUNCEMENTS
    case bpf_htons(ETH_P_ARP):
        trace_printk("do_netdev: handling ARP\n",
                    sizeof("do_netdev: handling ARP\n"));
        send_trace_notify(ctx, obs_point, UNKNOWN_ID, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
                         ctx->ingress_ifindex, trace.reason, trace.monitor);
        #ifdef ENABLE_L2_ANNOUNCEMENTS
            ret = handle_l2_announcement(ctx);
        #else
            ret = CTX_ACT_OK;
        #endif
        break;
# endif
#ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        if (!revalidate_data_pull(ctx, &data, &data_end, &ip6)) {
            trace_printk("do_netdev: invalid IPv6 data\n",
                        sizeof("do_netdev: invalid IPv6 data\n"));
            return send_drop_notify_error(ctx, identity, DROP_INVALID,
                                         CTX_ACT_DROP, METRIC_INGRESS);
        }
        trace_printk("do_netdev: IPv6 src_ip=%pI6 dst_ip=%pI6\n",
                    sizeof("do_netdev: IPv6 src_ip=%pI6 dst_ip=%pI6\n"),
                    &ip6->saddr, &ip6->daddr);
        if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("do_netdev: TCP seq=%u\n",
                        sizeof("do_netdev: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }

        identity = resolve_srcid_ipv6(ctx, ip6, identity, &ipcache_srcid, from_host);
        ctx_store_meta(ctx, CB_SRC_LABEL, identity);
        trace_printk("do_netdev: IPv6 identity=%u ipcache_srcid=%u\n",
                    sizeof("do_netdev: IPv6 identity=%u ipcache_srcid=%u\n"),
                    identity, ipcache_srcid);

# if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV6)
        if (from_host) {
            ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, ipcache_srcid);
            trace_printk("do_netdev: stored ipcache_srcid for host firewall\n",
                        sizeof("do_netdev: stored ipcache_srcid for host firewall\n"));
        }
# endif

# ifdef ENABLE_WIREGUARD
        if (!from_host) {
            next_proto = ip6->nexthdr;
            hdrlen = ipv6_hdrlen(ctx, &next_proto);
            if (likely(hdrlen > 0) &&
                ctx_is_wireguard(ctx, ETH_HLEN + hdrlen, next_proto, ipcache_srcid)) {
                trace.reason = TRACE_REASON_ENCRYPTED;
                trace_printk("do_netdev: WireGuard detected\n",
                            sizeof("do_netdev: WireGuard detected\n"));
            }
        }
# endif

        send_trace_notify(ctx, obs_point, ipcache_srcid, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
                         ctx->ingress_ifindex, trace.reason, trace.monitor);

        trace_printk("do_netdev: tail calling IPv6 handler\n",
                    sizeof("do_netdev: tail calling IPv6 handler\n"));
        ret = tail_call_internal(ctx, from_host ? CILIUM_CALL_IPV6_FROM_HOST :
                                                 CILIUM_CALL_IPV6_FROM_NETDEV,
                                &ext_err);
        return send_drop_notify_error_ext(ctx, identity, ret, ext_err,
                                         CTX_ACT_OK, METRIC_INGRESS);
#endif
#ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
            trace_printk("do_netdev: invalid IPv4 data\n",
                        sizeof("do_netdev: invalid IPv4 data\n"));
            return send_drop_notify_error(ctx, identity, DROP_INVALID,
                                         CTX_ACT_DROP, METRIC_INGRESS);
        }
        trace_printk("do_netdev: IPv4 src_ip=%pI4 dst_ip=%pI4\n",
                    sizeof("do_netdev: IPv4 src_ip=%pI4 dst_ip=%pI4\n"),
                    &ip4->saddr, &ip4->daddr);
        if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("do_netdev: TCP seq=%u\n",
                        sizeof("do_netdev: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }

        identity = resolve_srcid_ipv4(ctx, ip4, identity, &ipcache_srcid,
                                     from_host);
        ctx_store_meta(ctx, CB_SRC_LABEL, identity);
        trace_printk("do_netdev: IPv4 identity=%u ipcache_srcid=%u\n",
                    sizeof("do_netdev: IPv4 identity=%u ipcache_srcid=%u\n"),
                    identity, ipcache_srcid);

# if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV4)
        if (from_host) {
            ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, ipcache_srcid);
            trace_printk("do_netdev: stored ipcache_srcid for host firewall\n",
                        sizeof("do_netdev: stored ipcache_srcid for host firewall\n"));
        }
# endif

#ifdef ENABLE_WIREGUARD
        if (!from_host) {
            next_proto = ip4->protocol;
            hdrlen = ipv4_hdrlen(ip4);
            if (ctx_is_wireguard(ctx, ETH_HLEN + hdrlen, next_proto, ipcache_srcid)) {
                trace.reason = TRACE_REASON_ENCRYPTED;
                trace_printk("do_netdev: WireGuard detected\n",
                            sizeof("do_netdev: WireGuard detected\n"));
            }
        }
#endif

        send_trace_notify(ctx, obs_point, ipcache_srcid, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
                         ctx->ingress_ifindex, trace.reason, trace.monitor);

        trace_printk("do_netdev: tail calling IPv4 handler\n",
                    sizeof("do_netdev: tail calling IPv4 handler\n"));
        ret = tail_call_internal(ctx, from_host ? CILIUM_CALL_IPV4_FROM_HOST :
                                                 CILIUM_CALL_IPV4_FROM_NETDEV,
                                &ext_err);
        return send_drop_notify_error_ext(ctx, identity, ret, ext_err,
                                         CTX_ACT_OK, METRIC_INGRESS);
#endif
    default:
        trace_printk("do_netdev: unknown proto=%u\n",
                    sizeof("do_netdev: unknown proto=%u\n"),
                    proto);
        send_trace_notify(ctx, obs_point, UNKNOWN_ID, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
                         ctx->ingress_ifindex, trace.reason, trace.monitor);
#ifdef ENABLE_HOST_FIREWALL
        ret = send_drop_notify_error(ctx, identity, DROP_UNKNOWN_L3,
                                    CTX_ACT_DROP, METRIC_INGRESS);
#else
        ret = CTX_ACT_OK;
        trace_printk("do_netdev: passing unknown traffic to stack\n",
                    sizeof("do_netdev: passing unknown traffic to stack\n"));
#endif
    }

    trace_printk("do_netdev: returning ret=%d\n",
                sizeof("do_netdev: returning ret=%d\n"),
                ret);
    return ret;
}

__section_entry
int cil_from_netdev(struct __ctx_buff *ctx)
{
    __u32 src_id = UNKNOWN_ID;
    __be16 proto = 0;
#ifdef ENABLE_NODEPORT_ACCELERATION
    __u32 flags = ctx_get_xfer(ctx, XFER_FLAGS);
#endif
    int ret;
    struct ethhdr *eth;
    void *data, *data_end;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("cil_from_netdev: invalid eth data\n",
                    sizeof("cil_from_netdev: invalid eth data\n"));
        return DROP_INVALID;
    }

    PRINT_MAC_PAIR("cil_from_netdev: ", eth->h_source, eth->h_dest);

    if (ctx->vlan_present) {
        __u32 vlan_id = ctx->vlan_tci & 0xfff;
        if (vlan_id) {
            if (allow_vlan(ctx->ifindex, vlan_id)) {
                trace_printk("cil_from_netdev: allowed VLAN %u\n",
                            sizeof("cil_from_netdev: allowed VLAN %u\n"),
                            vlan_id);
                return CTX_ACT_OK;
            }
            ret = DROP_VLAN_FILTERED;
            trace_printk("cil_from_netdev: VLAN %u filtered\n",
                        sizeof("cil_from_netdev: VLAN %u filtered\n"),
                        vlan_id);
            goto drop_err;
        }
    }

    ctx_skip_nodeport_clear(ctx);

#ifdef ENABLE_NODEPORT_ACCELERATION
    if (flags & XFER_PKT_NO_SVC) {
        ctx_skip_nodeport_set(ctx);
        trace_printk("cil_from_netdev: skipping nodeport\n",
                    sizeof("cil_from_netdev: skipping nodeport\n"));
    }
#ifdef HAVE_ENCAP
    if (flags & XFER_PKT_SNAT_DONE) {
        ctx_snat_done_set(ctx);
        trace_printk("cil_from_netdev: SNAT done\n",
                    sizeof("cil_from_netdev: SNAT done\n"));
    }
#endif
#endif

    if (!validate_ethertype(ctx, &proto)) {
#ifdef ENABLE_HOST_FIREWALL
        ret = DROP_UNSUPPORTED_L2;
        trace_printk("cil_from_netdev: unsupported L2\n",
                    sizeof("cil_from_netdev: unsupported L2\n"));
        goto drop_err;
#else
        send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
                         TRACE_EP_ID_UNKNOWN,
                         TRACE_IFINDEX_UNKNOWN, TRACE_REASON_UNKNOWN, 0);
        trace_printk("cil_from_netdev: passing unknown traffic to stack\n",
                    sizeof("cil_from_netdev: passing unknown traffic to stack\n"));
        return CTX_ACT_OK;
#endif
    }

#ifdef ENABLE_IPSEC
    do_decrypt(ctx, proto);
    if (ctx->mark == MARK_MAGIC_DECRYPT) {
        trace_printk("cil_from_netdev: packet needs decryption, to stack\n",
                    sizeof("cil_from_netdev: packet needs decryption, to stack\n"));
        return CTX_ACT_OK;
    }
#endif

    ret = do_netdev(ctx, proto, UNKNOWN_ID, TRACE_FROM_NETWORK, false);
    trace_printk("cil_from_netdev: returning ret=%d\n",
                sizeof("cil_from_netdev: returning ret=%d\n"),
                ret);
    return ret;

drop_err:
    trace_printk("cil_from_netdev: dropping ret=%d\n",
                sizeof("cil_from_netdev: dropping ret=%d\n"),
                ret);
    return send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP, METRIC_INGRESS);
}

__section_entry
int cil_from_host(struct __ctx_buff *ctx)
{
    enum trace_point obs_point = TRACE_FROM_HOST;
    __u32 identity = UNKNOWN_ID;
    int ret __maybe_unused;
    __be16 proto = 0;
    __u32 magic;
    struct ethhdr *eth;
    void *data, *data_end;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("cil_from_host: invalid eth data\n",
                    sizeof("cil_from_host: invalid eth data\n"));
        return DROP_INVALID;
    }

    PRINT_MAC_PAIR("cil_from_host: ", eth->h_source, eth->h_dest);

    edt_set_aggregate(ctx, 0);

    if (!validate_ethertype(ctx, &proto)) {
        __u32 dst_sec_identity = UNKNOWN_ID;
        __u32 src_sec_identity = HOST_ID;
#ifdef ENABLE_HOST_FIREWALL
        trace_printk("cil_from_host: unsupported L2\n",
                    sizeof("cil_from_host: unsupported L2\n"));
        return send_drop_notify(ctx, src_sec_identity, dst_sec_identity,
                               TRACE_EP_ID_UNKNOWN, DROP_UNSUPPORTED_L2,
                               CTX_ACT_DROP, METRIC_EGRESS);
#else
        send_trace_notify(ctx, TRACE_TO_STACK, src_sec_identity, dst_sec_identity,
                         TRACE_EP_ID_UNKNOWN,
                         TRACE_IFINDEX_UNKNOWN, TRACE_REASON_UNKNOWN, 0);
        trace_printk("cil_from_host: passing unknown traffic to stack\n",
                    sizeof("cil_from_host: passing unknown traffic to stack\n"));
        return CTX_ACT_OK;
#endif
    }

    magic = inherit_identity_from_host(ctx, &identity);
    if (magic == MARK_MAGIC_PROXY_INGRESS || magic == MARK_MAGIC_PROXY_EGRESS) {
        obs_point = TRACE_FROM_PROXY;
        trace_printk("cil_from_host: from proxy, magic=%u\n",
                    sizeof("cil_from_host: from proxy, magic=%u\n"),
                    magic);
    }

#if defined(ENABLE_L7_LB)
    if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
        trace_printk("cil_from_host: handling L7 LB, endpoint ID=%u\n",
                    sizeof("cil_from_host: handling L7 LB, endpoint ID=%u\n"),
                    identity);
        ret = tail_call_egress_policy(ctx, (__u16)identity);
        trace_printk("cil_from_host: tail_call_egress_policy returned %d\n",
                    sizeof("cil_from_host: tail_call_egress_policy returned %d\n"),
                    ret);
        return send_drop_notify_error(ctx, UNKNOWN_ID, ret, CTX_ACT_DROP,
                                     METRIC_EGRESS);
    }
#endif

#ifdef ENABLE_IPSEC
    if (magic == MARK_MAGIC_ENCRYPT) {
        ret = CTX_ACT_OK;
        trace_printk("cil_from_host: packet marked for encryption\n",
                    sizeof("cil_from_host: packet marked for encryption\n"));
        send_trace_notify(ctx, TRACE_FROM_STACK, identity, UNKNOWN_ID,
                         TRACE_EP_ID_UNKNOWN,
                         ctx->ingress_ifindex, TRACE_REASON_ENCRYPTED, 0);

# ifdef TUNNEL_MODE
        ret = do_netdev_encrypt_encap(ctx, proto, identity);
        if (IS_ERR(ret)) {
            trace_printk("cil_from_host: encryption encap error ret=%d\n",
                        sizeof("cil_from_host: encryption encap error ret=%d\n"),
                        ret);
            return send_drop_notify_error(ctx, identity, ret,
                                         CTX_ACT_DROP, METRIC_EGRESS);
        }
# endif
        trace_printk("cil_from_host: returning encrypted ret=%d\n",
                    sizeof("cil_from_host: returning encrypted ret=%d\n"),
                    ret);
        return ret;
    }
#endif

    ret = do_netdev(ctx, proto, identity, obs_point, true);
    trace_printk("cil_from_host: returning ret=%d\n",
                sizeof("cil_from_host: returning ret=%d\n"),
                ret);
    return ret;
}

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
    struct ethhdr *eth;
    void *data, *data_end;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("cil_to_netdev: invalid eth data\n",
                    sizeof("cil_to_netdev: invalid eth data\n"));
        return DROP_INVALID;
    }

    PRINT_MAC_PAIR("cil_to_netdev: ", eth->h_source, eth->h_dest);

    bpf_clear_meta(ctx);

    if (magic == MARK_MAGIC_HOST || magic == MARK_MAGIC_OVERLAY)
        src_sec_identity = HOST_ID;
    else if (magic == MARK_MAGIC_IDENTITY)
        src_sec_identity = get_identity(ctx);
    trace_printk("cil_to_netdev: src_sec_identity=%u\n",
                sizeof("cil_to_netdev: src_sec_identity=%u\n"),
                src_sec_identity);

    if (ctx->vlan_present) {
        vlan_id = ctx->vlan_tci & 0xfff;
        if (vlan_id) {
            if (allow_vlan(ctx->ifindex, vlan_id)) {
                trace_printk("cil_to_netdev: allowed VLAN %u\n",
                            sizeof("cil_to_netdev: allowed VLAN %u\n"),
                            vlan_id);
                return CTX_ACT_OK;
            }
            ret = DROP_VLAN_FILTERED;
            trace_printk("cil_to_netdev: VLAN %u filtered\n",
                        sizeof("cil_to_netdev: VLAN %u filtered\n"),
                        vlan_id);
            goto drop_err;
        }
    }

#if defined(ENABLE_L7_LB)
    if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
        __u32 lxc_id = get_epid(ctx);
        trace_printk("cil_to_netdev: handling L7 LB, lxc_id=%u\n",
                    sizeof("cil_to_netdev: handling L7 LB, lxc_id=%u\n"),
                    lxc_id);
        ctx->mark = 0;
        ret = tail_call_egress_policy(ctx, (__u16)lxc_id);
        trace_printk("cil_to_netdev: tail_call_egress_policy returned %d\n",
                    sizeof("cil_to_netdev: tail_call_egress_policy returned %d\n"),
                    ret);
        goto drop_err;
    }
#endif

    validate_ethertype(ctx, &proto);
    trace_printk("cil_to_netdev: proto=%u\n",
                sizeof("cil_to_netdev: proto=%u\n"),
                proto);

#ifdef ENABLE_HOST_FIREWALL
    if (ctx_snat_done(ctx)) {
        trace_printk("cil_to_netdev: SNAT done, skipping host firewall\n",
                    sizeof("cil_to_netdev: SNAT done, skipping host firewall\n"));
        goto skip_host_firewall;
    }

    if (!eth_is_supported_ethertype(proto)) {
        ret = DROP_UNSUPPORTED_L2;
        trace_printk("cil_to_netdev: unsupported L2 proto=%u\n",
                    sizeof("cil_to_netdev: unsupported L2 proto=%u\n"),
                    proto);
        goto drop_err;
    }

    switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
    case bpf_htons(ETH_P_ARP):
        ret = CTX_ACT_OK;
        trace_printk("cil_to_netdev: handling ARP\n",
                    sizeof("cil_to_netdev: handling ARP\n"));
        break;
# endif
# ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            trace_printk("cil_to_netdev: invalid IPv6 data\n",
                        sizeof("cil_to_netdev: invalid IPv6 data\n"));
            return DROP_INVALID;
        }
        trace_printk("cil_to_netdev: handling IPv6 src_ip=%pI6 dst_ip=%pI6\n",
                    sizeof("cil_to_netdev: handling IPv6 src_ip=%pI6 dst_ip=%pI6\n"),
                    &ip6->saddr, &ip6->daddr);
        if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("cil_to_netdev: TCP seq=%u\n",
                        sizeof("cil_to_netdev: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
        trace_printk("cil_to_netdev: handling IPv6\n",
                    sizeof("cil_to_netdev: handling IPv6\n"));
        ret = handle_to_netdev_ipv6(ctx, src_sec_identity, &trace, &ext_err);
        break;
# endif
# ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            trace_printk("cil_to_netdev: invalid IPv4 data\n",
                        sizeof("cil_to_netdev: invalid IPv4 data\n"));
            return DROP_INVALID;
        }
        trace_printk("cil_to_netdev: handling IPv4 src_ip=%pI4 dst_ip=%pI4\n",
                    sizeof("cil_to_netdev: handling IPv4 src_ip=%pI4 dst_ip=%pI4\n"),
                    &ip4->saddr, &ip4->daddr);
        if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("cil_to_netdev: TCP seq=%u\n",
                        sizeof("cil_to_netdev: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
        trace_printk("cil_to_netdev: handling IPv4\n",
                    sizeof("cil_to_netdev: handling IPv4\n"));
        ret = handle_to_netdev_ipv4(ctx, src_sec_identity, &trace, &ext_err);
        break;
# endif
    default:
        ret = DROP_UNKNOWN_L3;
        trace_printk("cil_to_netdev: unknown L3 proto=%u\n",
                    sizeof("cil_to_netdev: unknown L3 proto=%u\n"),
                    proto);
        break;
    }

    if (ret == CTX_ACT_REDIRECT) {
        trace_printk("cil_to_netdev: redirecting\n",
                    sizeof("cil_to_netdev: redirecting\n"));
        return ret;
    }

    if (IS_ERR(ret))
        goto drop_err;

skip_host_firewall:
#endif /* ENABLE_HOST_FIREWALL */

    ret = host_egress_policy_hook(ctx, src_sec_identity, &ext_err);
    if (IS_ERR(ret)) {
        trace_printk("cil_to_netdev: host_egress_policy_hook error ret=%d\n",
                    sizeof("cil_to_netdev: host_egress_policy_hook error ret=%d\n"),
                    ret);
        goto drop_err;
    }

#if defined(ENABLE_BANDWIDTH_MANAGER)
    ret = edt_sched_departure(ctx, proto);
    if (ret == CTX_ACT_DROP) {
        trace_printk("cil_to_netdev: rate-limited drop\n",
                    sizeof("cil_to_netdev: rate-limited drop\n"));
        update_metrics(ctx_full_len(ctx), METRIC_EGRESS, -DROP_EDT_HORIZON);
        return ret;
    }
#endif

#if defined(ENABLE_ENCRYPTED_OVERLAY)
    if (ctx_is_overlay(ctx) && get_identity(ctx) == ENCRYPTED_OVERLAY_ID) {
        trace_printk("cil_to_netdev: handling encrypted overlay\n",
                    sizeof("cil_to_netdev: handling encrypted overlay\n"));
        ret = encrypt_overlay_and_redirect(ctx);
        if (ret == CTX_ACT_REDIRECT) {
            send_trace_notify(ctx, TRACE_TO_STACK, src_sec_identity,
                             dst_sec_identity,
                             TRACE_EP_ID_UNKNOWN, THIS_INTERFACE_IFINDEX,
                             TRACE_REASON_ENCRYPT_OVERLAY, 0);
            trace_printk("cil_to_netdev: redirected to stack\n",
                        sizeof("cil_to_netdev: redirected to stack\n"));
            return ret;
        }
        if (IS_ERR(ret))
            goto drop_err;
    }
#endif

#ifdef ENABLE_WIREGUARD
    if (!ctx_mark_is_wireguard(ctx)) {
        trace_printk("cil_to_netdev: checking WireGuard\n",
                    sizeof("cil_to_netdev: checking WireGuard\n"));
        ret = host_wg_encrypt_hook(ctx, proto);
        if (ret == CTX_ACT_REDIRECT) {
            trace_printk("cil_to_netdev: WireGuard redirect\n",
                        sizeof("cil_to_netdev: WireGuard redirect\n"));
            return ret;
        } else if (IS_ERR(ret))
            goto drop_err;
    } else {
        trace.reason |= TRACE_REASON_ENCRYPTED;
        trace_printk("cil_to_netdev: packet already encrypted\n",
                    sizeof("cil_to_netdev: packet already encrypted\n"));
    }

#if defined(ENCRYPTION_STRICT_MODE)
    if (!strict_allow(ctx, proto)) {
        ret = DROP_UNENCRYPTED_TRAFFIC;
        trace_printk("cil_to_netdev: dropping unencrypted traffic\n",
                    sizeof("cil_to_netdev: dropping unencrypted traffic\n"));
        goto drop_err;
    }
#endif
#endif

#ifdef ENABLE_HEALTH_CHECK
    ret = lb_handle_health(ctx, proto);
    if (ret != CTX_ACT_OK) {
        trace_printk("cil_to_netdev: health check returned %d\n",
                    sizeof("cil_to_netdev: health check returned %d\n"),
                    ret);
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
            trace_printk("cil_to_netdev: skipping egress gateway (host source)\n",
                        sizeof("cil_to_netdev: skipping egress gateway (host source)\n"));
            goto skip_egress_gateway;
        }

        if (proto != bpf_htons(ETH_P_IP)) {
            trace_printk("cil_to_netdev: skipping egress gateway (not IPv4)\n",
                        sizeof("cil_to_netdev: skipping egress gateway (not IPv4)\n"));
            goto skip_egress_gateway;
        }

        if (ctx_egw_done(ctx)) {
            trace_printk("cil_to_netdev: egress gateway already done\n",
                        sizeof("cil_to_netdev: egress gateway already done\n"));
            goto skip_egress_gateway;
        }

        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            ret = DROP_INVALID;
            trace_printk("cil_to_netdev: invalid data for egress gateway\n",
                        sizeof("cil_to_netdev: invalid data for egress gateway\n"));
            goto drop_err;
        }

        trace_printk("cil_to_netdev: egress gateway src_ip=%pI4 dst_ip=%pI4\n",
                    sizeof("cil_to_netdev: egress gateway src_ip=%pI4 dst_ip=%pI4\n"),
                    &ip4->saddr, &ip4->daddr);
        if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("cil_to_netdev: TCP seq=%u\n",
                        sizeof("cil_to_netdev: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }

        tuple.nexthdr = ip4->protocol;
        tuple.daddr = ip4->daddr;
        tuple.saddr = ip4->saddr;

        l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
        ret = ct_extract_ports4(ctx, ip4, l4_off, CT_EGRESS, &tuple, NULL);
        if (IS_ERR(ret)) {
            if (ret == DROP_CT_UNKNOWN_PROTO) {
                trace_printk("cil_to_netdev: unknown CT proto, skipping egress gateway\n",
                            sizeof("cil_to_netdev: unknown CT proto, skipping egress gateway\n"));
                goto skip_egress_gateway;
            }
            trace_printk("cil_to_netdev: ct_extract_ports4 error ret=%d\n",
                        sizeof("cil_to_netdev: ct_extract_ports4 error ret=%d\n"),
                        ret);
            goto drop_err;
        }

        is_reply = ct_is_reply4(get_ct_map4(&tuple), &tuple);
        if (is_reply) {
            trace_printk("cil_to_netdev: reply packet, skipping egress gateway\n",
                        sizeof("cil_to_netdev: reply packet, skipping egress gateway\n"));
            goto skip_egress_gateway;
        }

        src_ep = __lookup_ip4_endpoint(ip4->saddr);
        if (src_ep) {
            src_sec_identity = src_ep->sec_id;
            trace_printk("cil_to_netdev: src_ep found, src_sec_identity=%u\n",
                        sizeof("cil_to_netdev: src_ep found, src_sec_identity=%u\n"),
                        src_sec_identity);
        }

        info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
        if (info && info->sec_identity) {
            dst_sec_identity = info->sec_identity;
            trace_printk("cil_to_netdev: dst info found, dst_sec_identity=%u\n",
                        sizeof("cil_to_netdev: dst info found, dst_sec_identity=%u\n"),
                        dst_sec_identity);
        }

        __ipv4_ct_tuple_reverse(&tuple);
        ret = egress_gw_handle_packet(ctx, &tuple, src_sec_identity,
                                     dst_sec_identity, &trace);
        if (IS_ERR(ret)) {
            trace_printk("cil_to_netdev: egress_gw_handle_packet error ret=%d\n",
                        sizeof("cil_to_netdev: egress_gw_handle_packet error ret=%d\n"),
                        ret);
            goto drop_err;
        }
        if (ret != CTX_ACT_OK) {
            trace_printk("cil_to_netdev: egress gateway returned %d\n",
                        sizeof("cil_to_netdev: egress gateway returned %d\n"),
                        ret);
            return ret;
        }
    }
skip_egress_gateway:
#endif

#ifdef ENABLE_NODEPORT
    if (!ctx_snat_done(ctx) && !ctx_is_overlay(ctx) && !ctx_mark_is_wireguard(ctx)) {
        void *data, *data_end;
        struct ethhdr *eth;
        struct ipv6hdr *ip6 __maybe_unused;
        struct iphdr *ip4 __maybe_unused;
        struct tcphdr *tcp __maybe_unused;

        if (!revalidate_data(ctx, &data, &data_end, &eth)) {
            trace_printk("cil_to_netdev: invalid eth data for NAT\n",
                        sizeof("cil_to_netdev: invalid eth data for NAT\n"));
            ret = DROP_INVALID;
            goto drop_err;
        }

        PRINT_MAC_PAIR("cil_to_netdev: NAT ", eth->h_source, eth->h_dest);

        if (proto == bpf_htons(ETH_P_IPV6) && revalidate_data(ctx, &data, &data_end, &ip6)) {
            trace_printk("cil_to_netdev: NAT IPv6 src_ip=%pI6 dst_ip=%pI6\n",
                        sizeof("cil_to_netdev: NAT IPv6 src_ip=%pI6 dst_ip=%pI6\n"),
                        &ip6->saddr, &ip6->daddr);
            if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
                (void *)tcp + sizeof(*tcp) <= data_end) {
                trace_printk("cil_to_netdev: NAT TCP seq=%u\n",
                            sizeof("cil_to_netdev: NAT TCP seq=%u\n"),
                            bpf_ntohl(tcp->seq));
            }
        } else if (proto == bpf_htons(ETH_P_IP) && revalidate_data(ctx, &data, &data_end, &ip4)) {
            trace_printk("cil_to_netdev: NAT IPv4 src_ip=%pI4 dst_ip=%pI4\n",
                        sizeof("cil_to_netdev: NAT IPv4 src_ip=%pI4 dst_ip=%pI4\n"),
                        &ip4->saddr, &ip4->daddr);
            if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
                (void *)tcp + sizeof(*tcp) <= data_end) {
                trace_printk("cil_to_netdev: NAT TCP seq=%u\n",
                            sizeof("cil_to_netdev: NAT TCP seq=%u\n"),
                            bpf_ntohl(tcp->seq));
            }
        }

        trace_printk("cil_to_netdev: handling NAT forward\n",
                    sizeof("cil_to_netdev: handling NAT forward\n"));
        ret = handle_nat_fwd(ctx, 0, proto, false, &trace, &ext_err);
        if (ret == CTX_ACT_REDIRECT) {
            trace_printk("cil_to_netdev: NAT redirect\n",
                        sizeof("cil_to_netdev: NAT redirect\n"));
            return ret;
        }
    }
#endif

#ifdef ENABLE_HEALTH_CHECK
exit:
#endif
    if (IS_ERR(ret))
        goto drop_err;

    send_trace_notify(ctx, TRACE_TO_NETWORK, src_sec_identity, dst_sec_identity,
                     TRACE_EP_ID_UNKNOWN,
                     THIS_INTERFACE_IFINDEX, trace.reason, trace.monitor);

    trace_printk("cil_to_netdev: returning ret=%d\n",
                sizeof("cil_to_netdev: returning ret=%d\n"),
                ret);
    return ret;

drop_err:
    trace_printk("cil_to_netdev: dropping ret=%d ext_err=%d\n",
                sizeof("cil_to_netdev: dropping ret=%d ext_err=%d\n"),
                ret, ext_err);
    return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
                                     CTX_ACT_DROP, METRIC_EGRESS);
}

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
    struct ethhdr *eth;
    void *data, *data_end;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("cil_to_host: invalid eth data\n",
                    sizeof("cil_to_host: invalid eth data\n"));
        return DROP_INVALID;
    }

    PRINT_MAC_PAIR("cil_to_host: ", eth->h_source, eth->h_dest);

    if (((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) ||
        ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_TO_PROXY))
        magic = ctx->mark;

    if ((magic & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) {
        ctx->mark = magic;
        src_id = ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY);
        trace_printk("cil_to_host: encrypted packet, src_id=%u\n",
                    sizeof("cil_to_host: encrypted packet, src_id=%u\n"),
                    src_id);
    } else if ((magic & 0xFFFF) == MARK_MAGIC_TO_PROXY) {
        __be16 port = magic >> 16;
        traced = true;
        trace_printk("cil_to_host: redirecting to proxy, port=%u\n",
                    sizeof("cil_to_host: redirecting to proxy, port=%u\n"),
                    port);
        ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);
        ret = ctx_redirect_to_proxy_first(ctx, port);
        goto out;
    }

#ifdef ENABLE_IPSEC
    ctx_change_type(ctx, PACKET_HOST);
    trace_printk("cil_to_host: changed to PACKET_HOST\n",
                sizeof("cil_to_host: changed to PACKET_HOST\n"));

# ifdef ENABLE_NODEPORT
    if ((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_ENCRYPT)
        goto skip_ipsec_nodeport_revdnat;

    if (!validate_ethertype(ctx, &proto)) {
        trace_printk("cil_to_host: invalid ethertype for IPsec\n",
                    sizeof("cil_to_host: invalid ethertype for IPsec\n"));
        goto skip_ipsec_nodeport_revdnat;
    }

    struct ipv6hdr *ip6 __maybe_unused;
    struct iphdr *ip4 __maybe_unused;
    struct tcphdr *tcp __maybe_unused;

    if (proto == bpf_htons(ETH_P_IPV6) && revalidate_data(ctx, &data, &data_end, &ip6)) {
        trace_printk("cil_to_host: NAT IPv6 src_ip=%pI6 dst_ip=%pI6\n",
                    sizeof("cil_to_host: NAT IPv6 src_ip=%pI6 dst_ip=%pI6\n"),
                    &ip6->saddr, &ip6->daddr);
        if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("cil_to_host: NAT TCP seq=%u\n",
                        sizeof("cil_to_host: NAT TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
    } else if (proto == bpf_htons(ETH_P_IP) && revalidate_data(ctx, &data, &data_end, &ip4)) {
        trace_printk("cil_to_host: NAT IPv4 src_ip=%pI4 dst_ip=%pI4\n",
                    sizeof("cil_to_host: NAT IPv4 src_ip=%pI4 dst_ip=%pI4\n"),
                    &ip4->saddr, &ip4->daddr);
        if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("cil_to_host: NAT TCP seq=%u\n",
                        sizeof("cil_to_host: NAT TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
    }

    trace_printk("cil_to_host: handling NAT forward for IPsec\n",
                sizeof("cil_to_host: handling NAT forward for IPsec\n"));
    ret = handle_nat_fwd(ctx, 0, proto, true, &trace, &ext_err);
    if (IS_ERR(ret))
        goto out;

skip_ipsec_nodeport_revdnat:
# endif
#endif

#ifdef ENABLE_HOST_FIREWALL
    if (!validate_ethertype(ctx, &proto)) {
        ret = DROP_UNSUPPORTED_L2;
        trace_printk("cil_to_host: unsupported L2 proto=%u\n",
                    sizeof("cil_to_host: unsupported L2 proto=%u\n"),
                    proto);
        goto out;
    }

    switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
    case bpf_htons(ETH_P_ARP):
        ret = CTX_ACT_OK;
        trace_printk("cil_to_host: handling ARP\n",
                    sizeof("cil_to_host: handling ARP\n"));
        break;
# endif
# ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            trace_printk("cil_to_host: invalid IPv6 data\n",
                        sizeof("cil_to_host: invalid IPv6 data\n"));
            return DROP_INVALID;
        }
        trace_printk("cil_to_host: handling IPv6 src_ip=%pI6 dst_ip=%pI6\n",
                    sizeof("cil_to_host: handling IPv6 src_ip=%pI6 dst_ip=%pI6\n"),
                    &ip6->saddr, &ip6->daddr);
        if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("cil_to_host: TCP seq=%u\n",
                        sizeof("cil_to_host: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
        trace_printk("cil_to_host: handling IPv6\n",
                    sizeof("cil_to_host: handling IPv6\n"));
        ctx_store_meta(ctx, CB_SRC_LABEL, src_id);
        ctx_store_meta(ctx, CB_TRACED, traced);
        ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY, &ext_err);
        break;
# endif
# ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            trace_printk("cil_to_host: invalid IPv4 data\n",
                        sizeof("cil_to_host: invalid IPv4 data\n"));
            return DROP_INVALID;
        }
        trace_printk("cil_to_host: handling IPv4 src_ip=%pI4 dst_ip=%pI4\n",
                    sizeof("cil_to_host: handling IPv4 src_ip=%pI4 dst_ip=%pI4\n"),
                    &ip4->saddr, &ip4->daddr);
        if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("cil_to_host: TCP seq=%u\n",
                        sizeof("cil_to_host: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
        trace_printk("cil_to_host: handling IPv4\n",
                    sizeof("cil_to_host: handling IPv4\n"));
        ctx_store_meta(ctx, CB_SRC_LABEL, src_id);
        ctx_store_meta(ctx, CB_TRACED, traced);
        ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY, &ext_err);
        break;
# endif
    default:
        ret = DROP_UNKNOWN_L3;
        trace_printk("cil_to_host: unknown L3 proto=%u\n",
                    sizeof("cil_to_host: unknown L3 proto=%u\n"),
                    proto);
        break;
    }
#else
    ret = CTX_ACT_OK;
    trace_printk("cil_to_host: no host firewall, passing to stack\n",
                sizeof("cil_to_host: no host firewall, passing to stack\n"));
#endif

out:
    if (IS_ERR(ret)) {
        trace_printk("cil_to_host: error ret=%d ext_err=%d\n",
                    sizeof("cil_to_host: error ret=%d ext_err=%d\n"),
                    ret, ext_err);
        return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
    }

    if (!traced) {
        send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
                         TRACE_EP_ID_UNKNOWN,
                         CILIUM_HOST_IFINDEX, trace.reason, trace.monitor);
        trace_printk("cil_to_host: traced to stack\n",
                    sizeof("cil_to_host: traced to stack\n"));
    }

    trace_printk("cil_to_host: returning ret=%d\n",
                sizeof("cil_to_host: returning ret=%d\n"),
                ret);
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
    struct ethhdr *eth;
    struct ipv6hdr *ip6;
    struct tcphdr *tcp;
    void *data, *data_end;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("tail_ipv6_host_policy_ingress: invalid eth data\n",
                    sizeof("tail_ipv6_host_policy_ingress: invalid eth data\n"));
        return DROP_INVALID;
    }
    if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
        trace_printk("tail_ipv6_host_policy_ingress: invalid IPv6 data\n",
                    sizeof("tail_ipv6_host_policy_ingress: invalid IPv6 data\n"));
        return DROP_INVALID;
    }

    trace_printk("tail_ipv6_host_policy_ingress: entry src_id=%u traced=%d\n",
        sizeof("tail_ipv6_host_policy_ingress: entry src_id=%u traced=%d\n"),
        src_id, traced);

    PRINT_MAC_PAIR("tail_ipv6_host_policy_ingress: ", eth->h_source, eth->h_dest);

    trace_printk("tail_ipv6_host_policy_ingress: src_ip=%pI6 dst_ip=%pI6\n",
            sizeof("tail_ipv6_host_policy_ingress: src_ip=%pI6 dst_ip=%pI6\n"),
            &ip6->saddr, &ip6->daddr);

    if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
        (void *)tcp + sizeof(*tcp) <= data_end) {
        trace_printk("tail_ipv6_host_policy_ingress: TCP seq=%u\n",
                    sizeof("tail_ipv6_host_policy_ingress: TCP seq=%u\n"),
                    bpf_ntohl(tcp->seq));
    }

    ret = ipv6_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
    if (IS_ERR(ret)) {
        trace_printk("tail_ipv6_host_policy_ingress: error ret=%d ext_err=%d\n",
                    sizeof("tail_ipv6_host_policy_ingress: error ret=%d ext_err=%d\n"),
                    ret, ext_err);
        return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
    }

    if (!traced) {
        send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
                         TRACE_EP_ID_UNKNOWN,
                         CILIUM_HOST_IFINDEX, trace.reason, trace.monitor);
        trace_printk("tail_ipv6_host_policy_ingress: traced to stack\n",
                    sizeof("tail_ipv6_host_policy_ingress: traced to stack\n"));
    }

    trace_printk("tail_ipv6_host_policy_ingress: returning ret=%d\n",
                sizeof("tail_ipv6_host_policy_ingress: returning ret=%d\n"),
                ret);
    return ret;
}
#endif

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
    struct ethhdr *eth;
    struct iphdr *ip4;
    struct tcphdr *tcp;
    void *data, *data_end;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("tail_ipv4_host_policy_ingress: invalid eth data\n",
                    sizeof("tail_ipv4_host_policy_ingress: invalid eth data\n"));
        return DROP_INVALID;
    }
    if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
        trace_printk("tail_ipv4_host_policy_ingress: invalid IPv4 data\n",
                    sizeof("tail_ipv4_host_policy_ingress: invalid IPv4 data\n"));
        return DROP_INVALID;
    }

    trace_printk("tail_ipv4_host_policy_ingress: entry src_id=%u traced=%d\n",
        sizeof("tail_ipv4_host_policy_ingress: entry src_id=%u traced=%d\n"),
        src_id, traced);

    PRINT_MAC_PAIR("tail_ipv4_host_policy_ingress: ", eth->h_source, eth->h_dest);

    trace_printk("tail_ipv4_host_policy_ingress: src_ip=%pI4 dst_ip=%pI4\n",
            sizeof("tail_ipv4_host_policy_ingress: src_ip=%pI4 dst_ip=%pI4\n"),
            &ip4->saddr, &ip4->daddr);

    if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
        (void *)tcp + sizeof(*tcp) <= data_end) {
        trace_printk("tail_ipv4_host_policy_ingress: TCP seq=%u\n",
                    sizeof("tail_ipv4_host_policy_ingress: TCP seq=%u\n"),
                    bpf_ntohl(tcp->seq));
    }

    ret = ipv4_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
    if (IS_ERR(ret)) {
        trace_printk("tail_ipv4_host_policy_ingress: error ret=%d ext_err=%d\n",
                    sizeof("tail_ipv4_host_policy_ingress: error ret=%d ext_err=%d\n"),
                    ret, ext_err);
        return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
    }

    if (!traced) {
        send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
                         TRACE_EP_ID_UNKNOWN,
                         CILIUM_HOST_IFINDEX, trace.reason, trace.monitor);
        trace_printk("tail_ipv4_host_policy_ingress: traced to stack\n",
                    sizeof("tail_ipv4_host_policy_ingress: traced to stack\n"));
    }

    trace_printk("tail_ipv4_host_policy_ingress: returning ret=%d\n",
                sizeof("tail_ipv4_host_policy_ingress: returning ret=%d\n"),
                ret);
    return ret;
}
#endif

static __always_inline int
to_host_from_lxc(struct __ctx_buff *ctx)
{
    int ret = CTX_ACT_OK;
    __s8 ext_err = 0;
    __u16 proto = 0;
    struct ethhdr *eth;
    void *data, *data_end;
    struct ipv6hdr *ip6 __maybe_unused;
    struct iphdr *ip4 __maybe_unused;
    struct tcphdr *tcp __maybe_unused;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("to_host_from_lxc: invalid eth data\n",
                    sizeof("to_host_from_lxc: invalid eth data\n"));
        return DROP_INVALID;
    }

    PRINT_MAC_PAIR("to_host_from_lxc: ", eth->h_source, eth->h_dest);

    if (!validate_ethertype(ctx, &proto)) {
        ret = DROP_UNSUPPORTED_L2;
        trace_printk("to_host_from_lxc: unsupported L2 proto=%u\n",
                    sizeof("to_host_from_lxc: unsupported L2 proto=%u\n"),
                    proto);
        goto out;
    }

    switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
    case bpf_htons(ETH_P_ARP):
        ret = CTX_ACT_OK;
        trace_printk("to_host_from_lxc: handling ARP\n",
                    sizeof("to_host_from_lxc: handling ARP\n"));
        break;
# endif
# ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            trace_printk("to_host_from_lxc: invalid IPv6 data\n",
                        sizeof("to_host_from_lxc: invalid IPv6 data\n"));
            return DROP_INVALID;
        }
        trace_printk("to_host_from_lxc: handling IPv6 src_ip=%pI6 dst_ip=%pI6\n",
                    sizeof("to_host_from_lxc: handling IPv6 src_ip=%pI6 dst_ip=%pI6\n"),
                    &ip6->saddr, &ip6->daddr);
        if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("to_host_from_lxc: TCP seq=%u\n",
                        sizeof("to_host_from_lxc: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
        trace_printk("to_host_from_lxc: handling IPv6\n",
                    sizeof("to_host_from_lxc: handling IPv6\n"));
        ctx_store_meta(ctx, CB_SRC_LABEL, 0);
        ctx_store_meta(ctx, CB_TRACED, 1);
        ret = invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
                                           is_defined(ENABLE_IPV6)),
                                     is_defined(DEBUG)),
                                CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY,
                                tail_ipv6_host_policy_ingress,
                                &ext_err);
        break;
# endif
# ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            trace_printk("to_host_from_lxc: invalid IPv4 data\n",
                        sizeof("to_host_from_lxc: invalid IPv4 data\n"));
            return DROP_INVALID;
        }
        trace_printk("to_host_from_lxc: handling IPv4 src_ip=%pI4 dst_ip=%pI4\n",
                    sizeof("to_host_from_lxc: handling IPv4 src_ip=%pI4 dst_ip=%pI4\n"),
                    &ip4->saddr, &ip4->daddr);
        if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("to_host_from_lxc: TCP seq=%u\n",
                        sizeof("to_host_from_lxc: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
        trace_printk("to_host_from_lxc: handling IPv4\n",
                    sizeof("to_host_from_lxc: handling IPv4\n"));
        ctx_store_meta(ctx, CB_SRC_LABEL, 0);
        ctx_store_meta(ctx, CB_TRACED, 1);
        ret = invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
                                           is_defined(ENABLE_IPV6)),
                                     is_defined(DEBUG)),
                                CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY,
                                tail_ipv4_host_policy_ingress,
                                &ext_err);
        break;
# endif
    default:
        ret = DROP_UNKNOWN_L3;
        trace_printk("to_host_from_lxc: unknown L3 proto=%u\n",
                    sizeof("to_host_from_lxc: unknown L3 proto=%u\n"),
                    proto);
        break;
    }

out:
    if (IS_ERR(ret)) {
        trace_printk("to_host_from_lxc: error ret=%d ext_err=%d\n",
                    sizeof("to_host_from_lxc: error ret=%d ext_err=%d\n"),
                    ret, ext_err);
        return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err,
                                         CTX_ACT_DROP, METRIC_INGRESS);
    }
    trace_printk("to_host_from_lxc: returning ret=%d\n",
                sizeof("to_host_from_lxc: returning ret=%d\n"),
                ret);
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
    struct ethhdr *eth;
    struct iphdr *ip4 __maybe_unused;
    struct ipv6hdr *ip6 __maybe_unused;
    struct tcphdr *tcp __maybe_unused;
    __u16 proto = 0;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("from_host_to_lxc: invalid eth data\n",
                    sizeof("from_host_to_lxc: invalid eth data\n"));
        return DROP_INVALID;
    }

    PRINT_MAC_PAIR("from_host_to_lxc: ", eth->h_source, eth->h_dest);

    if (!validate_ethertype(ctx, &proto)) {
        trace_printk("from_host_to_lxc: unsupported L2 proto=%u\n",
                    sizeof("from_host_to_lxc: unsupported L2 proto=%u\n"),
                    proto);
        return DROP_UNSUPPORTED_L2;
    }

    switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
    case bpf_htons(ETH_P_ARP):
        ret = CTX_ACT_OK;
        trace_printk("from_host_to_lxc: handling ARP\n",
                    sizeof("from_host_to_lxc: handling ARP\n"));
        break;
# endif
# ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
            trace_printk("from_host_to_lxc: invalid IPv6 data\n",
                        sizeof("from_host_to_lxc: invalid IPv6 data\n"));
            return DROP_INVALID;
        }
        trace_printk("from_host_to_lxc: handling IPv6 src_ip=%pI6 dst_ip=%pI6\n",
                    sizeof("from_host_to_lxc: handling IPv6 src_ip=%pI6 dst_ip=%pI6\n"),
                    &ip6->saddr, &ip6->daddr);
        if (ip6->nexthdr == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("from_host_to_lxc: TCP seq=%u\n",
                        sizeof("from_host_to_lxc: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
        trace_printk("from_host_to_lxc: handling IPv6\n",
                    sizeof("from_host_to_lxc: handling IPv6\n"));
        ret = ipv6_host_policy_egress(ctx, HOST_ID, 0, ip6, &trace, ext_err);
        break;
# endif
# ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
            trace_printk("from_host_to_lxc: invalid IPv4 data\n",
                        sizeof("from_host_to_lxc: invalid IPv4 data\n"));
            return DROP_INVALID;
        }
        trace_printk("from_host_to_lxc: handling IPv4 src_ip=%pI4 dst_ip=%pI4\n",
                    sizeof("from_host_to_lxc: handling IPv4 src_ip=%pI4 dst_ip=%pI4\n"),
                    &ip4->saddr, &ip4->daddr);
        if (ip4->protocol == IPPROTO_TCP && revalidate_data(ctx, &data, &data_end, &tcp) &&
            (void *)tcp + sizeof(*tcp) <= data_end) {
            trace_printk("from_host_to_lxc: TCP seq=%u\n",
                        sizeof("from_host_to_lxc: TCP seq=%u\n"),
                        bpf_ntohl(tcp->seq));
        }
        trace_printk("from_host_to_lxc: handling IPv4\n",
                    sizeof("from_host_to_lxc: handling IPv4\n"));
        ret = ipv4_host_policy_egress(ctx, HOST_ID, 0, ip4, &trace, ext_err);
        break;
# endif
    default:
        ret = DROP_UNKNOWN_L3;
        trace_printk("from_host_to_lxc: unknown L3 proto=%u\n",
                    sizeof("from_host_to_lxc: unknown L3 proto=%u\n"),
                    proto);
        break;
    }

    trace_printk("from_host_to_lxc: returning ret=%d\n",
                sizeof("from_host_to_lxc: returning ret=%d\n"),
                ret);
    return ret;
}
#endif

__section_entry
int handle_lxc_traffic(struct __ctx_buff *ctx __maybe_unused)
{
#ifdef ENABLE_HOST_FIREWALL
    bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
    __u32 lxc_id;
    int ret;
    __s8 ext_err = 0;
    struct ethhdr *eth;
    void *data, *data_end;

    if (!revalidate_data(ctx, &data, &data_end, &eth)) {
        trace_printk("handle_lxc_traffic: invalid eth data\n",
                    sizeof("handle_lxc_traffic: invalid eth data\n"));
        return DROP_INVALID;
    }

    PRINT_MAC_PAIR("handle_lxc_traffic: ", eth->h_source, eth->h_dest);

    if (from_host) {
        ret = from_host_to_lxc(ctx, &ext_err);
        if (IS_ERR(ret)) {
            trace_printk("handle_lxc_traffic: from_host_to_lxc error ret=%d\n",
                        sizeof("handle_lxc_traffic: from_host_to_lxc error ret=%d\n"),
                        ret);
            return send_drop_notify_error_ext(ctx, HOST_ID, ret, ext_err,
                                             CTX_ACT_DROP, METRIC_EGRESS);
        }

        lxc_id = ctx_load_meta(ctx, CB_DST_ENDPOINT_ID);
        ctx_store_meta(ctx, CB_SRC_LABEL, HOST_ID);
        trace_printk("handle_lxc_traffic: tail calling policy, lxc_id=%u\n",
                    sizeof("handle_lxc_traffic: tail calling policy, lxc_id=%u\n"),
                    lxc_id);
        ret = tail_call_policy(ctx, (__u16)lxc_id);
        trace_printk("handle_lxc_traffic: tail_call_policy returned %d\n",
                    sizeof("handle_lxc_traffic: tail_call_policy returned %d\n"),
                    ret);
        return send_drop_notify_error(ctx, HOST_ID, ret,
                                     CTX_ACT_DROP, METRIC_EGRESS);
    }

    ret = to_host_from_lxc(ctx);
    trace_printk("handle_lxc_traffic: returning ret=%d\n",
                sizeof("handle_lxc_traffic: returning ret=%d\n"),
                ret);
    return ret;
#else
    trace_printk("handle_lxc_traffic: no host firewall, returning 0\n",
                sizeof("handle_lxc_traffic: no host firewall, returning 0\n"));
    return 0;
#endif
}

BPF_LICENSE("Dual BSD/GPL");