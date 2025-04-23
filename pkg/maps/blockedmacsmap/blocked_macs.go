// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package blockedmacsmap

import (
    "github.com/cilium/ebpf"
    "github.com/cilium/cilium/pkg/bpf"
    "github.com/cilium/cilium/pkg/maps"
)

const (
    // MapName is the kernel name for our blocked‐MACs map.
    MapName     = "blocked_macs"
    // MaxEntries is the max number of MACs we will block.
    MaxEntries  = 256
)

// MACKey is a 6-byte MAC address.
type MACKey struct {
    Addr [6]byte `align:"addr"`
}

func (k *MACKey) New() bpf.MapKey { return &MACKey{} }

// MACValue is just a 1-byte dummy value (we only care about existence).
type MACValue struct {
    Block uint8 `align:"value"`
}

func (v *MACValue) New() bpf.MapValue { return &MACValue{} }

// blockedMACs is a plain hash: MAC → dummy.
var blockedMACs = bpf.NewMap(
    MapName,
    ebpf.Hash,
    &MACKey{},
    &MACValue{},
    MaxEntries,
    0,
)

// Init creates (or opens) and pins the map under /sys/fs/bpf.
func Init() error {
    return blockedMACs.OpenOrCreate()
}

func init() {
    // make sure maps.InitAll() will pick it up
    maps.Register(blockedMACs)
}
