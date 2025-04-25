// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package blockedmacsmap

import (
    "fmt"

    "github.com/cilium/ebpf"
    "github.com/cilium/hive/cell"

    "github.com/cilium/cilium/pkg/bpf"
)

var Cell = cell.Module(
    "blockedmacsmap",
    "eBPF blocked-MACs map",
    cell.Invoke(InitMaps),
)

const (
    MapName = "blocked-macs"
    MaxEntries = 256
)

// MACKey is a 6-byte Ethernet address.
type MACKey struct {
    Addr [6]byte `align:"addr"`
}

func (k *MACKey) New() bpf.MapKey { return &MACKey{} }
func (k *MACKey) String() string {
    return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
        k.Addr[0], k.Addr[1], k.Addr[2],
        k.Addr[3], k.Addr[4], k.Addr[5],
    )
}

// MACValue is a 1-byte dummy payload (1 == blocked).
type MACValue struct {
    Block uint8 `align:"value"`
}

func (v *MACValue) New() bpf.MapValue { return &MACValue{} }
func (v *MACValue) String() string    { return fmt.Sprintf("%d", v.Block) }

var blockedMACs = bpf.NewMap(
    MapName,
    ebpf.Hash,
    &MACKey{},
    &MACValue{},
    MaxEntries,
    0,
)

// InitMaps opens (or creates & pins) the blocked_macs map under /sys/fs/bpf.
func InitMaps() error {
    return blockedMACs.OpenOrCreate()
}
