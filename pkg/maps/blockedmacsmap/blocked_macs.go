// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package blockedmacsmap

import (
    "fmt"
    "net"
    "unsafe"

    "golang.org/x/sys/unix"

    "github.com/cilium/cilium/pkg/bpf"
    "github.com/cilium/cilium/pkg/ebpf"
    "github.com/cilium/hive/cell"
)

const (
    MapName    = "blocked_macs"
    MaxEntries = 256
)

// Map provides access to the eBPF map blocked_macs.
type Map interface {
    // AddBlockedMAC adds a MAC address to the blocked_macs map.
    AddBlockedMAC(mac net.HardwareAddr) error
    // DeleteBlockedMAC removes a MAC address from the blocked_macs map.
    DeleteBlockedMAC(mac net.HardwareAddr) error
    // LookupBlockedMAC checks if a MAC address is blocked.
    LookupBlockedMAC(mac net.HardwareAddr) (bool, error)
    // IterateWithCallback iterates through all MACs in the map.
    IterateWithCallback(cb IterateCallback) error
    // MaxEntries returns the maximum number of entries.
    MaxEntries() uint32
}

type blockedMACsMap struct {
    bpfMap *ebpf.Map
}

// NewMap creates a new blocked_macs map instance.
func NewMap(maxEntries int) *blockedMACsMap {
    return &blockedMACsMap{
        bpfMap: ebpf.NewMap(&ebpf.MapSpec{
            Name:       MapName,
            Type:       ebpf.Hash,
            KeySize:    uint32(unsafe.Sizeof(MACKey{})),
            ValueSize:  uint32(unsafe.Sizeof(MACValue{})),
            MaxEntries: uint32(maxEntries),
            Flags:      unix.BPF_F_NO_PREALLOC,
            Pinning:    ebpf.PinByName,
        }),
    }
}

func (m *blockedMACsMap) Init() error {
    if err := m.bpfMap.OpenOrCreate(); err != nil {
        return fmt.Errorf("failed to init bpf map: %w", err)
    }
    return nil
}

func (m *blockedMACsMap) close() error {
    if err := m.bpfMap.Close(); err != nil {
        return fmt.Errorf("failed to close bpf map: %w", err)
    }
    return nil
}

func (m *blockedMACsMap) AddBlockedMAC(mac net.HardwareAddr) error {
    if len(mac) != 6 {
        return fmt.Errorf("invalid MAC address: %s", mac)
    }
    key := MACKey{Addr: [6]byte{mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]}}
    value := MACValue{Block: 1}
    return m.bpfMap.Update(key, value, 0)
}

func (m *blockedMACsMap) DeleteBlockedMAC(mac net.HardwareAddr) error {
    if len(mac) != 6 {
        return fmt.Errorf("invalid MAC address: %s", mac)
    }
    key := MACKey{Addr: [6]byte{mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]}}
    return m.bpfMap.Delete(key)
}

func (m *blockedMACsMap) LookupBlockedMAC(mac net.HardwareAddr) (bool, error) {
    if len(mac) != 6 {
        return false, fmt.Errorf("invalid MAC address: %s", mac)
    }
    key := MACKey{Addr: [6]byte{mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]}}
    var value MACValue
    err := m.bpfMap.Lookup(key, &value)
    if err != nil {
        return false, err
    }
    return value.Block == 1, nil
}

type IterateCallback func(*MACKey, *MACValue)

func (m *blockedMACsMap) IterateWithCallback(cb IterateCallback) error {
    return m.bpfMap.IterateWithCallback(&MACKey{}, &MACValue{},
        func(k, v interface{}) {
            key := k.(*MACKey)
            value := v.(*MACValue)
            cb(key, value)
        },
    )
}

func (m *blockedMACsMap) MaxEntries() uint32 {
    return m.bpfMap.MaxEntries()
}

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

// LoadBlockedMACsMap loads the pre-initialized blocked_macs map.
func LoadBlockedMACsMap() (Map, error) {
    bpfMap, err := ebpf.LoadRegisterMap(MapName)
    if err != nil {
        return nil, fmt.Errorf("failed to load bpf map: %w", err)
    }
    return &blockedMACsMap{bpfMap: bpfMap}, nil
}

var blockedMACs = NewMap(MaxEntries)

var Cell = cell.Module(
    "blockedmacsmap",
    "eBPF blocked-MACs map",
    cell.Invoke(func() error {
        return blockedMACs.Init()
    }),
)