// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dupbackendsmap

import (
    "encoding/binary"
    "fmt"
    "net"

    "golang.org/x/sys/unix"

    "github.com/cilium/cilium/pkg/bpf"
    "github.com/cilium/cilium/pkg/ebpf"
    "github.com/cilium/cilium/pkg/logging"
    "github.com/cilium/cilium/pkg/logging/logfields"
    "github.com/sirupsen/logrus"
    "github.com/cilium/hive/cell"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "dup-backends-map")

const (
    // MapName is the kernel map name for dup_backends
    MapName     = "dup_backends"
    // MaxBackends is the maximum number of entries in dup_backends
    MaxBackends = 256
    // pinnedPath is where we pin this map on the host BPF filesystem
    pinnedPath  = "/sys/fs/bpf/cilium/cilium_dup_backends"
)

type dupBackendsMap struct {
    *bpf.Map
}

// singleton instance of our dup_backends BPF map
var dupBackends = dupBackendsMap{
    Map: bpf.NewMap(
        MapName,
        ebpf.Hash,
        &DupBackendsKey{},
        &DupBackendsValue{},
        MaxBackends,
        unix.BPF_F_NO_PREALLOC,
    ).WithPressureMetric(),
}

// Cell defines the Hive module for the dup_backends map
var Cell = cell.Module(
    "dupbackendsmap",
    "eBPF Duplicate-Backends Map",
    cell.Invoke(InitMaps),
)

// DupBackendsKey must match struct dup_backends_key in your BPF C code
type DupBackendsKey struct {
    Idx uint32 `align:"idx"`
}

func (k *DupBackendsKey) New() bpf.MapKey { return &DupBackendsKey{} }
func (k *DupBackendsKey) String() string  { return fmt.Sprintf("%d", k.Idx) }

// DupBackendsValue must match struct dup_backends_value in your BPF C code
type DupBackendsValue struct {
    IP   uint32  `align:"ip"`  // IPv4 in network byte order
    MAC  [6]byte `align:"mac"` // destination MAC
    _    [2]byte             // explicit padding so sizeof==12
}

func (v *DupBackendsValue) New() bpf.MapValue { return &DupBackendsValue{} }
func (v *DupBackendsValue) String() string {
    ip := make(net.IP, 4)
    binary.BigEndian.PutUint32(ip, v.IP)
    return fmt.Sprintf("ip=%s mac=%02x:%02x:%02x:%02x:%02x:%02x",
        ip, v.MAC[0], v.MAC[1], v.MAC[2],
        v.MAC[3], v.MAC[4], v.MAC[5],
    )
}

// IterateCallback is called for every key/value in the map.
type IterateCallback func(key *DupBackendsKey, val *DupBackendsValue)

// AddBackend inserts or updates one backend at index [0,MaxBackends).
func (m dupBackendsMap) AddBackend(idx int, ip net.IP, mac net.HardwareAddr) error {
    if idx < 0 || idx >= MaxBackends {
        return fmt.Errorf("index %d out of range [0,%d)", idx, MaxBackends)
    }
    ip4 := ip.To4()
    if ip4 == nil {
        return fmt.Errorf("invalid IPv4 address: %s", ip)
    }
    if len(mac) != 6 {
        return fmt.Errorf("invalid MAC address: %s", mac)
    }

    key := &DupBackendsKey{Idx: uint32(idx)}
    value := &DupBackendsValue{
        IP:  binary.BigEndian.Uint32(ip4),
        MAC: [6]byte{mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]},
    }

    if err := m.Map.Update(key, value); err != nil {
        return fmt.Errorf("failed to upsert backend[%d]=%s/%s: %w",
            idx, ip4, mac, err)
    }
    log.WithFields(logrus.Fields{
        "idx": idx, "ip": ip4, "mac": mac,
    }).Info("Upserted dup_backends entry")
    return nil
}

// DeleteBackend removes the entry at index [0,MaxBackends).
func (m dupBackendsMap) DeleteBackend(idx int) error {
    if idx < 0 || idx >= MaxBackends {
        return fmt.Errorf("index %d out of range [0,%d)", idx, MaxBackends)
    }
    key := &DupBackendsKey{Idx: uint32(idx)}
    if err := m.Map.Delete(key); err != nil {
        return fmt.Errorf("failed to delete dup_backends[%d]: %w", idx, err)
    }
    log.WithField("idx", idx).Info("Deleted dup_backends entry")
    return nil
}

// LookupBackend retrieves the IP/MAC at index [0,MaxBackends).
func (m dupBackendsMap) LookupBackend(idx int) (*net.IP, *net.HardwareAddr, error) {
    if idx < 0 || idx >= MaxBackends {
        return nil, nil, fmt.Errorf("index %d out of range [0,%d)", idx, MaxBackends)
    }
    key := &DupBackendsKey{Idx: uint32(idx)}
    raw, err := m.Map.Lookup(key)
    if err != nil {
        return nil, nil, err
    }
    val := raw.(*DupBackendsValue)
    ip := make(net.IP, 4)
    binary.BigEndian.PutUint32(ip, val.IP)
    mac := net.HardwareAddr(val.MAC[:])
    return &ip, &mac, nil
}

// IterateWithCallback walks through all entries in dup_backends.
func (m dupBackendsMap) IterateWithCallback(cb IterateCallback) error {
    return m.Map.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
        cb(k.(*DupBackendsKey), v.(*DupBackendsValue))
    })
}

// MaxBackends returns the configured size of the map.
func (m dupBackendsMap) MaxBackends() uint32 {
    return uint32(m.Map.MaxEntries())
}

// OpenOrCreate tries to open a pinned map, falling back to Create().
func (m *dupBackendsMap) OpenOrCreate() error {
    if err := m.Map.Open(); err == nil {
        return nil
    }
    if err := m.Map.Create(); err != nil {
        return fmt.Errorf("unable to open or create %s: %w", MapName, err)
    }
    return nil
}

// InitMaps is invoked by Hive to ensure the map exists & is pinned.
func InitMaps() error {
    log.WithField("map_name", MapName).Debug("Attempting to open or create dup_backends map")
    if err := dupBackends.OpenOrCreate(); err != nil {
        log.WithError(err).WithFields(logrus.Fields{
            "map_name":    MapName,
            "pinned_path": pinnedPath,
        }).Error("Failed to open or create dup_backends map")
        return err
    }
    log.WithFields(logrus.Fields{
        "map_name":    MapName,
        "pinned_path": pinnedPath,
    }).Info("Successfully initialized dup_backends map")
    return nil
}
