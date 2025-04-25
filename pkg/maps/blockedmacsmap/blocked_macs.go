// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package blockedmacsmap

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "blockedmacs-map")

const (
	// MapName for blocked_macs map
	MapName = "blocked_macs"
	// MaxEntries is the maximum number of keys in the blocked_macs map
	MaxEntries = 256
)

// blockedMACsMap represents the blocked_macs BPF map
type blockedMACsMap struct {
	*bpf.Map
}

// blockedMACs is the singleton instance of the blocked_macs map
var blockedMACs = blockedMACsMap{
	bpf.NewMap(
		MapName,
		ebpf.Hash,
		&MACKey{},
		&MACValue{},
		MaxEntries,
		unix.BPF_F_NO_PREALLOC,
	).WithPressureMetric(),
}

// Cell defines the Hive module for the blocked_macs map
var Cell = cell.Module(
	"blockedmacsmap",
	"eBPF Blocked-MACs Map",
	cell.Invoke(InitMaps),
)

// MACKey must match struct blockedmacs_key in bpf/lib/maps.h
type MACKey struct {
	Addr [6]byte `align:"addr"`
}

func (k *MACKey) New() bpf.MapKey { return &MACKey{} }
func (k *MACKey) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		k.Addr[0], k.Addr[1], k.Addr[2],
		k.Addr[3], k.Addr[4], k.Addr[5])
}

// MACValue must match struct blockedmacs_value in bpf/lib/maps.h
type MACValue struct {
	Block uint8 `align:"blocked"`
}

func (v *MACValue) New() bpf.MapValue { return &MACValue{} }
func (v *MACValue) String() string    { return fmt.Sprintf("%d", v.Block) }

// IterateCallback defines the signature for iterating map entries
type IterateCallback func(*MACKey, *MACValue)

// AddBlockedMAC adds a MAC address to the blocked_macs map
func (m blockedMACsMap) AddBlockedMAC(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return fmt.Errorf("invalid MAC address: %s", mac)
	}
	key := MACKey{Addr: [6]byte{mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]}}
	value := MACValue{Block: 1}
	if err := m.Update(&key, &value); err != nil {
		return fmt.Errorf("failed to add MAC %s: %w", mac, err)
	}
	log.WithField("mac", mac).Info("Added MAC to blocked_macs map")
	return nil
}

// DeleteBlockedMAC removes a MAC address from the blocked_macs map
func (m blockedMACsMap) DeleteBlockedMAC(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return fmt.Errorf("invalid MAC address: %s", mac)
	}
	key := MACKey{Addr: [6]byte{mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]}}
	if err := m.Delete(&key); err != nil {
		return fmt.Errorf("failed to delete MAC %s: %w", mac, err)
	}
	log.WithField("mac", mac).Info("Deleted MAC from blocked_macs map")
	return nil
}

// LookupBlockedMAC checks if a MAC address is blocked
func (m blockedMACsMap) LookupBlockedMAC(mac net.HardwareAddr) (bool, error) {
	if len(mac) != 6 {
		return false, fmt.Errorf("invalid MAC address: %s", mac)
	}
	key := MACKey{Addr: [6]byte{mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]}}
	value, err := m.Lookup(&key)
	if err != nil {
		return false, nil // Not found is not an error
	}
	if val, ok := value.(*MACValue); ok {
		return val.Block == 1, nil
	}
	return false, fmt.Errorf("invalid value type for MAC %s", mac)
}

// IterateWithCallback iterates through all MACs in the map
func (m blockedMACsMap) IterateWithCallback(cb IterateCallback) error {
	return m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*MACKey)
		value := v.(*MACValue)
		cb(key, value)
	})
}

// MaxEntries returns the maximum number of entries
func (m blockedMACsMap) MaxEntries() uint32 {
	return uint32(m.Map.MaxEntries())
}

// OpenOrCreate opens or creates the blocked_macs map
func (m *blockedMACsMap) OpenOrCreate() error {
    // Try to open the pinned map
    if err := m.Map.Open(); err == nil {
        return nil
    }
    // Fallback to creating it
    return m.Map.Create()
}

// InitMaps initializes the blocked_macs map
func InitMaps() error {
	log.WithField("map_name", MapName).Debug("Attempting to open or create blocked_macs map")
	if err := blockedMACs.OpenOrCreate(); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			"map_name":    MapName,
			"pinned_path": "/sys/fs/bpf/cilium/cilium_blocked_macs",
		}).Error("Failed to open or create blocked_macs map")
		return err
	}
	log.WithFields(logrus.Fields{
		"map_name":    MapName,
		"pinned_path": "/sys/fs/bpf/cilium/cilium_blocked_macs",
	}).Info("Successfully initialized blocked_macs map")
	return nil
}