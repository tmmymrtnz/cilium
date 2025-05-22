// pkg/fanout/fanout.go
package fanout

import (
    "fmt"
    "net"
    "os"
    "time"
)

// Config holds your fan-out parameters.
type Config struct {
    Listen   string   // e.g. ":9000"
    Backends []string // e.g. ["10.0.0.5:9000", "10.0.0.6:9000"]
}

// Run starts your UDP listener and fans each packet out.
func Run(cfg Config) error {
    lnAddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
    if err != nil {
        return fmt.Errorf("invalid listen address %q: %w", cfg.Listen, err)
    }
    sock, err := net.ListenUDP("udp", lnAddr)
    if err != nil {
        return fmt.Errorf("listen %s failed: %w", cfg.Listen, err)
    }
    go func() {
        buf := make([]byte, 64*1024)
        backends := make([]*net.UDPAddr, len(cfg.Backends))
        for i, b := range cfg.Backends {
            addr, err := net.ResolveUDPAddr("udp", b)
            if err != nil {
                fmt.Fprintf(os.Stderr, "invalid backend %q: %v\n", b, err)
                return
            }
            backends[i] = addr
        }
        for {
            n, src, err := sock.ReadFromUDP(buf)
            if err != nil {
                fmt.Fprintf(os.Stderr, "read error: %v\n", err)
                time.Sleep(100 * time.Millisecond)
                continue
            }
            for _, dst := range backends {
                if _, err := sock.WriteToUDP(buf[:n], dst); err != nil {
                    fmt.Fprintf(os.Stderr, "fanout %v failed: %v\n", dst, err)
                }
            }
            // optional: log every X packets or bytes
            fmt.Printf("fanned out %d-byte packet from %v\n", n, src)
        }
    }()
    return nil
}
