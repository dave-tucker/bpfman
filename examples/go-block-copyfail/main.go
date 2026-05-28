//go:build linux
// +build linux

// go-block-copyfail is the userspace component for the block-copyfail
// ClusterBpfApplication.  It runs as a DaemonSet on every node, writes the
// init net-namespace inode into the BPF init_net_ns map (so the UDP_ENCAP
// mitigation can distinguish host vs. container calls), then streams blocked-
// event notifications from the shared ring buffer.
//
// Maps are provided by bpfman's CSI driver at /run/block-copyfail/maps/.
// The volume must NOT be mounted read-only because we write to init_net_ns.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	MapsMountPoint   = "/run/block-copyfail/maps"
	EventsMapName    = "events"
	InitNetNsMapName = "init_net_ns"
)

// BlockEvent mirrors struct block_event in mitigations.h.
// C layout: pid(4) comm(16) reason(4) ts(8) = 32 bytes.
// reason ends at offset 24 which is already 8-byte aligned, so the C compiler
// adds no padding before ts.  binary.Read is sequential so the Go struct must
// match exactly — no filler fields.
type BlockEvent struct {
	Pid    uint32
	Comm   [16]byte
	Reason uint32
	Ts     uint64
}

// Block-reason constants — must match mitigations.h.
const (
	ReasonCopyfail  uint32 = 1 // CVE-2026-31431: AF_ALG AEAD bind
	ReasonRxrpc     uint32 = 2 // CVE-2026-43500: AF_RXRPC socket
	ReasonUdpSplice uint32 = 3 // CVE-2026-43284: MSG_SPLICE_PAGES/UDP
	ReasonEspintcp  uint32 = 4 // CVE-2026-46300: TCP_ULP espintcp
	ReasonUdpEncap  uint32 = 5 // CVE-2026-43284: UDP_ENCAP non-init-netns
)

func reasonString(r uint32) string {
	switch r {
	case ReasonCopyfail:
		return "CVE-2026-31431  AF_ALG AEAD bind blocked          (socket_bind)"
	case ReasonRxrpc:
		return "CVE-2026-43500  AF_RXRPC socket creation blocked   (socket_create)"
	case ReasonUdpSplice:
		return "CVE-2026-43284  UDP MSG_SPLICE_PAGES blocked        (socket_sendmsg)"
	case ReasonEspintcp:
		return "CVE-2026-46300  TCP_ULP espintcp blocked            (socket_setsockopt)"
	case ReasonUdpEncap:
		return "CVE-2026-43284  UDP_ENCAP from non-init netns blocked (socket_setsockopt)"
	default:
		return fmt.Sprintf("unknown reason %d", r)
	}
}

// bpf2go compiles mitigations.bpf.c and generates Go type bindings.
// Run `go generate ./...` from the examples directory before building.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -cflags "-O2 -g -Wall" -target amd64,arm64,ppc64le,s390x bpf ./bpf/mitigations.bpf.c -- -I.:/usr/include/bpf:/usr/include/linux

func main() {
	log.SetPrefix("go-block-copyfail: ")

	// Write the init net-namespace inode into the BPF map before events start
	// flowing.  The UDP_ENCAP mitigation reads this value to decide whether a
	// setsockopt call comes from the host net namespace or a container.
	initNetNsPath := fmt.Sprintf("%s/%s", MapsMountPoint, InitNetNsMapName)
	if err := populateInitNetNs(initNetNsPath); err != nil {
		log.Fatalf("populate init_net_ns: %v", err)
	}

	// Open the ring buffer map that all BPF programs write blocked events into.
	eventsPath := fmt.Sprintf("%s/%s", MapsMountPoint, EventsMapName)
	eventsMap, err := ebpf.LoadPinnedMap(eventsPath, &ebpf.LoadPinOptions{})
	if err != nil {
		log.Fatalf("open pinned events map %s: %v", eventsPath, err)
	}
	defer eventsMap.Close()

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("create ring buffer reader: %v", err)
	}
	defer rd.Close()

	log.Println("listening for blocked events…")

	// Close the reader on SIGINT/SIGTERM so rd.Read() unblocks and we exit cleanly.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("shutting down…")
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ring buffer read: %v", err)
			continue
		}

		var evt BlockEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}

		comm := strings.TrimRight(string(evt.Comm[:]), "\x00")
		log.Printf("BLOCKED  pid=%-6d  comm=%-16s  %s", evt.Pid, comm, reasonString(evt.Reason))
	}
}

// populateInitNetNs reads the init network namespace inode number from
// /proc/1/ns/net (PID 1 is always in the init netns) and writes it into the
// BPF init_net_ns array map at key 0.
func populateInitNetNs(mapPath string) error {
	link, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		return fmt.Errorf("readlink /proc/1/ns/net: %w", err)
	}

	var inum uint32
	if _, err := fmt.Sscanf(link, "net:[%d]", &inum); err != nil {
		return fmt.Errorf("parse net ns inode from %q: %w", link, err)
	}
	log.Printf("init net namespace inode = %d", inum)

	m, err := ebpf.LoadPinnedMap(mapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("open pinned map %s: %w", mapPath, err)
	}
	defer m.Close()

	key := uint32(0)
	if err := m.Update(&key, &inum, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update init_net_ns map: %w", err)
	}
	return nil
}
