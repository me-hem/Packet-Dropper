//go:build linux

package main

import (
	"log"
	"net"
	"os"
	"time"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf xdp.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Lookup the network interface by name
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network interface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the XDP program to the network interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.IngressProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to interface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl+C to exit and remove the program")

	// Print the number of packets dropped
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		key := uint32(0)
		var droppedPacketCount uint64
		if err := objs.DroppedPktCount.Lookup(&key, &droppedPacketCount); err != nil {
			log.Printf("Unable to retrieve dropped packet info: %s", err)
			continue
		}

		log.Printf("Dropped Packet Count: %d\n", droppedPacketCount)
	}
}