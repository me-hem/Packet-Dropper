//go:build linux
package main

import (
	"bufio"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf cgroup_connect4.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <cgroup_path> [process_name]", os.Args[0])
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	// Attach the eBPF program to the cgroup connect4 hook
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.IngressProgFunc,
	})
	if err != nil {
		log.Fatalf("Failed to attach program to cgroup: %v", err)
	}
	defer l.Close()

	log.Printf("eBPF program attached to cgroup: %s", cgroupPath)
	log.Printf("Press Ctrl+C to exit and remove the program")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		key := uint32(0)
		var droppedPacketCount uint64
		if err := objs.DroppedPktCount.Lookup(&key, &droppedPacketCount); err != nil {
			log.Printf("Unable to retrieve dropped packet info: %s", err)
			continue
		}
		log.Printf("Dropped Connection Count: %d\n", droppedPacketCount)
	}
}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}