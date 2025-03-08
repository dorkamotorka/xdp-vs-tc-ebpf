package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf drop drop.c

import (
	"fmt"
	"log"
	"net"
	"flag"

	"github.com/cilium/ebpf" // NOTE: Uncomment for TC Hook
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	var ifname string
	flag.StringVar(&ifname, "i", "lo", "Network interface name where the eBPF programs will be attached")
	flag.Parse()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs dropObjects
	if err := loadDropObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach XDP program to the network interface.
	/*
	xdplink, err := link.AttachXDP(link.XDPOptions{
				Program:   objs.XdpDropPort8080,
				Interface: iface.Index,
				//Flags: link.XDPDriverMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdplink.Close()
	fmt.Println("XDP program successfully attached. Press Enter to exit.")
	*/

	// Attach TC Program to the network interface.
	tclink, err := link.AttachTCX(link.TCXOptions{
				Program:   objs.TcDropPort8080,
				Attach:	   ebpf.AttachTCXIngress,
				Interface: iface.Index,
	})
	if err != nil {
			log.Fatal("Attaching TC:", err)
	}
	defer tclink.Close()
	fmt.Println("TC program successfully attached. Press Enter to exit.")

	fmt.Scanln()
}
