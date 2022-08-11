//go:build linux
// +build linux
package main

import (
	"C"
	"github.com/cilium/ebpf/link"
)
import (
	"os"
    "log"
    "os/signal"
    "net"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ./xdp.bpf.c -- -I/usr/include/bpf -I.
func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

    ifaceName := "lo"
	iface, _ := net.InterfaceByName(ifaceName)

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilter,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()
}

/*	e := make(chan []byte, 300)
	p, err := bpfModule.InitPerfBuf("events", e, nil, 1024)
	must(err)

	p.Start()

	counter := make(map[string]int, 350)
	go func() {
		for data := range e {
			comm := string(data)
			counter[comm]++
		}
	}()

	<-sig
	p.Stop()
	for comm, n := range counter {
		fmt.Printf("%s: %d\n", comm, n)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}*/
