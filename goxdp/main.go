
//go:build linux
// +build linux
package main

import (
	"C"
	"github.com/cilium/ebpf/link"
//    "github.com/cilium/ebpf/perf"
)
import (
//    "bytes"
//    "encoding/binary"
    "os"
    "log"
    "os/signal"
    "net"
    "time"
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
    link.Tracepoint("syscalls", "sys_enter_execve", objs.Getp, nil)
    
    ticker := time.NewTicker(1 * time.Second)
    const mapKey uint32 = 0
	for range ticker.C {
		var value string
		if err := objs.Events.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("%s comm %s \n", "sys_execve", value)
	
    if value=="myprocess" {
	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilter,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()
    <-sig }
    <-sig
}
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
