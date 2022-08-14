
//go:build linux
// +build linux
package main

import (
	"C"
	"github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
)
import (
    "bytes"
    "encoding/binary"
    "os"
    "log"
    "os/signal"
    "net"
)
type y struct {
    comm byte
}
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ./xdp.bpf.c -- -I/usr/include/bpf -I.
func main() {
    var x y
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
    rd, _ := perf.NewReader(objs.Events, os.Getpagesize())

    for {
    	ev, err := rd.Read()
		if err != nil {
			log.Fatalf("Read fail")
		}
        b_arr := bytes.NewBuffer(ev.RawSample)
    if err := binary.Read(b_arr, binary.LittleEndian, &x); err != nil {
			log.Printf("parsing perf event: %s", err)
            continue
		} 
    if x.comm=="myprocess" {
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
