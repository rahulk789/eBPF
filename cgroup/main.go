
//go:build linux
// +build linux

package main

import (
	"flag"
    "fmt"
    "os"
    "errors"
    "log"
	"syscall"
    "os/signal"
    "bytes"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
   	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -type event_data bpf ./sk.bpf.c -- -I/usr/include/bpf -I.

func main() {
	// Name of the kernel function to trace.
	fn := "sys_execve"
    
    pidarg := flag.Int("pid",1000,"the pid of the process to be filtered")
    flag.Parse()
    pid := *pidarg
    //bpf_map_update_elem(pidcheck,pid)
    fmt.Printf("pid:%d",pid)	
    // Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

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

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will emit an event containing pid and command of the execved task.
	kp, err := link.Kprobe(fn, objs.KprobeExecve)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	// bpfEvent is generated by bpf2go.
	var event bpfEventData
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("pid: %d\tcomm: %s\n", event.Pid, unix.ByteSliceToString(event.Comm[:]))
	}
}

