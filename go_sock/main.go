
//go:build linux
// +build linux
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"syscall"
    "unsafe"
    "encoding/binary"
    
    "github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ./sk.bpf.c -- -I/usr/include/bpf -I.

func main() {
var ifname="loop"
const SO_ATTACH_BPF = 50

	program, err := ioutil.ReadFile("bpf_bpfel.o")
	if err != nil {
		fmt.Println("Error readinf file into byte slice !")
	}
	// Get intrface ifindex

	var index int
	links, err := netlink.LinkList()
	if err != nil {
		fmt.Println("Error")
	}

	for _, link := range links {
		// newMap[link.Attrs().Index] = link.Attrs().Name

		if link.Attrs().Name == ifname {
			index = link.Attrs().Index
			fmt.Println("Index is:", link.Attrs().Index)

		}
	}
spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program))
if err != nil {
  panic(err)
}

coll, err := ebpf.NewCollection(spec)
if err != nil {
  panic(err)
}
defer coll.Close()

prog := coll.DetachProgram("sk_filter")
if prog == nil {
  panic("no program named filter found")
}
defer prog.Close()

sock, err := openRawSock(index)
if err != nil {
  panic(err)
}
defer syscall.Close(sock)

if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
  panic(err)
}}

func openRawSock(index int) (int, error) {
	// const ETH_P_ALL uint16 = 0x00<<8 | 0x03
	const ETH_P_ALL uint16 = 0x03

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = htons(ETH_P_ALL)
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
    return *(*uint16)(unsafe.Pointer(&b[0]))
}
