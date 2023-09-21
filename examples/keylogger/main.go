//go:build linux
// +build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	bpfdHelpers "github.com/bpfd-dev/bpfd/bpfd-operator/pkg/helpers"
	gobpfd "github.com/bpfd-dev/bpfd/clients/gobpfd/v1"
	configMgmt "github.com/bpfd-dev/bpfd/examples/pkg/config-mgmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const (
	DefaultConfigPath     = "/etc/bpfd/bpfd.toml"
	PrimaryByteCodeFile   = "/run/bpfd/examples/keylogger/bpf_bpfel_x86.o"
	SecondaryByteCodeFile = "bpf_bpfel_x86.o"
	ProgramName           = "keylogger-example"
	BpfProgramMapIndex    = "keypresses"
)

//go:generate bpf2go -target amd64 -cc clang -no-strip -cflags "-O2 -g -Wall" bpf ./bpf/keylogger.bpf.c -- -I.:/usr/include/bpf:/usr/include/linux
func main() {

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Parse Input Parameters (CmdLine and Config File)
	paramData, err := configMgmt.ParseParamData(configMgmt.ProgTypeXdp, DefaultConfigPath, PrimaryByteCodeFile, SecondaryByteCodeFile)
	if err != nil {
		log.Printf("error processing parameters: %v\n", err)
		return
	}

	var mapPath string

	// If running in a Kubernetes deployment, read the map path from the Bpf Program CRD
	if paramData.CrdFlag {
		c := bpfdHelpers.GetClientOrDie()

		maps, err := bpfdHelpers.GetMaps(c, ProgramName, []string{BpfProgramMapIndex})
		if err != nil {
			log.Printf("error getting bpf stats map: %v\n", err)
			return
		}

		mapPath = maps[BpfProgramMapIndex]
	} else {
		ctx := context.Background()

		configFileData := configMgmt.LoadConfig(DefaultConfigPath)
		creds, err := configMgmt.LoadTLSCredentials(configFileData.Tls)
		if err != nil {
			log.Printf("Failed to generate credentials for new client: %v", err)
			return
		}

		conn, err := configMgmt.CreateConnection(configFileData.Grpc.Endpoints, ctx, creds)
		if err != nil {
			log.Printf("failed to create client connection: %v", err)
			return
		}

		c := gobpfd.NewBpfdClient(conn)

		// If the bytecode src is a Program ID, skip the loading and unloading of the bytecode.
		if paramData.BytecodeSrc != configMgmt.SrcProgId {
			var loadRequestCommon *gobpfd.LoadRequestCommon
			if paramData.MapOwnerId != 0 {
				mapOwnerId := uint32(paramData.MapOwnerId)
				loadRequestCommon = &gobpfd.LoadRequestCommon{
					Location:    paramData.BytecodeSource.Location,
					Name:        "keylogger",
					ProgramType: *bpfdHelpers.Kprobe.Uint32(),
					MapOwnerId:  &mapOwnerId,
				}
			} else {
				loadRequestCommon = &gobpfd.LoadRequestCommon{
					Location:    paramData.BytecodeSource.Location,
					Name:        "keylogger",
					ProgramType: *bpfdHelpers.Kprobe.Uint32(),
				}
			}

			loadRequest := &gobpfd.LoadRequest{
				Common: loadRequestCommon,
				AttachInfo: &gobpfd.LoadRequest_KprobeAttachInfo{
					KprobeAttachInfo: &gobpfd.KprobeAttachInfo{
						FnName: "input_handle_event",
					},
				},
			}

			// 1. Load Program using bpfd
			var res *gobpfd.LoadResponse
			res, err = c.Load(ctx, loadRequest)
			if err != nil {
				conn.Close()
				log.Print(err)
				return
			}
			paramData.ProgId = uint(res.GetId())
			log.Printf("Program registered with id %d\n", paramData.ProgId)

			// 2. Set up defer to unload program when this is closed
			defer func(id uint) {
				log.Printf("Unloading Program: %d\n", id)
				_, err = c.Unload(ctx, &gobpfd.UnloadRequest{Id: uint32(id)})
				if err != nil {
					conn.Close()
					log.Print(err)
					return
				}
				conn.Close()
			}(paramData.ProgId)
		} else {
			// 2. Set up defer to close connection
			defer func(id uint) {
				log.Printf("Closing Connection for Program: %d\n", id)
				conn.Close()
			}(paramData.ProgId)
		}

		// 3. Get access to our map
		mapPath, err = configMgmt.RetrieveMapPinPath(ctx, c, paramData.ProgId, bpfdHelpers.Xdp.Uint32(), "xdp_stats_map")
		if err != nil {
			log.Printf("Unable to retrieve maps\n")
			conn.Close()
			log.Print(err)
			return
		}
	}

	opts := &ebpf.LoadPinOptions{
		ReadOnly:  false,
		WriteOnly: false,
		Flags:     0,
	}
	perfMap, err := ebpf.LoadPinnedMap(mapPath, opts)
	if err != nil {
		log.Printf("Failed to load pinned Map: %s\n", mapPath)
		log.Print(err)
		return
	}

	rd, err := perf.NewReader(perfMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		d := binary.LittleEndian.Uint32(record.RawSample[0:4])
		s := keyMap[d]
		log.Printf("%s\n", s)
	}
}

func withoutBpfd() {
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 11,
		},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe("input_handle_event", objs.InputHandleEvent, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	rd, err := perf.NewReader(objs.Keypresses, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		d := binary.LittleEndian.Uint32(record.RawSample[0:4])
		s := keyMap[d]
		log.Println("Record: ", s)
	}
}

var keyMap = map[uint32]string{
	0x1:  "ESC",
	0x2:  "1",
	0x3:  "2",
	0x4:  "3",
	0x5:  "4",
	0x6:  "5",
	0x7:  "6",
	0x8:  "7",
	0x9:  "8",
	0xa:  "9",
	0xb:  "0",
	0xc:  "-",
	0xd:  "=",
	0xe:  "BACKSPACE",
	0xf:  "TAB",
	0x10: "Q",
	0x11: "W",
	0x12: "E",
	0x13: "R",
	0x14: "T",
	0x15: "Y",
	0x16: "U",
	0x17: "I",
	0x18: "O",
	0x19: "P",
	0x1a: "[",
	0x1b: "]",
	0x1c: "ENTER",
	0x1d: "LEFTCTRL",
	0x1e: "A",
	0x1f: "S",
	0x20: "D",
	0x21: "F",
	0x22: "G",
	0x23: "H",
	0x24: "J",
	0x25: "K",
	0x26: "L",
	0x27: ";",
	0x28: "'",
	0x29: "`",
	0x2a: "LEFTSHIFT",
	0x2b: "\\",
	0x2c: "Z",
	0x2d: "X",
	0x2e: "C",
	0x2f: "V",
	0x30: "B",
	0x31: "N",
	0x32: "M",
	0x33: ",",
	0x34: ".",
	0x35: "/",
	0x36: "RIGHTSHIFT",
	0x37: "KPASTERISK",
	0x38: "LEFTALT",
	0x39: "SPACE",
	0x3a: "CAPSLOCK",
	0x3b: "F1",
	0x3c: "F2",
	0x3d: "F3",
	0x3e: "F4",
	0x3f: "F5",
	0x40: "F6",
	0x41: "F7",
	0x42: "F8",
	0x43: "F9",
	0x44: "F10",
	0x45: "NUMLOCK",
	0x46: "SCROLLLOCK",
}
