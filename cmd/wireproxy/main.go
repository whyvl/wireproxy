package main

import (
	"context"
	"fmt"
	"github.com/landlock-lsm/go-landlock/landlock"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/akamensky/argparse"
	"github.com/pufferffish/wireproxy"
	"golang.zx2c4.com/wireguard/device"
	"suah.dev/protect"
)

// an argument to denote that this process was spawned by -d
const daemonProcess = "daemon-process"

var version = "1.0.8-dev"

func panicIfError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// attempts to pledge and panic if it fails
// this does nothing on non-OpenBSD systems
func pledgeOrPanic(promises string) {
	panicIfError(protect.Pledge(promises))
}

// attempts to unveil and panic if it fails
// this does nothing on non-OpenBSD systems
func unveilOrPanic(path string, flags string) {
	panicIfError(protect.Unveil(path, flags))
}

// get the executable path via syscalls or infer it from argv
func executablePath() string {
	programPath, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return programPath
}

func lock(stage string) {
	switch stage {
	case "boot":
		exePath := executablePath()
		// OpenBSD
		unveilOrPanic("/", "r")
		unveilOrPanic(exePath, "x")
		// only allow standard stdio operation, file reading, networking, and exec
		// also remove unveil permission to lock unveil
		pledgeOrPanic("stdio rpath inet dns proc exec")
		// Linux
		panicIfError(landlock.V4.BestEffort().RestrictPaths(
			landlock.RODirs("/"),
		))
	case "boot-daemon":
	case "read-config":
		// OpenBSD
		pledgeOrPanic("stdio rpath inet dns")
	case "ready":
		// no file access is allowed from now on, only networking
		// OpenBSD
		pledgeOrPanic("stdio inet dns")
		// Linux
		net.DefaultResolver.PreferGo = true // needed to lock down dependencies
		panicIfError(landlock.V4.BestEffort().RestrictPaths(
			landlock.ROFiles("/etc/resolv.conf"),
			landlock.ROFiles("/dev/fd"),
			landlock.ROFiles("/dev/zero"),
			landlock.ROFiles("/dev/urandom"),
			landlock.ROFiles("/etc/localtime"),
			landlock.ROFiles("/proc/self/stat"),
			landlock.ROFiles("/proc/self/status"),
			landlock.ROFiles("/usr/share/locale"),
			landlock.ROFiles("/proc/self/cmdline"),
			landlock.ROFiles("/usr/share/zoneinfo"),
			landlock.ROFiles("/proc/sys/kernel/version"),
			landlock.ROFiles("/proc/sys/kernel/ngroups_max"),
			landlock.ROFiles("/proc/sys/kernel/cap_last_cap"),
			landlock.ROFiles("/proc/sys/vm/overcommit_memory"),
			landlock.RWFiles("/dev/log"),
			landlock.RWFiles("/dev/null"),
			landlock.RWFiles("/dev/full"),
			landlock.RWFiles("/dev/stdin"),
			landlock.RWFiles("/dev/stdout"),
			landlock.RWFiles("/dev/stderr"),
			landlock.RWFiles("/proc/self/fd"),
		))
	default:
		panic("invalid stage")
	}
}

func extractPort(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}

	return uint16(port)
}

func lockNetwork(sections []wireproxy.RoutineSpawner, infoAddr *string) {
	var rules []landlock.Rule
	if infoAddr != nil && *infoAddr != "" {
		rules = append(rules, landlock.BindTCP(extractPort(*infoAddr)))
	}

	for _, section := range sections {
		switch section := section.(type) {
		case *wireproxy.TCPServerTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(extractPort(section.Target)))
		case *wireproxy.HTTPConfig:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		case *wireproxy.TCPClientTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(uint16(section.BindAddress.Port)))
		case *wireproxy.Socks5Config:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		}
	}

	panicIfError(landlock.V4.RestrictNet(rules...))
}

func main() {
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGQUIT)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-s
		cancel()
	}()

	exePath := executablePath()
	lock("boot")

	isDaemonProcess := len(os.Args) > 1 && os.Args[1] == daemonProcess
	args := os.Args
	if isDaemonProcess {
		lock("boot-daemon")
		args = []string{args[0]}
		args = append(args, os.Args[2:]...)
	}
	parser := argparse.NewParser("wireproxy", "Userspace wireguard client for proxying")

	config := parser.String("c", "config", &argparse.Options{Help: "Path of configuration file"})
	silent := parser.Flag("s", "silent", &argparse.Options{Help: "Silent mode"})
	daemon := parser.Flag("d", "daemon", &argparse.Options{Help: "Make wireproxy run in background"})
	info := parser.String("i", "info", &argparse.Options{Help: "Specify the address and port for exposing health status"})
	printVerison := parser.Flag("v", "version", &argparse.Options{Help: "Print version"})
	configTest := parser.Flag("n", "configtest", &argparse.Options{Help: "Configtest mode. Only check the configuration file for validity."})

	err := parser.Parse(args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		return
	}

	if *printVerison {
		fmt.Printf("wireproxy, version %s\n", version)
		return
	}

	if *config == "" {
		fmt.Println("configuration path is required")
		return
	}

	if !*daemon {
		lock("read-config")
	}

	conf, err := wireproxy.ParseConfig(*config)
	if err != nil {
		log.Fatal(err)
	}

	if *configTest {
		fmt.Println("Config OK")
		return
	}

	lockNetwork(conf.Routines, info)

	if isDaemonProcess {
		os.Stdout, _ = os.Open(os.DevNull)
		os.Stderr, _ = os.Open(os.DevNull)
		*daemon = false
	}

	if *daemon {
		args[0] = daemonProcess
		cmd := exec.Command(exePath, args...)
		err = cmd.Start()
		if err != nil {
			fmt.Println(err.Error())
		}
		return
	}

	// Wireguard doesn't allow configuring which FD to use for logging
	// https://github.com/WireGuard/wireguard-go/blob/master/device/logger.go#L39
	// so redirect STDOUT to STDERR, we don't want to print anything to STDOUT anyways
	os.Stdout = os.NewFile(uintptr(syscall.Stderr), "/dev/stderr")
	logLevel := device.LogLevelVerbose
	if *silent {
		logLevel = device.LogLevelSilent
	}

	lock("ready")

	tun, err := wireproxy.StartWireguard(conf.Device, logLevel)
	if err != nil {
		log.Fatal(err)
	}

	for _, spawner := range conf.Routines {
		go spawner.SpawnRoutine(tun)
	}

	tun.StartPingIPs()

	if *info != "" {
		go func() {
			err := http.ListenAndServe(*info, tun)
			if err != nil {
				panic(err)
			}
		}()
	}

	<-ctx.Done()
}
