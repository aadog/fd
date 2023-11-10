package main

import (
	"embed"
	"github.com/frida/frida-go/frida"
)

//go:embed frida-agent-example
var projectExample embed.FS

var fmgr *frida.DeviceManager

func init() {
	fmgr = frida.NewDeviceManager()
}
