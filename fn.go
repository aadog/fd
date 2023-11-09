package main

import (
	"errors"
	"github.com/frida/frida-go/frida"
	"strings"
)

func GetApplication(d *frida.Device, name string) (*frida.Application, error) {
	apps, err := d.EnumerateApplications("", frida.ScopeFull)
	if err != nil {
		return nil, err
	}
	for _, app := range apps {
		if strings.ToLower(app.Name()) == strings.ToLower(name) || (strings.ToLower(app.Identifier()) == strings.ToLower(name)) {
			return app, nil
		}
	}
	return nil, errors.New("application not found")
}
func GetProcess(d *frida.Device, name string) (*frida.Process, error) {
	pss, err := d.EnumerateProcesses(frida.ScopeFull)
	if err != nil {
		return nil, err
	}
	for _, ps := range pss {
		if strings.ToLower(ps.Name()) == strings.ToLower(name) || strings.ToLower(ps.Params()["path"].(string)) == strings.ToLower(name) {
			return ps, nil
		}
	}
	return nil, errors.New("process not found")
}

func DeviceForDevi(devi string) (*frida.Device, error) {
	var d *frida.Device
	var err error
	if devi == "" {
		d, err = fmgr.USBDevice()
		if err != nil {
			return nil, err
		}
	} else {
		d, err = fmgr.AddRemoteDevice(devi, frida.NewRemoteDeviceOptions())
		if err != nil {
			return nil, err
		}
	}
	return d, nil
}
