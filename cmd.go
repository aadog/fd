package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/aadog/dict-go"
	"github.com/frida/frida-go/frida"
	"github.com/gin-gonic/gin"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"time"
)

type ReqRpcCall struct {
	Func    string `json:"func"`
	Args    []any  `json:"args"`
	Timeout string `json:"timeout"`
}
type ResRpcCall struct {
	ResRpcCall bool    `json:"resRpcCall"`
	Error      *string `json:"error"`
	Data       any     `json:"data"`
}

func Ptr[T any](t T) *T {
	return &t
}

// 列出所有主机
func listDevices() error {
	ls, err := fmgr.EnumerateDevices()
	if err != nil {
		return err
	}
	for _, d := range ls {
		if d.DeviceType() != frida.DeviceTypeRemote || strings.Contains(d.ID(), "@") {
			params, err := d.Params()
			if err != nil {
				return err
			}
			p := dict.NewDictWithObj(params)
			os := p.GetDict("os")
			fmt.Println(fmt.Sprintf("id:%s,name:%s,type:%s,access:%s, os:%s/%s/%s,%s ", d.ID(), d.Name(), d.DeviceType().String(), p.GetString("access"), p.GetString("platform"), p.GetString("arch"), os.GetString("name"), os.GetString("version")))
		} else {
			fmt.Println(fmt.Sprintf("id:%s,name:%s,type:%s", d.ID(), d.Name(), d.DeviceType().String()))
		}
	}

	return nil
}

// 列出所有app
func listApp(devi string) error {
	d, err := DeviceForDevi(devi)
	if err != nil {
		return err
	}
	defer d.Clean()

	params, err := d.Params()
	if err != nil {
		return err
	}
	p := dict.NewDictWithObj(params)
	os := p.GetDict("os")
	fmt.Println(fmt.Sprintf("deviceInfo name:%s, access:%s, os:%s/%s/%s,%s ", d.Name(), p.GetString("access"), p.GetString("platform"), p.GetString("arch"), os.GetString("name"), os.GetString("version")))
	apps, err := d.EnumerateApplications("", frida.ScopeFull)
	if err != nil {
		return err
	}
	for _, app := range apps {
		fmt.Println(app.String())
	}
	return nil
}

// 列出所有进程
func listProcess(devi string) error {
	d, err := DeviceForDevi(devi)
	if err != nil {
		return err
	}
	defer d.Clean()

	params, err := d.Params()
	if err != nil {
		return err
	}
	p := dict.NewDictWithObj(params)
	os := p.GetDict("os")
	fmt.Println(fmt.Sprintf("deviceInfo name:%s, access:%s, os:%s/%s/%s,%s ", d.Name(), p.GetString("access"), p.GetString("platform"), p.GetString("arch"), os.GetString("name"), os.GetString("version")))
	apps, err := d.EnumerateProcesses(frida.ScopeFull)
	if err != nil {
		return err
	}
	for _, app := range apps {
		p := app.Params()
		fmt.Println(fmt.Sprintf("名称:%-50s pid:%d path:%s", app.Name(), app.PID(), p["path"]))
	}
	return nil
}

// 创建工程
func createProejct(projectName string) error {
	if projectName == "" {
		return errors.New("还没有指定创建的目录")
	}
	err := os.MkdirAll(projectName, os.ModePerm)
	if err != nil {
		return err
	}
	err = fs.WalkDir(projectExample, ".", func(path string, d fs.DirEntry, err error) error {
		if path == "." {
			return nil
		}
		if d.IsDir() {
			topath := strings.ReplaceAll(path, "frida-agent-example", projectName)
			err = os.MkdirAll(topath, os.ModePerm)
			if err != nil {
				return err
			}
		} else {
			o, err := projectExample.ReadFile(path)
			if err != nil {
				return err
			}
			o = bytes.ReplaceAll(o, []byte("frida-agent-example"), []byte(projectName))
			topath := strings.ReplaceAll(path, "frida-agent-example", projectName)
			err = os.WriteFile(topath, o, os.ModePerm)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Println("创建工程成功:", projectName)
	fmt.Println("执行以下命令")
	fmt.Println()
	fmt.Println("cd ", projectName)
	fmt.Println("npm install")
	fmt.Println("npm run watch")
	fmt.Println("run _agent.js -name 通讯录")
	return nil
}

func run(script string, name string, isPid bool, runIsBinPath bool, restart bool, devi string) error {
	if isPid == true {
		return runPid(script, name, devi)
	} else if runIsBinPath {
		return runBinPath(script, name, restart, devi)
	} else {
		return runPackage(script, name, restart, devi)
	}
	return nil
}

func runPid(script string, name string, devi string) error {
	task, taskCancel := context.WithCancel(context.TODO())
	defer taskCancel()
	d, err := DeviceForDevi(devi)
	if err != nil {
		return err
	}
	defer d.Clean()

	params, err := d.Params()
	if err != nil {
		return err
	}
	p := dict.NewDictWithObj(params)
	osDict := p.GetDict("os")
	fmt.Println(fmt.Sprintf("deviceInfo name:%s, access:%s, os:%s/%s/%s,%s ", d.Name(), p.GetString("access"), p.GetString("platform"), p.GetString("arch"), osDict.GetString("name"), osDict.GetString("version")))

	var pid int
	_pid, err := strconv.ParseInt(name, 10, 64)
	if err != nil {
		return err
	}
	pid = int(_pid)
	fmt.Println(fmt.Sprintf("调试进程:%d,脚本:%s", pid, script))

	session, err := d.Attach(pid, frida.NewSessionOptions(frida.RealmNative, 5000))
	if err != nil {
		return err
	}
	defer session.Detach()
	defer session.Clean()

	jsByte, err := os.ReadFile(script)
	if err != nil {
		return err
	}
	var sc *frida.Script
	sc, err = session.CreateScript(string(jsByte))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.TODO())
	sc.On("destroyed", func() {
		cancel()
		fmt.Println("destroyed")
	})
	defer sc.Clean()
	sc.On("message", func(msg string, data []byte) {
		jsd := dict.NewDict()
		err := jsd.UnmarshalJSON([]byte(msg))
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		tp := jsd.GetString("type")
		if tp == "log" {
			log.Println(jsd.GetString("payload"))
		} else if tp == "error" {
			log.Println(jsd.GetString("stack"))
			log.Println(jsd.GetString("fileName"))
		} else if tp == "send" {
			fmt.Println(jsd.JsonString())
		} else {
			log.Println(jsd.JsonString())
		}
	})
	err = sc.Load()
	if err != nil {
		return err
	}
	defer sc.Unload()
	select {
	case <-ctx.Done():
		fmt.Println("脚本运行完毕")
	case <-task.Done():
		return nil
	}
	return nil
}
func runPackage(script string, name string, restart bool, devi string) error {
	task, taskCancel := context.WithCancel(context.TODO())
	defer taskCancel()
	d, err := DeviceForDevi(devi)
	if err != nil {
		return err
	}
	defer d.Clean()
	params, err := d.Params()
	if err != nil {
		return err
	}
	p := dict.NewDictWithObj(params)
	osDict := p.GetDict("os")
	fmt.Println(fmt.Sprintf("deviceInfo name:%s, access:%s, os:%s/%s/%s,%s ", d.Name(), p.GetString("access"), p.GetString("platform"), p.GetString("arch"), osDict.GetString("name"), osDict.GetString("version")))

	spawnCtx, resumeOK := context.WithCancel(context.TODO())
	var pid int
	app, err := GetApplication(d, name)
	if err != nil {
		return err
	}
	if restart == true {
		d.Kill(app.PID())
		pid = 0
	} else {
		pid = app.PID()
	}
	if pid == 0 {
		pid, err = d.Spawn(app.Identifier(), frida.NewSpawnOptions())
		if err != nil {
			return err
		}
		go func() {
			select {
			case <-spawnCtx.Done():
				d.Resume(pid)
			case <-task.Done():
				return
			}
		}()
	}

	session, err := d.Attach(pid, frida.NewSessionOptions(frida.RealmNative, 5000))
	if err != nil {
		return err
	}
	defer session.Detach()
	defer session.Clean()

	jsByte, err := os.ReadFile(script)
	if err != nil {
		return err
	}
	var sc *frida.Script
	sc, err = session.CreateScript(string(jsByte))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.TODO())
	sc.On("destroyed", func() {
		cancel()
		fmt.Println("destroyed")
	})
	defer sc.Clean()
	sc.On("message", func(msg string, data []byte) {
		jsd := dict.NewDict()
		err := jsd.UnmarshalJSON([]byte(msg))
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		tp := jsd.GetString("type")
		if tp == "log" {
			log.Println(jsd.GetString("payload"))
		} else if tp == "error" {
			log.Println(jsd.GetString("stack"))
			log.Println(jsd.GetString("fileName"))
		} else if tp == "send" {
			fmt.Println(jsd.JsonString())
		} else {
			log.Println(jsd.JsonString())
		}
	})
	err = sc.Load()
	if err != nil {
		return err
	}
	resumeOK()
	defer sc.Unload()
	select {
	case <-ctx.Done():
		fmt.Println("脚本运行完毕")
	case <-task.Done():
		return nil
	}
	return nil
}
func runBinPath(script string, name string, restart bool, devi string) error {
	task, taskCancel := context.WithCancel(context.TODO())
	defer taskCancel()
	d, err := DeviceForDevi(devi)
	if err != nil {
		return err
	}
	defer d.Clean()
	params, err := d.Params()
	if err != nil {
		return err
	}
	p := dict.NewDictWithObj(params)
	osDict := p.GetDict("os")
	fmt.Println(fmt.Sprintf("deviceInfo name:%s, access:%s, os:%s/%s/%s,%s ", d.Name(), p.GetString("access"), p.GetString("platform"), p.GetString("arch"), osDict.GetString("name"), osDict.GetString("version")))

	spawnCtx, resumeOK := context.WithCancel(context.TODO())
	var pid int
	app, err := GetProcess(d, name)
	if err != nil {
		return err
	}
	if restart == true {
		d.Kill(app.PID())
		pid = 0
	} else {
		pid = app.PID()
	}
	if pid == 0 {
		pid, err = d.Spawn(app.Params()["path"].(string), frida.NewSpawnOptions())
		if err != nil {
			return err
		}
		go func() {
			select {
			case <-spawnCtx.Done():
				d.Resume(pid)
			case <-task.Done():
				return
			}
		}()
	}

	session, err := d.Attach(pid, frida.NewSessionOptions(frida.RealmNative, 5000))
	if err != nil {
		return err
	}
	defer session.Detach()
	defer session.Clean()

	jsByte, err := os.ReadFile(script)
	if err != nil {
		return err
	}
	var sc *frida.Script
	sc, err = session.CreateScript(string(jsByte))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.TODO())
	sc.On("destroyed", func() {
		cancel()
		fmt.Println("destroyed")
	})
	defer sc.Clean()
	sc.On("message", func(msg string, data []byte) {
		jsd := dict.NewDict()
		err := jsd.UnmarshalJSON([]byte(msg))
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		tp := jsd.GetString("type")
		if tp == "log" {
			log.Println(jsd.GetString("payload"))
		} else if tp == "error" {
			log.Println(jsd.GetString("stack"))
			log.Println(jsd.GetString("fileName"))
		} else if tp == "send" {
			fmt.Println(jsd.JsonString())
		} else {
			log.Println(jsd.JsonString())
		}
	})
	err = sc.Load()
	if err != nil {
		return err
	}
	resumeOK()
	defer sc.Unload()
	select {
	case <-ctx.Done():
		fmt.Println("脚本运行完毕")
	case <-task.Done():
		return nil
	}
	return nil
}

func compile(script string, name string, devi string) error {
	d, err := DeviceForDevi(devi)
	if err != nil {
		return err
	}
	defer d.Clean()
	params, err := d.Params()
	if err != nil {
		return err
	}
	p := dict.NewDictWithObj(params)
	osDict := p.GetDict("os")
	fmt.Println(fmt.Sprintf("deviceInfo name:%s, access:%s, os:%s/%s/%s,%s ", d.Name(), p.GetString("access"), p.GetString("platform"), p.GetString("arch"), osDict.GetString("name"), osDict.GetString("version")))

	var pid int
	app, err := GetApplication(d, name)
	if err != nil {
		return err
	}
	pid = app.PID()
	if pid == 0 {
		pid, err = d.Spawn(app.Identifier(), frida.NewSpawnOptions())
		if err != nil {
			return err
		}
		d.Resume(pid)
	}
	session, err := d.Attach(pid, frida.NewSessionOptions(frida.RealmNative, 5000))
	if err != nil {
		return err
	}
	defer session.Detach()
	jsBytes, err := os.ReadFile(script)
	if err != nil {
		return err
	}
	compileBytes, err := session.CompileScript(string(jsBytes), frida.NewScriptOptions(""))
	if err != nil {
		return err
	}
	pName := strings.ReplaceAll(script, path.Ext(script), "")
	outName := fmt.Sprintf("%s.compile%s", pName, path.Ext(script))
	err = os.WriteFile(outName, compileBytes, os.ModePerm)
	if err != nil {
		return err
	}
	fmt.Println("编译完成:", outName)
	return nil
}

func http(script string, name string, devi string, addr string) error {
	task, taskCancel := context.WithCancel(context.TODO())
	defer taskCancel()
	d, err := DeviceForDevi(devi)
	if err != nil {
		return err
	}
	defer d.Clean()
	params, err := d.Params()
	if err != nil {
		return err
	}
	p := dict.NewDictWithObj(params)
	osDict := p.GetDict("os")
	fmt.Println(fmt.Sprintf("deviceInfo name:%s, access:%s, os:%s/%s/%s,%s ", d.Name(), p.GetString("access"), p.GetString("platform"), p.GetString("arch"), osDict.GetString("name"), osDict.GetString("version")))

	var pid int
	app, err := GetApplication(d, name)
	if err != nil {
		return err
	}
	pid = app.PID()
	if pid == 0 {
		pid, err = d.Spawn(app.Identifier(), frida.NewSpawnOptions())
		if err != nil {
			return err
		}
		d.Resume(pid)
	}
	session, err := d.Attach(pid, frida.NewSessionOptions(frida.RealmNative, 5000))
	if err != nil {
		return err
	}
	defer session.Detach()
	defer session.Clean()

	jsByte, err := os.ReadFile(script)
	if err != nil {
		return err
	}
	var sc *frida.Script
	sc, err = session.CreateScript(string(jsByte))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.TODO())
	sc.On("destroyed", func() {
		cancel()
		fmt.Println("destroyed")
	})
	defer sc.Clean()
	sc.On("message", func(msg string, data []byte) {
		jsd := dict.NewDict()
		err := jsd.UnmarshalJSON([]byte(msg))
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		tp := jsd.GetString("type")
		if tp == "log" {
			log.Println(jsd.GetString("payload"))
		} else if tp == "error" {
			log.Println(jsd.GetString("stack"))
			log.Println(jsd.GetString("fileName"))
		} else if tp == "send" {
			fmt.Println(jsd.JsonString())
		} else {
			log.Println(jsd.JsonString())
		}
	})
	err = sc.Load()
	if err != nil {
		return err
	}
	defer sc.Unload()
	webApp := gin.New()
	webApp.POST("/call", func(c *gin.Context) {
		if sc.IsDestroyed() == true {
			c.JSON(200, ResRpcCall{
				ResRpcCall: true,
				Error:      Ptr("application IsDestroyed"),
				Data:       nil,
			})
			return
		}
		var req ReqRpcCall
		err := c.ShouldBindJSON(&req)
		if err != nil {
			c.JSON(200, ResRpcCall{
				ResRpcCall: true,
				Error:      Ptr(err.Error()),
				Data:       nil,
			})
			return
		}
		timeout := time.Second * 30
		if req.Timeout != "" {
			timeout, err = time.ParseDuration(req.Timeout)
			if err != nil {
				c.JSON(200, ResRpcCall{
					ResRpcCall: true,
					Error:      Ptr(err.Error()),
					Data:       nil,
				})
				return
			}
		}
		ctx, _ := context.WithTimeout(context.TODO(), timeout)
		jsr := sc.ExportsCallWithContext(ctx, req.Func, req.Args...)
		c.JSON(200, ResRpcCall{
			ResRpcCall: true,
			Error:      nil,
			Data:       jsr,
		})
		return
	})
	go func() {
		fmt.Println("rpc run address:", addr)
		err := webApp.Run(addr)
		if err != nil {
			fmt.Println(err.Error())
			taskCancel()
			return
		}
	}()

	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, os.Kill)
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		fmt.Println("脚本运行完毕")
	case <-task.Done():
		return nil
	}
	return nil
}
