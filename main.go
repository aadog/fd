package main

import (
	"fmt"
	"github.com/alecthomas/kingpin/v2"
)

var (
	lsDeviceCommand  = kingpin.Command("lsdev", "list devices")
	lsAppCommand     = kingpin.Command("lsapp", "list app")
	lsAppDevi        = lsAppCommand.Flag("devi", "device").String()
	lsProcessCommand = kingpin.Command("lsps", "list process")
	lsProcessDevi    = lsProcessCommand.Flag("devi", "device").String()

	createCommand     = kingpin.Command("create", "create project")
	createProjectName = createCommand.Arg("projectName", "project name").Required().String()

	runCommand   = kingpin.Command("run", "run js file")
	runScript    = runCommand.Arg("script", "run script file name").Required().String()
	runDevi      = runCommand.Flag("devi", "devi").String()
	runName      = runCommand.Flag("name", "pid or package or label").String()
	runIsPid     = runCommand.Flag("pid", "is pid").Bool()
	runIsBinPath = runCommand.Flag("bin", "is bin path").Bool()
	runRestart   = runCommand.Flag("restart", "restart app").Bool()

	compileCommand = kingpin.Command("compile", "compile js to byte")
	compileScript  = compileCommand.Arg("script", "compile script file name").Required().String()
	compileName    = compileCommand.Flag("name", "package or label").Required().String()
	compileDevi    = compileCommand.Flag("devi", "devi").String()

	httpCommand = kingpin.Command("http", "export http")
	httpScript  = httpCommand.Arg("script", "compile script file name").Required().String()
	httpName    = httpCommand.Flag("name", "package or label").Required().String()
	httpDevi    = httpCommand.Flag("devi", "devi").String()
	httpAddr    = httpCommand.Flag("addr", "listen addr").Default("0.0.0.0:5566").String()
)

func main() {
	cmd := kingpin.Parse()
	switch cmd {
	case lsDeviceCommand.FullCommand():
		err := listDevices()
		if err != nil {
			panic(err)
		}
	case lsAppCommand.FullCommand():
		err := listApp(*lsAppDevi)
		if err != nil {
			panic(err)
		}
	case lsProcessCommand.FullCommand():
		err := listProcess(*lsProcessDevi)
		if err != nil {
			panic(err)
		}
	case "create":
		err := createProejct(*createProjectName)
		if err != nil {
			panic(err)
		}
	case runCommand.FullCommand():
		err := run(*runScript, *runName, *runIsPid, *runIsBinPath, *runRestart, *runDevi)
		if err != nil {
			panic(err)
		}
	case compileCommand.FullCommand():
		err := compile(*compileScript, *compileName, *compileDevi)
		if err != nil {
			panic(err)
		}
	case httpCommand.FullCommand():
		err := http(*httpScript, *httpName, *httpDevi, *httpAddr)
		if err != nil {
			panic(err)
		}
	default:
		fmt.Println(cmd)
	}

}
