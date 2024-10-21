using CommandLine;
using Microsoft.Extensions.Logging;
using PInvoke.FridaCore;

namespace fd;

[Verb("compile",HelpText = "compile script file")]
public class CompileCommand:ICommand
{
    [Option('c',"connect", Required = false, HelpText = "usb=usb,or address,connect remote device")]
    public string? ConnectDevice { get; set; }
    
    [Option("token", Required = false, HelpText = "connect remote device set token")]
    public string? ConnectDeviceToken { get; set; }
    
    [Option("runtime", Required = false, HelpText = "0|1|2 or FRIDA_SCRIPT_RUNTIME_DEFAULT|FRIDA_SCRIPT_RUNTIME_QJS|FRIDA_SCRIPT_RUNTIME_V8")]
    public FridaScriptRuntime? ScriptRuntime { get; set; }
    
    [Option("name",Required = false, HelpText = "use application name")]
    public string? ApplicationName { get; set; }
    
    [Option("id",Required = false, HelpText = "use application identifier name")]
    public string? ApplicationIdentifier { get; set; }
    
    [Option("ps",Required = false, HelpText = "use process name")]
    public string? Process { get; set; }
    
    [Option("pid",Required = false, HelpText = "use pid")]
    public uint? Pid { get; set; }
    
    [Value(0, Required = true, MetaName = "scriptPath", HelpText = "script path")]
    public string? ScriptPath { get; set; }
    public int Execute()
    {
        Func.CheckAndConnectDevice(ConnectDevice, ConnectDeviceToken);
        var selectDevice = Func.DeviceForDevi(ConnectDevice);
        var selectDeviceParams = selectDevice.QuerySystemParameters();
        var osName = "";
        var osVersion = "";
        if (selectDeviceParams["os"] is List<object> os)
        {
            var c = os[0] as Dictionary<string, object>;
            osVersion = c["version"].ToString();
            var d = os[2] as Dictionary<string, object>;
            osName=d["name"].ToString();
        }
        Global.Logger.LogInformation($"deviceInfo name:{selectDevice.GetName()}, access:{selectDeviceParams["access"]}, os:{selectDeviceParams["platform"]}/{selectDeviceParams["arch"]}/{osName},{osVersion} ");

        if (File.Exists(ScriptPath) == false)
        {
            throw new FileNotFoundException("Script file not found", ScriptPath);
        }

        uint? pid = 0;
        if (ApplicationName != null)
        {
            var app = Func.FindApplication(selectDevice,ApplicationName);
            if (app == null)
            {
                throw new Exception($"find application {ApplicationName} not exists");
            }
            if (app.GetPid() == 0)
            {
                throw new Exception($"find application {ApplicationName} not running");
            }
            pid = app.GetPid();
            Frida.GObjectUnRef(app.Handle);
        }else if (ApplicationIdentifier != null)
        {
            var app = Func.FindApplicationIdentifier(selectDevice,ApplicationIdentifier);
            if (app == null)
            {
                throw new Exception($"find application Identifier {ApplicationIdentifier} not exists");
            }
            if (app.GetPid() == 0)
            {
                throw new Exception($"find application Identifier {ApplicationIdentifier} not running");
            }
            pid = app.GetPid();
            Frida.GObjectUnRef(app.Handle);
        }else if (Process != null)
        {
            var process = selectDevice.FindProcessByName(Process,new FridaProcessMatchOptions());
            if (process == null)
            {
                throw new Exception($"find process {Process} not exists");
            }
            if (process.GetPid() == 0)
            {
                throw new Exception($"find process {Process} not running");
            }
            pid = process.GetPid();
            Frida.GObjectUnRef(process.Handle);
        }else if (Pid != null)
        {
            var p = selectDevice.FindProcessByPid(Pid.Value,new FridaProcessMatchOptions());
            if (p == null)
            {
                throw new Exception($"pid:{Pid} not running");
            }
            pid = Pid;
            Frida.GObjectUnRef(p.Handle);
        }
        else
        {
            pid = (uint?)System.Diagnostics.Process.GetCurrentProcess().Id;
        }

        var session = selectDevice.AttachProcess(pid.Value, new FridaSessionOptions());
        var fileSource = File.ReadAllText(ScriptPath);
        var options = new FridaScriptOptions();
        if (ScriptRuntime != null)
        {
            options.Runtime = ScriptRuntime.Value;
        }
        var s = session.CompileScript(fileSource, options);
        var outPath = Path.ChangeExtension(ScriptPath, "compile.js");
        File.WriteAllBytes(outPath,s);
        Global.Logger.LogInformation($"compile ok:{outPath}");
        session.Detach();
        Frida.FridaUnref(session);
        Frida.FridaUnref(selectDevice);
        return 0;
    }
}