using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using CommandLine;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PInvoke.FridaCore;

namespace fd;

[Verb("run", HelpText = "Run running script")]
public class RunCommand:ICommand
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
    
    [Option("spawn",Required = false, HelpText = "true/false  spawn mode")]
    public bool? Spawn { get; set; }
    
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
        
        if (ApplicationName != null)
        {
            return RunApplicationName(selectDevice);
        }else if (Pid != null)
        {
            return RunPid(selectDevice);
        }else if (ApplicationIdentifier != null)
        {
            return RunApplicationIdentifier(selectDevice);
        }else if (Process != null)
        {
            return RunProcess(selectDevice);
        }
        else
        {
            throw new Exception("no select run mode");
        }
        return 0;
    }
    

    public void OnMessage(IntPtr script,string message,IntPtr data,IntPtr userData)
    {

        var jsonMessage = JsonConvert.DeserializeObject<JObject>(message);
        var messageType = jsonMessage["type"].ToString();
        switch (messageType)
        {
            case "log":
            {
                var payload = jsonMessage["payload"]!.ToString();
                var level = jsonMessage["level"]!.ToString();
                if (level == "debug")
                {
                    Global.Logger.LogDebug(payload);
                }
                if (level == "info")
                {
                    Console.WriteLine(payload);
                }
                break;
            }
            case "error":
            {
                var stack = jsonMessage["stack"].ToString();
                var fileName = jsonMessage["fileName"].ToString();
                Global.Logger.LogInformation(stack);
                Global.Logger.LogInformation(fileName);
                break;
            }
            case "send":
            {
                if (jsonMessage["payload"].Type==JTokenType.String)
                {
                    var payload = jsonMessage["payload"].ToString();
                    //cmd parse
                    if (payload.StartsWith("$|"))
                    {
                        var cmdArr = payload.Split("|");
                        var cmd=cmdArr[1];
                        if (cmd == "down")
                        {
                            var id = cmdArr[2];
                            var filePath = cmdArr[3];
                            var fileData=FridaTools.GBytesToBytes(data);
                            Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
                            File.Delete(filePath);
                            File.WriteAllBytes(filePath,fileData);
                            var fridaScript = new FridaScript(script);
                            fridaScript.Post(JsonConvert.SerializeObject(JObject.FromObject(new
                            {
                                type = id,
                            })),IntPtr.Zero);
                            return;
                        }
                        Global.Logger.LogInformation($"cmd:{cmd}");
                    }
                    else
                    {
                        Global.Logger.LogInformation(jsonMessage.ToString());
                    }
                }else if (jsonMessage["payload"].Type==JTokenType.Array)
                {
                    
                }
                else
                {
                    Global.Logger.LogInformation(jsonMessage.ToString());
                }
                break;
            }
            default:
            {
                Console.WriteLine(jsonMessage.ToString());
                break;
            }
        }
        // Console.WriteLine(jsonMessage["type"]);
    }

    public int RunPid(FridaDevice device)
    {
        var pid = Pid.Value;
        if (pid == 0)
        {
            throw new ApplicationException($"No process {pid} found");
        }
        var sessionOptions = new FridaSessionOptions();
  
        sessionOptions.PersistTimeout = 5000;
        var session=device.AttachProcess(pid,sessionOptions);
        var scriptOptions=new FridaScriptOptions();
        //scriptOptions.Name = "test1";
        var script =session.CreateScript(File.ReadAllText(ScriptPath!), scriptOptions);
        script.OnMessage(OnMessage);
        script.Load();
        var mainLoop = Frida.FridaMainLoopNew(false);
        if (mainLoop.IsRunning())
        {
            mainLoop.Run();
        }
        CancellationTokenSource ctx=new CancellationTokenSource();
        session.OnDetached((a,b,c,d) =>
        {
            ctx.Cancel();
        });
        ctx.Token.WaitHandle.WaitOne();
        if (script.IsDestroyed() == false)
        {
            script.UnLoad();
        }
        mainLoop.MainLoopUnRef();
        Frida.FridaUnref(script);
        session.Detach();
        Frida.FridaUnref(session);
        Frida.FridaUnref(device);
        return 0;
    }

    public int RunProcess(FridaDevice device)
    {
      if (Spawn==true)
        {
            var process = device.FindProcessByName(Process,new FridaProcessMatchOptions{Scope = FridaScope.FRIDA_SCOPE_METADATA});
            if (process == null)
            {
                throw new ApplicationException($"No process {Process} found");
            }

            var processDict = process.GetParameters();
            string processPath = "";
            string? processDir=null;
            if (processDict.ContainsKey("applications"))
            {
                var applications = processDict["applications"] as List<object>;
                processPath = applications[0] as string;
            }
            else
            {
                processPath = processDict["path"] as string;
                processDir=Path.GetDirectoryName(processPath)!;
            }
            
            var pid = process.GetPid();
            Frida.GObjectUnRef(process.Handle);
            if (pid != 0)
            {
                device.KillProcess(pid);
                Thread.Sleep(1000);
            }

            var spawnOptions = new FridaSpawnOptions();
            if (processDir != null)
            {
                spawnOptions.Cwd = processDir;
            }
            var spawnPid=device.SpawnProcess(processPath, spawnOptions);
            if (spawnPid == 0)
            {
                throw new ApplicationException("Spawn process failed");
            }
            
            var sessionOptions = new FridaSessionOptions();
            sessionOptions.PersistTimeout = 5000;
            var session=device.AttachProcess(spawnPid,sessionOptions);
            var scriptOptions=new FridaScriptOptions();
            var script =session.CreateScript(File.ReadAllText(ScriptPath!), scriptOptions);
            script.OnMessage(OnMessage);
            script.Load();
            device.ResumeProcess(spawnPid);
            var mainLoop = Frida.FridaMainLoopNew(false);
            if (mainLoop.IsRunning())
            {
                mainLoop.Run();
            }
            CancellationTokenSource ctx=new CancellationTokenSource();
            session.OnDetached((a,b,c,d) =>
            {
                ctx.Cancel();
            });
            ctx.Token.WaitHandle.WaitOne();
            if (script.IsDestroyed() == false)
            {
                script.UnLoad();
            }
            mainLoop.MainLoopUnRef();
            Frida.FridaUnref(script);
            session.Detach();
            Frida.FridaUnref(session);
            Frida.FridaUnref(device);
        }
        else
        {
            var options = new FridaProcessMatchOptions();
            var process = device.FindProcessByName(Process,options);
            if (process == null)
            {
                throw new ApplicationException($"No process {Process} found");
            }
            var pid = process.GetPid();
            Frida.GObjectUnRef(process.Handle);
            if (pid == 0)
            {
                throw new ApplicationException($"No process {Process} found");
            }
            var sessionOptions = new FridaSessionOptions();
            sessionOptions.PersistTimeout = 5000;
            var session=device.AttachProcess(pid,sessionOptions);
            var scriptOptions=new FridaScriptOptions();
            var script =session.CreateScript(File.ReadAllText(ScriptPath!), scriptOptions);
            script.OnMessage(OnMessage);
            script.InstallRpcHandle();
            script.Load();
            var mainLoop = Frida.FridaMainLoopNew(false);
            if (mainLoop.IsRunning())
            {
                mainLoop.Run();
            }
            
            CancellationTokenSource ctx=new CancellationTokenSource();
            session.OnDetached((a,b,c,d) =>
            {
                ctx.Cancel();
            });
            ctx.Token.WaitHandle.WaitOne();
            if (script.IsDestroyed() == false)
            {
                script.UnLoad();
            }
            mainLoop.MainLoopUnRef();
            Frida.FridaUnref(script);
            session.Detach();
            Frida.FridaUnref(session);
            Frida.FridaUnref(device);
        }

        return 0;
    }
    public int RunApplicationName(FridaDevice device)
    {
        if (Spawn==true)
        {
            var application = Func.FindApplication(device, ApplicationName);
            if (application == null)
            {
                throw new ApplicationException($"No process {ApplicationName} found");
            }

            var applicationIdentifier = application.GetIdentifier();
            var pid = application.GetPid();
            Frida.GObjectUnRef(application.Handle);
            if (pid != 0)
            {
                device.KillProcess(pid);
                Thread.Sleep(1000);
            }

            var spawnOptions = new FridaSpawnOptions();
            var spawnPid=device.SpawnProcess(applicationIdentifier, spawnOptions);
            if (spawnPid == 0)
            {
                throw new ApplicationException("Spawn process failed");
            }

            var sessionOptions = new FridaSessionOptions();
            sessionOptions.PersistTimeout = 5000;
            var session=device.AttachProcess(spawnPid,sessionOptions);
            var scriptOptions=new FridaScriptOptions();
            var script =session.CreateScript(File.ReadAllText(ScriptPath!), scriptOptions);
            script.OnMessage(OnMessage);
            script.Load();
            device.ResumeProcess(spawnPid);
            var mainLoop = Frida.FridaMainLoopNew(false);
            if (mainLoop.IsRunning())
            {
                mainLoop.Run();
            }
            CancellationTokenSource ctx=new CancellationTokenSource();
            session.OnDetached((a,b,c,d) =>
            {
                ctx.Cancel();
            });
            ctx.Token.WaitHandle.WaitOne();
            if (script.IsDestroyed() == false)
            {
                script.UnLoad();
            }
            mainLoop.MainLoopUnRef();
            Frida.FridaUnref(script);
            session.Detach();
            Frida.FridaUnref(session);
            Frida.FridaUnref(device);
        }
        else
        {
            var application = Func.FindApplication(device, ApplicationName);
            if (application == null)
            {
                throw new ApplicationException($"No process {ApplicationName} found");
            }
            var pid = application.GetPid();
            Frida.GObjectUnRef(application.Handle);
            if (pid == 0)
            {
                throw new ApplicationException($"No process {ApplicationName} found");
            }
            var sessionOptions = new FridaSessionOptions();
            sessionOptions.PersistTimeout = 5000;
            var session=device.AttachProcess(pid,sessionOptions);
            var scriptOptions=new FridaScriptOptions();
            var script =session.CreateScript(File.ReadAllText(ScriptPath!), scriptOptions);
            script.OnMessage(OnMessage);
            script.Load();
            var mainLoop = Frida.FridaMainLoopNew(false);
            if (mainLoop.IsRunning())
            {
                mainLoop.Run();
            }
            CancellationTokenSource ctx=new CancellationTokenSource();
            session.OnDetached((a,b,c,d) =>
            {
                ctx.Cancel();
            });
            ctx.Token.WaitHandle.WaitOne();
            if (script.IsDestroyed() == false)
            {
                script.UnLoad();
            }
            mainLoop.MainLoopUnRef();
            Frida.FridaUnref(script);
            session.Detach();
            Frida.FridaUnref(session);
            Frida.FridaUnref(device);
        }
        return 0;
    }
    public int RunApplicationIdentifier(FridaDevice device)
    {
        if (Spawn==true)
        {
            var application = Func.FindApplicationIdentifier(device, ApplicationIdentifier);
            if (application == null)
            {
                throw new ApplicationException($"No process {ApplicationIdentifier} found");
            }
            var pid = application.GetPid();
            Frida.GObjectUnRef(application.Handle);
            if (pid != 0)
            {
                device.KillProcess(pid);
                Thread.Sleep(1000);
            }

            var spawnOptions = new FridaSpawnOptions();
            var spawnPid=device.SpawnProcess(ApplicationIdentifier, spawnOptions);
            if (spawnPid == 0)
            {
                throw new ApplicationException("Spawn process failed");
            }

            var sessionOptions = new FridaSessionOptions();
            sessionOptions.PersistTimeout = 5000;
            var session=device.AttachProcess(spawnPid,sessionOptions);
            var scriptOptions=new FridaScriptOptions();
           
            var script =session.CreateScript(File.ReadAllText(ScriptPath!), scriptOptions);
            script.OnMessage(OnMessage);
            script.Load();
            device.ResumeProcess(spawnPid);
            var mainLoop = Frida.FridaMainLoopNew(false);
            if (mainLoop.IsRunning())
            {
                mainLoop.Run();
            }
            CancellationTokenSource ctx=new CancellationTokenSource();
            session.OnDetached((a,b,c,d) =>
            {
                ctx.Cancel();
            });
            ctx.Token.WaitHandle.WaitOne();
            if (script.IsDestroyed() == false)
            {
                script.UnLoad();
            }
            mainLoop.MainLoopUnRef();
            Frida.FridaUnref(script);
            session.Detach();
            Frida.FridaUnref(session);
            Frida.FridaUnref(device);
        }
        else
        {
            var application = Func.FindApplicationIdentifier(device, ApplicationIdentifier);
            if (application == null)
            {
                throw new ApplicationException($"No process {ApplicationIdentifier} found");
            }
            var pid = application.GetPid();
            Frida.GObjectUnRef(application.Handle);
            if (pid == 0)
            {
                throw new ApplicationException($"No process {ApplicationIdentifier} found");
            }
            var sessionOptions = new FridaSessionOptions();
            sessionOptions.PersistTimeout = 5000;
            var session=device.AttachProcess(pid,sessionOptions);
            var scriptOptions=new FridaScriptOptions();
            scriptOptions.Runtime = FridaScriptRuntime.FRIDA_SCRIPT_RUNTIME_QJS;
            var script =session.CreateScript(File.ReadAllText(ScriptPath!), scriptOptions);
            script.OnMessage(OnMessage);
            script.Load();
            var mainLoop = Frida.FridaMainLoopNew(false);
            if (mainLoop.IsRunning())
            {
                mainLoop.Run();
            }
            CancellationTokenSource ctx=new CancellationTokenSource();
            session.OnDetached((a,b,c,d) =>
            {
                ctx.Cancel();
            });
            ctx.Token.WaitHandle.WaitOne();
            if (script.IsDestroyed() == false)
            {
                script.UnLoad();
            }
            mainLoop.MainLoopUnRef();
            Frida.FridaUnref(script);
            session.Detach();
            Frida.FridaUnref(session);
            Frida.FridaUnref(device);
        }
        return 0;
    }
}