using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using CommandLine;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders.Embedded;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PInvoke.FridaCore;

namespace fd;

public class RpcCallRequest
{
    public required string MethodName { get; set; }
    public required List<object> Args { get; set; }
}

public class RpcCallResponse
{
    public required string CallId { get; set; }
    public required string Status { get; set; }
    public required object Result { get; set; }
}

[Verb("http",HelpText = "http rpc gateway")]
public class HttpRpcCommand:ICommand
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
    public string SwaggerYamlSource { get; set; }

    public HttpRpcCommand()
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var file = assembly.GetManifestResourceStream("fd.swagger.yaml")!;
        using var reader = new StreamReader(file);
        SwaggerYamlSource = reader.ReadToEnd();
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
                    Global.Logger.LogInformation(payload);
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
        var script =session.CreateScript(File.ReadAllText(ScriptPath!), scriptOptions);
        script.InstallRpcHandle();
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
        Task.Run(async () =>
        {
            await this.RunApplication(script,ctx.Token);
        },ctx.Token);
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
            script.InstallRpcHandle();
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
            Task.Run(async () =>
            {
                await this.RunApplication(script,ctx.Token);
            },ctx.Token);
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
            var process = device.FindProcessByName(Process,new FridaProcessMatchOptions());
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
            Task.Run(async () =>
            {
                await this.RunApplication(script,ctx.Token);
            },ctx.Token);
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
            script.InstallRpcHandle();
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
            Task.Run(async () =>
            {
                await this.RunApplication(script,ctx.Token);
            },ctx.Token);
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
            script.InstallRpcHandle();
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
            Task.Run(async () =>
            {
                await this.RunApplication(script,ctx.Token);
            },ctx.Token);
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
            script.InstallRpcHandle();
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
            Task.Run(async () =>
            {
                await this.RunApplication(script,ctx.Token);
            },ctx.Token);
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
            var script =session.CreateScript(File.ReadAllText(ScriptPath!), scriptOptions);
            script.InstallRpcHandle();
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
            Task.Run(async () =>
            {
                await this.RunApplication(script,ctx.Token);
            },ctx.Token);
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

    public async Task RunApplication(FridaScript script,CancellationToken cancellationToken)
    {
        var builder=WebApplication.CreateBuilder(new string[]{});
        var app=builder.Build();
        app.UseSwaggerUI(options =>
        {
            options.SwaggerEndpoint("/swagger.yaml", "HttpRpc API");
        });
        app.MapGet("/swagger.yaml", new RequestDelegate(async (context) =>
        {
            await context.Response.WriteAsync(SwaggerYamlSource);
        }));
        
        app.MapGet("/", new RequestDelegate(async (ctx) =>
        {
            ctx.Response.Redirect("/swagger/");

            await ctx.Response.CompleteAsync();
        }));
        app.MapPost("/rpc", new RequestDelegate(async (ctx) =>
        {
            var request = ctx.Request;
            var response=ctx.Response;
            using var reader = new StreamReader(request.Body);
            var body = await reader.ReadToEndAsync(cancellationToken);
            var jsonObject = JsonConvert.DeserializeObject<RpcCallRequest>(body);
            var callId = Guid.NewGuid().ToString();
            var jsonResult=script.RpcCall(callId,jsonObject!.MethodName,jsonObject.Args,cancellationToken);
            
            response.ContentType = "application/json";
            await response.WriteAsync(JsonConvert.SerializeObject(new RpcCallResponse
            {
                CallId = jsonResult[1].ToString(),
                Status = jsonResult[2].ToString(),
                Result = jsonResult[3]
            }),cancellationToken);
            await ctx.Response.CompleteAsync();
        }));
        await app.RunAsync(cancellationToken);
        Console.WriteLine("http rpc shutodwn");
    }

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
}