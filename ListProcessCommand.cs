using CommandLine;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using PInvoke.FridaCore;

namespace fd;

[Verb("lsps", HelpText = "List all process")]
public class ListProcessCommand:ICommand
{
    [Option('c',"connect", Required = false, HelpText = "usb=usb,or address,connect remote device")]
    public string? ConnectDevice { get; set; }
    
    [Option("token", Required = false, HelpText = "connect remote device set token")]
    public string? ConnectDeviceToken { get; set; }
    
    [Option("scope", Required = false, HelpText = "0|1|2 0=FRIDA_SCOPE_MINIMAL,1=FRIDA_SCOPE_METADATA,2=FRIDA_SCOPE_FULL")]
    public FridaScope? Scope { get; set; }
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
        var options = new FridaProcessQueryOptions
        {
            Scope = FridaScope.FRIDA_SCOPE_METADATA
        };
        if (Scope != null)
        {
            options.Scope = Scope.Value;
        }
        var apps = selectDevice.EnumerateProcessList(options);
        foreach (var app in apps)
        {
            var objectParams = app.GetParameters();
            var path = "";
            if (objectParams.ContainsKey("path"))
            {
                path = objectParams["path"].ToString();
            }

            var started = "";
            if (objectParams.ContainsKey("started"))
            {
                started = DateTime.Parse(objectParams["started"].ToString()!).ToString("yyyy-MM-dd HH:mm:ss");
            }

            Console.WriteLine($"name:{app.GetName()},pid:{app.GetPid()},started:{started},path:{path}");
            FridaNative.g_object_unref(app.Handle);
        }
        return 0;
    }
}