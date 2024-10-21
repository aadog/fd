using CommandLine;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using PInvoke.FridaCore;

namespace fd;

[Verb("lsapp", HelpText = "Lists all Application")]
public class ListApplicationCommand:ICommand
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
        var options = new FridaApplicationQueryOptions { };
        if (Scope != null)
        {
            options.Scope = Scope.Value;
        }
        var apps = selectDevice.EnumerateApplicationList(options);
        foreach (var app in apps)
        {
            if (app.GetPid() == 0)
            {
                Console.WriteLine($"identifier:{app.GetIdentifier()},name:{app.GetName()},parameters:{JsonConvert.SerializeObject(app.GetParameters())}");
            }
            else
            {
                Console.WriteLine($"identifier:{app.GetIdentifier()},name:{app.GetName()},pid:{app.GetPid()},parameters:{JsonConvert.SerializeObject(app.GetParameters())}");
            }
            Frida.GObjectUnRef(app.Handle);
        }
        Frida.FridaUnref(selectDevice);
        return 0;
    }
}