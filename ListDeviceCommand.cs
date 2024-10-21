using System.ComponentModel.DataAnnotations;
using System.Reflection;
using CommandLine;
using Microsoft.Extensions.Logging;
using PInvoke.FridaCore;

namespace fd;

[Verb("lsdev", HelpText = "Lists all Devices")]
public class ListDeviceCommand : ICommand
{
    [Option('c',"connect", Required = false, HelpText = "usb=usb,or address,connect remote device")]
    public string? ConnectDevice { get; set; }
    
    [Option("token", Required = false, HelpText = "connect remote device set token")]
    public string? ConnectDeviceToken { get; set; }
    
    public int Execute()
    {
        Func.CheckAndConnectDevice(ConnectDevice, ConnectDeviceToken);
        var devices = Global.DeviceManager.EnumerateDevices();
        foreach (var device in devices)
        {
            var deviceType = device.GetDType();
            var deviceId = device.GetId();
            if (deviceType == FridaDeviceType.FridaDeviceTypeLocal||deviceType==FridaDeviceType.FridaDeviceTypeUsb || deviceId.Contains("@"))
            {
                var systemParameters = device.QuerySystemParameters();
                var osName = "";
                var osVersion = "";
                if (systemParameters["os"] is List<object> os)
                {
                    var c = os[0] as Dictionary<string, object>;
                    osVersion = c["version"].ToString();
                    var d = os[2] as Dictionary<string, object>;
                    osName=d["name"].ToString();
                }
                Console.WriteLine(
                    $"id:{device.GetId()},name:{device.GetName()},type:{device.GetDType().ToString()},access:{systemParameters["access"]},os:{systemParameters["platform"]}/{systemParameters["arch"]}/{osName},{osVersion}");
            }
            else
            {
                Console.WriteLine(
                    $"id:{device.GetId()},name:{device.GetName()},type:{device.GetDType().ToString()}");
            }

            Frida.FridaUnref(device);
        }
        
        return 0;
    }
}