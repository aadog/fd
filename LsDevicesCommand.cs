using aadog.PInvoke.Base;
using aadog.PInvoke.FridaCore;
using aadog.PInvoke.LibFridaCore.Enums;
using CommandLine;
using Newtonsoft.Json;
using System.Drawing;

namespace fd;

[Verb("ls-devices", HelpText = "Lists all Devices")]
public class LsDevicesCommand : ICommand
{
    [Option('h', "help", Required = false, HelpText = "show this help message and exit")]
    public bool OptionHelp { get; set; }
    public string TypeToString(FridaDeviceType d)
    {
        return d switch
        {
            FridaDeviceType.FRIDA_DEVICE_TYPE_LOCAL => "local",
            FridaDeviceType.FRIDA_DEVICE_TYPE_USB => "usb",
            FridaDeviceType.FRIDA_DEVICE_TYPE_REMOTE => "remote",
            _ => throw new ArgumentOutOfRangeException(nameof(d), d, null),
        };
    }

    record DeviceView
    {
        public string Id;
        public string Type;
        public string Name;
        public string Os;
    }

    public int Execute()
    {
        var listDevices = Global.DeviceManager!.enumerateDevice();
        var rowArr = new List<DeviceView>
        {
            new DeviceView() { Id = "Id", Type = "Type", Name = "Name", Os = "Os" },
            new DeviceView() { Id = "-", Type = "-", Name = "-", Os = "-" }
        };

        foreach (var fridaDevice in listDevices)
        {
            var deviceId = fridaDevice.getId();
            if (deviceId != "")
            {
                var deviceName = fridaDevice.getName();
                var deviceType = TypeToString(fridaDevice.getType());
                var deviceOs = "";
                if (fridaDevice.getType() != FridaDeviceType.FRIDA_DEVICE_TYPE_REMOTE && deviceName != "")
                {
                    var systemParameters = fridaDevice.querySystemParameters();
                    var os = systemParameters["os"]! as Dictionary<string, object>;
                    deviceOs=$"{os["name"]} {os["version"]}";
                }
                else
                {
                    deviceOs="";
                }
                rowArr.Add(new DeviceView(){Id = deviceId,Name = deviceName,Type = deviceType,Os = deviceOs});
            }
            fridaDevice.unRef();
        }

        var headArr = rowArr[..2];
        var bodyArr = rowArr[2..];
        bodyArr.Sort((a,b)=>a.Type.Length.CompareTo(b.Type.Length));
        var col_0_max = rowArr.Max(e => e.Id.Length);
        var col_1_max = rowArr.Max(e => e.Type.Length);
        var col_2_max = rowArr.Max(e => e.Name.Length);
        var col_3_max = rowArr.Max(e => e.Os.Length);
        for (int i = 0; i < headArr.Count; i++)
        {
            var i1 = i;
            char AutoPad() => i1 == 1 ? '-' : ' ';
            Console.WriteLine("{0}  {1}  {2}  {3}",
                headArr[i].Id.PadRight(col_0_max, AutoPad()),
                headArr[i].Type.PadRight(col_1_max, AutoPad()),
                headArr[i].Name.PadRight(col_2_max, AutoPad()),
                headArr[i].Os.PadRight(col_3_max, AutoPad())
                );
        }
        for (int i = 0; i < bodyArr.Count; i++)
        {
            char AutoPad() =>' ';
            Console.WriteLine("{0}  {1}  {2}  {3}",
                bodyArr[i].Id.PadRight(col_0_max, AutoPad()),
                bodyArr[i].Type.PadRight(col_1_max, AutoPad()),
                bodyArr[i].Name.PadRight(col_2_max, AutoPad()),
                bodyArr[i].Os.PadRight(col_3_max, AutoPad())
            );
        }
        return 0;
    }
}