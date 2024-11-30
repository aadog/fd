using aadog.PInvoke.FridaCore;
using aadog.PInvoke.LibFridaCore;
using aadog.PInvoke.LibFridaCore.Enums;
using CommandLine;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using FridaRemoteDeviceOptions = aadog.PInvoke.FridaCore.FridaRemoteDeviceOptions;

namespace fd;

[Verb("ps", HelpText = "frida-ps [options]")]
public class PsCommand:ICommand
{
    [Option('U',"usb", Required = false, HelpText = "connect to USB device")]
    public bool OptionUsb { get; set; }
    [Option('D', "device", Required = false, HelpText = "connect to device with the given OptionID")]
    public string? OptionID { get; set; }
    [Option('a',"applications", Required = false, HelpText = "list only applications")]
    public bool OptionApplication { get; set; }
    [Option('i', "installed", Required = false, HelpText = "include all installed applications")]
    public bool OptionInstalled { get; set; }
    [Option('j', "json", Required = false, HelpText = "output results as JSON")]
    public bool OptionJson { get; set; }
    [Option('H', "host", Required = false, HelpText = "connect to remote frida-server on HOST")]
    public string? OptionHost { get; set; }
    [Option("token", Required = false, HelpText = "authenticate with HOST using TOKEN")]
    public string? OptionToken { get; set; }
    //
    // [Option("token", Required = false, HelpText = "connect remote device set token")]
    // public string? ConnectDeviceToken { get; set; }

    // [Option("scope", Required = false, HelpText = "0|1|2 0=FRIDA_SCOPE_MINIMAL,1=FRIDA_SCOPE_METADATA,2=FRIDA_SCOPE_FULL")]
    // public FridaScope? Scope { get; set; }
    public int Execute()
    {
        aadog.PInvoke.FridaCore.FridaDevice? device = null;
        if (OptionUsb)
        {
            var devices = Global.DeviceManager!.enumerateDevice();
            foreach (var fridaDevice in devices)
            {
                if (fridaDevice.getType() == FridaDeviceType.FRIDA_DEVICE_TYPE_USB && fridaDevice.getId() != "")
                {
                    device = fridaDevice;
                }
                else
                {
                    fridaDevice.Dispose();
                }
            }
            if (device == null)
            {
                throw new FridaCoreException($"Device 'Usb' not found");
            }
        }
        else if (OptionID != null)
        {
            device = Global.DeviceManager!.FindDeviceById(OptionID, 1000);
            if (device == null)
            {
                throw new FridaCoreException($"Device '{OptionID}' not found");
            }
        }
        else if (OptionHost != null)
        {
            using var options=FridaRemoteDeviceOptions.create();
            if (OptionToken!=null)
            {
                options.SetToken(OptionToken);
            }

            device = Global.DeviceManager!.addRemoteDevice(OptionHost,options);
        }else
        {
            device = Global.DeviceManager!.FindDeviceByType(FridaDeviceType.FRIDA_DEVICE_TYPE_LOCAL, 1000);
        }

        using var selDevice = device;
        

        if (OptionInstalled&&OptionApplication==false)
        {
            throw new FridaCoreException("-i cannot be used without -a");
        }

        if (OptionApplication)
        {
            return RunApplications(selDevice!);
        }


        return Process(selDevice!);
    }

    record ApplicationView
    {
        public string? PID;
        public string Name;
        public string Identifier;
    }
    public int RunApplications(aadog.PInvoke.FridaCore.FridaDevice device)
    {
        var listProcesses = device!.enumerateApplications(null);
        var rowArr = new List<ApplicationView>
        {
            new () { PID = "Id",Name = "Name",Identifier = "Identifier"},
            new () { PID = "-", Name = "-",Identifier = "-"}
        };

        foreach (var fridaProcess in listProcesses)
        {
            rowArr.Add(new ApplicationView() { PID = $"{fridaProcess.getPid()}", Name = fridaProcess.getName() ,Identifier = fridaProcess.getIdentifier()});
            fridaProcess.Dispose();
        }

        var headArr = rowArr[..2];
        var bodyArr = rowArr[2..];
        if (OptionInstalled==false)
        {
            if (bodyArr.Count == 0)
            {
                throw new FridaCoreException("No running applications.");
            }

            bodyArr = bodyArr.FindAll(e => Int64.Parse(e.PID) != 0);
            bodyArr.Sort((a, b) => Int64.Parse(a.PID).CompareTo(Int64.Parse(b.PID)));
        }
        else
        {
            if (bodyArr.Count == 0)
            {
                throw new FridaCoreException("No installed applications.");
            }
            bodyArr.Sort((a, b) => Int64.Parse(b.PID).CompareTo(Int64.Parse(a.PID)));
        }
        if (OptionJson)
        {
            foreach (var applicationView in bodyArr)
            {
                if (applicationView.PID == "0")
                {
                    applicationView.PID = null;
                }
            }
            Console.WriteLine(JsonConvert.SerializeObject(bodyArr, Formatting.Indented));
            return 0;
        }

        var col_0_max = rowArr.Max(e => e.PID.Length);
        var col_1_max = rowArr.Max(e => e.Name.Length);
        var col_2_max = rowArr.Max(e => e.Identifier.Length);
        for (int i = 0; i < headArr.Count; i++)
        {
            var i1 = i;
            char AutoPad() => i1 == 1 ? '-' : ' ';
            Console.WriteLine("{0}  {1}  {2}",
                headArr[i].PID.PadRight(col_0_max, AutoPad()),
                headArr[i].Name.PadRight(col_1_max, AutoPad()),
            headArr[i].Name.PadRight(col_2_max, AutoPad())
            );
        }
        for (int i = 0; i < bodyArr.Count; i++)
        {
            if (bodyArr[i].PID == "0") bodyArr[i].PID = "-";
            char AutoPad() => ' ';
            Console.WriteLine("{0}  {1}  {2}",
                bodyArr[i].PID.PadRight(col_0_max, AutoPad()),
                bodyArr[i].Name.PadRight(col_1_max, AutoPad()),
                bodyArr[i].Identifier.PadRight(col_2_max, AutoPad())
            );
        }

        return 0;
    }


    record ProcessView
    {
        public string PID;
        public string Name;
    }
    public int Process(aadog.PInvoke.FridaCore.FridaDevice device)
    {
        var listProcesses = device!.enumerateProcesses(null);
        var rowArr = new List<ProcessView>
        {
            new ProcessView() { PID = "Id",Name = "Name"},
            new ProcessView() { PID = "-", Name = "-"}
        };

        foreach (var fridaProcess in listProcesses)
        {
            rowArr.Add(new ProcessView(){PID = $"{fridaProcess.getPid()}",Name = fridaProcess.getName()});
            fridaProcess.Dispose();
        }

        var headArr = rowArr[..2];
        var bodyArr = rowArr[2..];
        bodyArr.Sort((a, b) => a.PID.Length.CompareTo(b.PID.Length));
        if (OptionJson)
        {
            Console.WriteLine(JsonConvert.SerializeObject(bodyArr,Formatting.Indented));
            return 0;
        }

        var col_0_max = rowArr.Max(e => e.PID.Length);
        var col_1_max = rowArr.Max(e => e.Name.Length);
        for (int i = 0; i < headArr.Count; i++)
        {
            var i1 = i;
            char AutoPad() => i1 == 1 ? '-' : ' ';
            Console.WriteLine("{0}  {1}",
                headArr[i].PID.PadRight(col_0_max, AutoPad()),
                headArr[i].Name.PadRight(col_1_max, AutoPad())
            );
        }
        for (int i = 0; i < bodyArr.Count; i++)
        {
            char AutoPad() => ' ';
            Console.WriteLine("{0}  {1}",
                bodyArr[i].PID.PadRight(col_0_max, AutoPad()),
                bodyArr[i].Name.PadRight(col_1_max, AutoPad())
            );
        }

        return 0;
    }
}