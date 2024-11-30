using aadog.PInvoke.FridaCore;
using Microsoft.Extensions.Logging;

namespace fd;
// using PInvoke.FridaCore;
public static class Global
{
    public static FridaDeviceManager? DeviceManager;
    public static ILoggerFactory Factory = LoggerFactory.Create(builder => builder.AddConsole(c=>c.TimestampFormat="[yyyy-MM-dd HH:mm:ss]"));
    public static ILogger Logger = Factory.CreateLogger("");
}