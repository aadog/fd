using aadog.PInvoke.FridaCore;
using aadog.PInvoke.LibFridaCore;
using CommandLine;
using FridaDeviceManager = aadog.PInvoke.FridaCore.FridaDeviceManager;


namespace fd;

unsafe class Program
{
    static int Main(string[] args)
    {

        LibFridaCoreFunctions.IsWindows = true;
        Frida.Init();
        Global.DeviceManager = FridaDeviceManager.create();
        
        try
        {
            Parser.Default
                .ParseArguments<LsDevicesCommand, PsCommand, CreateProjectCommand,
                    CompileCommand, RunCommand, HttpRpcCommand>(args)
                .MapResult(
                    (LsDevicesCommand command) => command.Execute(),
                    (PsCommand command) => command.Execute(),
                    (CreateProjectCommand command) => command.Execute(),
                    (CompileCommand command) => command.Execute(),
                    (RunCommand command) => command.Execute(),
                    (HttpRpcCommand command) => command.Execute(),
                    errs => 1
                );
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
        //frida bug
        // Global.DeviceManager.Close();
        Global.DeviceManager.unRef();
        return 0;
    }
}