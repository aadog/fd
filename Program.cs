using System.ComponentModel.DataAnnotations;
using System.Threading.Channels;
using CommandLine;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Primitives;
using Nito.AsyncEx;
using PInvoke.FridaCore;

namespace fd;

class Program
{
    static int Main(string[] args)
    {
        Frida.FridaInit();
        Parser.Default
            .ParseArguments<ListDeviceCommand, ListApplicationCommand, ListProcessCommand, CreateProjectCommand, CompileCommand, RunCommand,HttpRpcCommand>(args)
            .MapResult(
                (ListDeviceCommand command) => command.Execute(),
                (ListApplicationCommand command) => command.Execute(),
                (ListProcessCommand command) => command.Execute(),
                (CreateProjectCommand command) => command.Execute(),
                (CompileCommand command) => command.Execute(),
                (RunCommand command) => command.Execute(),
                (HttpRpcCommand command) => command.Execute(),
                errs =>1
            );
        Global.DeviceManager.Close();
        Frida.FridaUnref(Global.DeviceManager);
        Frida.FridaDeInit();
        return 0;
    }
}