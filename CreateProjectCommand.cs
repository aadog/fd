using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text;
using System.Text.Unicode;
using CommandLine;
using Microsoft.Extensions.Logging;

namespace fd;

[Verb("create", HelpText = "create frida-agent project")]
public class CreateProjectCommand:ICommand
{
    [Value(0,MetaName = "ProjectName",Required =true,HelpText = "project name")]
    public string? ProjectName { get; set; }

    public void ExtractAllFile(string outDirPath)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var names=assembly.GetManifestResourceNames();
        foreach (var name in names)
        {
            if (!name.StartsWith("fd.frida.agent.example"))
            {
                continue;
            }
            var streamData = assembly.GetManifestResourceStream(name);
            if (streamData == null)
            {
                throw new FileNotFoundException($"Resource {name} not found in assembly {assembly.FullName}");
            }

            var resourcePathArr = name.Split(".");
            var dirPathArr = resourcePathArr[1..^2];
            var dirPath = Path.Combine(outDirPath, Path.Combine(dirPathArr));
            var fileNameArr = resourcePathArr[^2..];
            var fileName = string.Join(".", fileNameArr);
            if (!Directory.Exists(dirPath))
            {
                Directory.CreateDirectory(dirPath);
            }

            if (fileName == "package.json" || fileName == "package-lock.json")
            {
                
                using var inReader = new StreamReader(streamData);
                var content = inReader.ReadToEnd();
                content = content.Replace("frida-agent-example", ProjectName);
                var strPath = Path.Combine(dirPath, fileName);
                using var outStream = new FileStream(strPath,new FileStreamOptions
                {
                    Mode = FileMode.Create,
                    Access = FileAccess.Write
                });
                outStream.Write(Encoding.UTF8.GetBytes(content),0,content.Length);
                outStream.Flush();
            }
            else
            {
                using var inStream=new BufferedStream(streamData);
                var strPath = Path.Combine(dirPath, fileName);
                using var outStream = new FileStream(strPath,new FileStreamOptions
                {
                    Mode = FileMode.Create,
                    Access = FileAccess.Write
                });
                byte[] buffer = new byte[1024];
                int length;
                while ((length=inStream.Read(buffer,0,buffer.Length))>0)
                {
                    outStream.Write(buffer,0,length);
                }
                outStream.Flush();
            }
        }
    }

    public int Execute()
    {
        if (ProjectName==null)
        {
            throw new ArgumentException("Project name is null");
        }
        if (Directory.Exists(ProjectName))
        {
            throw new ArgumentException("Project is exists"); 
        }
        Directory.CreateDirectory(ProjectName);
        ExtractAllFile(ProjectName);
        Global.Logger.LogInformation($"create project {ProjectName} ok!");
        return 0;
    }
}