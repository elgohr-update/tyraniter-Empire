using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using Microsoft.CodeAnalysis;
using System.Text.RegularExpressions;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using System.CommandLine;
using System.CommandLine.Invocation;

namespace EmpireCompiler
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            RootCommand rootCommand = new RootCommand();
            Option initial = new Option(aliases: new string[] { "-i", "--initial" });
            initial.Argument = new Argument<bool>();

            Option task = new Option(aliases: new string[] { "-t", "--task" });
            task.Argument = new Argument<string>();

            Option all = new Option(aliases: new string[] { "-a", "--all" });
            all.Argument = new Argument<bool>();

            Option sourcefile = new Option(aliases: new string[] { "-s", "--sourcefile" });
            sourcefile.Argument = new Argument<string>();

            Option version = new Option(aliases: new string[] { "-v", "--version" });
            version.Argument = new Argument<string>();

            //0 console exe 1 windows exe 2 dll
            Option outputkind = new Option(aliases: new string[] { "-o", "--outputkind" });
            outputkind.Argument = new Argument<int>();

            rootCommand.AddOption(initial);
            rootCommand.AddOption(task);
            rootCommand.AddOption(all);
            rootCommand.AddOption(version);
            rootCommand.AddOption(sourcefile);
            rootCommand.AddOption(outputkind);

            rootCommand.Handler = CommandHandler.Create<bool, bool, string, string, string, int>(async (initial, all, version, sourcefile, task, outputkind) =>
            {
                var optionsBuilder = new DbContextOptionsBuilder<CovenantContext>();
                if (initial)
                {
                    using (var context = new CovenantContext(optionsBuilder.Options))
                    {
                        //Console.WriteLine("starting initialize db");
                        await DbInitializer.Initialize(context);
                        //Console.WriteLine("success initialize db");
                        Console.WriteLine("ok");
                    }
                }
                else if (all)
                {
                    using (var context = new CovenantContext(optionsBuilder.Options))
                    {
                        //Console.WriteLine("starting compile all tasks");
                        await CompileAll(context);
                        //Console.WriteLine("success compile all tasks");
                        Console.WriteLine("ok");
                    }
                }
                else if (task != null)
                {
                    using (var context = new CovenantContext(optionsBuilder.Options))
                    {
                        //Console.WriteLine($"starting compile task {task}");
                        if (sourcefile != null)
                        {
                            string code = File.ReadAllText(Common.CovenantTaskCSharpDirectory+Path.DirectorySeparatorChar+sourcefile);
                            await Compile(context, task, code, outputkind);
                        }
                        else
                            await Compile(context, task);
                        //Console.WriteLine($"sucess compile task {task}");
                        Console.WriteLine("ok");
                    }
                }
            });

            // Parse the incoming args and invoke the handler
            return rootCommand.InvokeAsync(args).Result;
        }

        public static async Task CompileAll(CovenantContext context) {
            GruntTask[] tasks = await context.GetGrantTaskAll();
            foreach (GruntTask task in tasks) {
                CreateGruntTasking(task);
            }
            
        }
        public static async Task Compile(CovenantContext context,string moduleName)
        {
            try
            {
                GruntTask commandTask = null;
                try
                {
                    commandTask = await context.GetGruntTaskByName(moduleName);
                }
                catch
                {
                }
                if (commandTask != null)
                {
                    CreateGruntTasking(commandTask);
                }
                else
                {
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.StackTrace + "\n" + e.Message);
            }

        }

        public static async Task Compile(CovenantContext context, string moduleName, string code, int outputKind = 2)
        {
            try
            {
                GruntTask commandTask = null;
                try
                {
                    commandTask = await context.GetGruntTaskByName(moduleName);
                }
                catch
                {
                }
                if (commandTask != null)
                {
                    commandTask.Code = code;
                    commandTask.OutputKind = (OutputKind)outputKind;
                    CreateGruntTasking(commandTask);
                }
                else
                {
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.StackTrace + "\n" + e.Message);
            }

        }

        public static void CreateGruntTasking(GruntTask task)
        {
            List<string> parameters = task.Options.OrderBy(O => O.Id).Select(O => string.IsNullOrEmpty(O.Value) ? O.DefaultValue : O.Value).ToList();
            if (task.Name.Equals("SharpShell", StringComparison.CurrentCultureIgnoreCase))
            {
                string WrapperFunctionFormat =
    @"using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security;
using System.Security.Principal;
using System.Collections.Generic;
using SharpSploit.Credentials;
using SharpSploit.Enumeration;
using SharpSploit.Execution;
using SharpSploit.Generic;
using SharpSploit.Misc;
public static class Task
{{
    public static string Execute()
    {{
        {0}
    }}
}}";
                string csharpcode = string.Join(" ", parameters);
                task.Code = string.Format(WrapperFunctionFormat, csharpcode);
                task.Compiled = false;
                parameters = new List<string> { };
            }
            try
            {
                task.Compile();
            }
            catch (CompilerException e)
            {
                Console.WriteLine(e.Message);
            }
        }

        private static IEnumerable<ParsedParameter> ParseParameters(string command)
        {
            List<ParsedParameter> ParsedParameters = new List<ParsedParameter>();

            // ("surrounded by quotes") | (/labeled:"with or without quotes") | (orseperatedbyspace)
            List<string> matches = Regex
                .Matches(command, @"""[^""\\]*(?:\\.[^""\\]*)*""|(/[^""\\/:]*:[""][^""\\]*(?:\\.[^""\\]*)*[""]|[^ ]+)|[^ ]+")
                .Cast<Match>()
                .Select(M => M.Value)
                .ToList();
            for (int i = 0; i < matches.Count; i++)
            {
                if (matches[i].StartsWith("/", StringComparison.Ordinal) && matches[i].IndexOf(":", StringComparison.Ordinal) != -1)
                {
                    int labelIndex = matches[i].IndexOf(":", StringComparison.Ordinal);
                    string label = matches[i].Substring(1, labelIndex - 1);
                    string val = matches[i].Substring(labelIndex + 1, matches[i].Length - labelIndex - 1);
                    ParsedParameters.Add(new ParsedParameter
                    {
                        Position = i,
                        IsLabeled = true,
                        Label = label,
                        Value = (val.StartsWith("\"", StringComparison.Ordinal) && val.EndsWith("\"", StringComparison.Ordinal)) ? val.Trim('"') : val
                    });
                }
                else
                {
                    ParsedParameters.Add(new ParsedParameter
                    {
                        Position = i,
                        IsLabeled = false,
                        Label = "",
                        Value = matches[i].Trim('"')
                    });
                }
            }
            return ParsedParameters;
        }
        public class ParsedParameter
        {
            public int Position { get; set; }
            public bool IsLabeled { get; set; }
            public string Label { get; set; }
            public string Value { get; set; }
        }

    }
}
