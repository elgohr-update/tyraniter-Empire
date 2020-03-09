// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Reflection;
using Microsoft.CodeAnalysis;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace EmpireCompiler
{
    public static class Common
    {
        public static string CovenantDirectory = Assembly.GetExecutingAssembly().Location.Split("bin")[0].Split("EmpireCompiler.dll")[0];
        public static string CovenantDataDirectory = CovenantDirectory + "data" + Path.DirectorySeparatorChar;
        public static string CovenantDatabaseFile = CovenantDataDirectory + "covenant.db";
        public static string CovenantTempDirectory = CovenantDataDirectory + "temp" + Path.DirectorySeparatorChar;

        public static string CovenantAssemblyReferenceDirectory = CovenantDataDirectory + "AssemblyReferences" + Path.DirectorySeparatorChar;
        public static string CovenantEmbeddedResourcesDirectory = CovenantDataDirectory + "EmbeddedResources" + Path.DirectorySeparatorChar;
        public static string CovenantReferenceSourceLibraries = CovenantDataDirectory + "ReferenceSourceLibraries" + Path.DirectorySeparatorChar;

        public static Dictionary<DotNetVersion, string> CovenantAssemblyReferenceDirectories = new Dictionary<DotNetVersion, string> {
            { DotNetVersion.Net35,CovenantAssemblyReferenceDirectory + "net35" + Path.DirectorySeparatorChar },
            { DotNetVersion.Net40,CovenantAssemblyReferenceDirectory + "net40" + Path.DirectorySeparatorChar },
            { DotNetVersion.Net45,CovenantAssemblyReferenceDirectory + "net45" + Path.DirectorySeparatorChar },
        };

        public static string CovenantTaskDirectory = CovenantDataDirectory + "Tasks" + Path.DirectorySeparatorChar;
        public static string CovenantTaskCSharpDirectory = CovenantTaskDirectory + "CSharp" + Path.DirectorySeparatorChar;
        public static string CovenantTaskCSharpCompiledDirectory = CovenantDataDirectory + "Compiled" + Path.DirectorySeparatorChar;

        public static Dictionary<DotNetVersion, string> CovenantTaskCSharpCompiledDirectories = new Dictionary<DotNetVersion, string> {
            { DotNetVersion.Net35,CovenantTaskCSharpCompiledDirectory + "net35" + Path.DirectorySeparatorChar },
            { DotNetVersion.Net40,CovenantTaskCSharpCompiledDirectory + "net40" + Path.DirectorySeparatorChar },
            { DotNetVersion.Net45,CovenantTaskCSharpCompiledDirectory + "net45" + Path.DirectorySeparatorChar },
        };

        public static List<string> ReferenceSourceLibraries = new List<string>
        {
            "SharpSploit",
            "Rubeus",
            "Seatbelt",
            "SharpDPAPI",
            "SharpChrome",
            "SharpDump",
            "SharpUp",
            "SharpWMI"
        };

        public static Dictionary<string, List<string>> ReferenceSourceLibraryReferenceAssemblies = new Dictionary<string, List<string>>
        {
            {"SharpSploit",new List<string>{
                "mscorlib.dll",
                "System.dll",
                "System.Core.dll" ,
                "System.DirectoryServices.dll",
                "System.IdentityModel.dll",
                "System.Management.dll",
                "System.Management.Automation.dll" }
            },
            {"Rubeus",new List<string>{
                "mscorlib.dll",
                "System.dll",
                "System.Core.dll" ,
                "System.DirectoryServices.dll",
                "System.DirectoryServices.AccountManagement.dll",
                "System.IdentityModel.dll"}
            },
            {"Seatbelt", new List<string>{
                "mscorlib.dll",
                "System.dll",
                "System.Core.dll" ,
                "System.DirectoryServices.dll",
                "System.Management.dll",
                "System.ServiceProcess.dll",
                "System.XML.dll",
                "System.Web.Extensions.dll"}
            },
            {"SharpDPAPI",new List<string>{
                "mscorlib.dll",
                "System.dll",
                "System.Core.dll" ,
                "System.XML.dll",
                "System.Security.dll" }
            },
            {"SharpChrome",new List<string>{
                "mscorlib.dll",
                "System.dll",
                "System.Core.dll" ,
                "System.XML.dll",
                "System.Security.dll" }
            },
            {"SharpDump",new List<string>{
                "mscorlib.dll",
                "System.dll",
                "System.Core.dll" ,}
            },
            {"SharpUp",new List<string>{
                "mscorlib.dll",
                "System.dll",
                "System.Core.dll" ,
                "System.Management.dll",
                "System.ServiceProcess.dll",
                "System.XML.dll"}
            },
            {"SharpWMI",new List<string>{
                "mscorlib.dll",
                "System.dll",
                "System.Core.dll" ,
                "System.Management.dll", }
            }
        };

        public static List<string> Tasks = new List<string> {
            "Agent",
            "Assembly",
            "AssemblyReflect",
            "BypassAmsi",
            "BypassUACCommand",
            "BypassUACGrunt",
            "ChangeDirectory",
            "ChromeDump",
            "Connect",
            "DCOMCommand",
            "DCOMGrunt",
            "DCSync",
            "Disconnect",
            "Download",
            "GetCurrentDirectory",
            "GetDomainComputer",
            "GetDomainGroup",
            "GetDomainUser",
            "GetNetLocalGroup",
            "GetNetLocalGroupMember",
            "GetNetLoggedOnUser",
            "GetNetSession",
            "GetRegistryKey",
            "GetRemoteRegistryKey",
            "GetSystem",
            "Help",
            "ImpersonateProcess",
            "ImpersonateUser",
            "Jobs",
            "Kerberoast",
            "Keylogger",
            "Kill",
            "Launcher",
            "ListDirectory",
            "LogonPasswords",
            "LsaCache",
            "LsaSecrets",
            "MakeToken",
            "Mimikatz",
            "PersistAutorun",
            "PersistCOMHijack",
            "PersistStartup",
            "PersistWMI",
            "PortScan",
            "PowerShell",
            "PowerShellImport",
            "PrivExchange",
            "ProcessList",
            "ReadTextFile",
            "RevertToSelf",
            "Rubeus",
            "SafetyKatz",
            "SamDump",
            "ScreenShot",
            "Seatbelt",
            "Set",
            "SetRegistryKey",
            "SetRemoteRegistryKey",
            "SharpChrome",
            "SharpDPAPI",
            "SharpDump",
            "SharpShell",
            "SharpUp",
            "SharpWMI",
            "Shell",
            "ShellCmd",
            "ShellCmdRunAs",
            "ShellCode",
            "ShellRunAs",
            "Stager",
            "Upload",
            "WMICommand",
            "WMIGrunt",
            "Wdigest",
            "WhoAmI"
        };

        public static Dictionary<string, List<string>> TaskReferenceSourceLibraries = new Dictionary<string, List<string>>()
        {
            { "SharpSploit", new List<string>{"Shell" ,"ShellCmd" ,"ShellrunAs" ,"ShellCmdrunAs" ,"PowerShell" ,"Assembly" ,"BypassAmsi" ,"AssemblyReflect" ,"ListDirectory" ,"ChangeDirectory" ,"ProcessList" ,"Mimikatz" ,"LogonPasswords" ,"LsaSecrets" ,"LsaCache" ,"SamDump" ,"Wdigest" ,"DCSync" ,"Portscan" ,"Kerberoast" ,"SafetyKatz" ,"WhoAmI" ,"ImpersonateUser" ,"ImpersonateProcess" ,"GetSystem" ,"MakeToken" ,"RevertToSelf" ,"WMICommand" ,"WMIGrunt" ,"DCOMCommand" ,"DCOMGrunt" ,"BypassUACCommand" ,"BypassUACGrunt" ,"GetDomainUser" ,"GetDomainGroup" ,"GetDomainComputer" ,"GetNetLocalGroup" ,"GetNetLocalGroupMember" ,"GetNetLoggedOnUser" ,"GetNetSession" ,"GetRegistryKey" ,"SetRegistryKey" ,"GetRemoteRegistryKey" ,"SetRemoteRegistryKey" ,"ShellCode" ,"SharpShell" ,"PrivExchange" ,"PersistCOMHijack" ,"PersistStartup" ,"PersistAutorun" ,"PersistWMI" ,"Keylogger" } },
            { "SharpDPAPI", new List<string>{"SharpDPAPI" } },
            { "Rubeus", new List<string>{"Rubeus"} },
            { "SharpChrome", new List<string>{"SharpChrome"} },
            { "SharpUp", new List<string>{"SharpUp"} },
            { "SharpDump",new List<string>{"SharpDump"} },
            { "Seatbelt", new List<string>{"Seatbelt" }},
            { "SharpWMI", new List<string>{"SharpWMI" }},
        };

        public static Dictionary<string,List<string>> TaskEmbeddedResource = new Dictionary<string, List<string>> {
            { "SharpSploit.Resources.powerkatz_x64.dll",new List<string>{
                "Mimikatz",
                "LogonPasswords",
                "LsaSecrets",
                "LsaCache",
                "SamDump",
                "Wdigest",
                "DCSync",
                "SafetyKatz"} },
            { "SharpSploit.Resources.powerkatz_x86.dll",new List<string>{
                "Mimikatz",
                "LogonPasswords",
                "LsaSecrets",
                "LsaCache",
                "SamDump",
                "Wdigest",
                "DCSync",
                "SafetyKatz"} },
            { "SharpChrome.dll",new List<string>{
                "ChromeDump"} },
        };

        public static Dictionary<string, List<string>> TaskReferenceAssembly = new Dictionary<string, List<string>>
        {
            {"Launcher", new List<string>{
                "mscorlib.dll","System.dll","System.Core.dll"}},
            {"Stager", new List<string>{
                "mscorlib.dll","System.dll","System.Core.dll"}},
            {"Agent", new List<string>{
                "mscorlib.dll","System.dll","System.Core.dll"}},
            {"Upload", new List<string>{
                "mscorlib.dll","System.dll","System.Core.dll"}},
            {"Download", new List<string>{
                "mscorlib.dll","System.dll","System.Core.dll"}},
            {"ReadTextFile", new List<string>{
                "mscorlib.dll","System.dll","System.Core.dll"}},
            {"GetCurrentDirectory", new List<string>{
                "mscorlib.dll","System.dll","System.Core.dll"}},
            {"PrivExchange", new List<string>{
                "System.XML.dll"}},
            {"ScreenShot", new List<string>{
                "mscorlib.dll","System.dll","System.Core.dll","System.Drawing.dll","System.Windows.Forms.dll"}},
            {"ChromeDump", new List<string>{
                "mscorlib.dll","System.dll","System.Core.dll"}},
        };

        public static List<Compiler.Reference> DefaultNet35References = new List<Compiler.Reference>
        {
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net35] + "mscorlib.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net35] + "System.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net35] + "System.Core.dll", Framework = DotNetVersion.Net35, Enabled = true },
        };

        public static List<Compiler.Reference> DefaultNet40References = new List<Compiler.Reference>
        {
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net40] + "mscorlib.dll", Framework = DotNetVersion.Net40, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net40] + "System.dll", Framework = DotNetVersion.Net40, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net40] + "System.Core.dll", Framework = DotNetVersion.Net40, Enabled = true }
        };

        public static List<Compiler.Reference> DefaultNet45References = new List<Compiler.Reference>
        {
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net45] + "mscorlib.dll", Framework = DotNetVersion.Net45, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net45] + "System.dll", Framework = DotNetVersion.Net45, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net45] + "System.Core.dll", Framework = DotNetVersion.Net45, Enabled = true }
        };

        public static List<Compiler.Reference> DefaultNetFrameworkReferences = new List<Compiler.Reference>
        {
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net35] + "mscorlib.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net35] + "System.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net35] + "System.Core.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net40] + "mscorlib.dll", Framework = DotNetVersion.Net40, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net40] + "System.dll", Framework = DotNetVersion.Net40, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net40] + "System.Core.dll", Framework = DotNetVersion.Net40, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net45] + "mscorlib.dll", Framework = DotNetVersion.Net45, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net45] + "System.dll", Framework = DotNetVersion.Net45, Enabled = true },
            new Compiler.Reference { File = CovenantTaskCSharpCompiledDirectories[DotNetVersion.Net45] + "System.Core.dll", Framework = DotNetVersion.Net45, Enabled = true }
        };

        public enum DotNetVersion
        {
            Net45,
            Net40,
            Net35,
        }
    }
}
