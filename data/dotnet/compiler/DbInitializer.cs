using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;


namespace EmpireCompiler
{
    public static class DbInitializer
    {
        public async static Task Initialize(CovenantContext context)
        {
            context.Database.EnsureCreated();
            await InitializeTasks(context);
        }
        public async static Task InitializeTasks(CovenantContext context)
        {
            //ReferenceAssemblies
            if (!context.ReferenceAssemblies.Any())
            {
                List<ReferenceAssembly> ReferenceAssemblies = new List<ReferenceAssembly>();
                foreach (Common.DotNetVersion version in Common.CovenantAssemblyReferenceDirectories.Keys)
                {
                    Directory.GetFiles(Common.CovenantAssemblyReferenceDirectories[version]).ToList().ForEach(R =>
                    {
                        FileInfo info = new FileInfo(R);
                        ReferenceAssemblies.Add(new ReferenceAssembly
                        {
                            Name = info.Name,
                            Location = info.FullName,
                            DotNetVersion = version
                        });
                    });
                }
                await context.ReferenceAssemblies.AddRangeAsync(ReferenceAssemblies);
                await context.SaveChangesAsync();
            }

            //EmbeddedResources
            if (!context.EmbeddedResources.Any())
            {
                IEnumerable<EmbeddedResource> EmbeddedResources = Directory.GetFiles(Common.CovenantEmbeddedResourcesDirectory).Select(R =>
                {
                    FileInfo info = new FileInfo(R);
                    return new EmbeddedResource
                    {
                        Name = info.Name,
                        Location = info.FullName
                    };
                });
                await context.EmbeddedResources.AddRangeAsync(EmbeddedResources);
                await context.SaveChangesAsync();
            }

            //ReferenceSourceLibraries
            if (!context.ReferenceSourceLibraries.Any())
            {
                var ReferenceSourceLibraries = new List<ReferenceSourceLibrary>();
                foreach (string library in Common.ReferenceSourceLibraries)
                {
                    ReferenceSourceLibraries.Add(
                    new ReferenceSourceLibrary
                    {
                        Name = library, Description = "",
                        Location = Common.CovenantReferenceSourceLibraries + library + Path.DirectorySeparatorChar,
                        SupportedDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40, Common.DotNetVersion.Net45 }
                    });
                };
                await context.ReferenceSourceLibraries.AddRangeAsync(ReferenceSourceLibraries);
                await context.SaveChangesAsync();

                List<ReferenceSourceLibraryReferenceAssembly> sourceLibraryAssembly = new List<ReferenceSourceLibraryReferenceAssembly>();
                foreach (string library in Common.ReferenceSourceLibraryReferenceAssemblies.Keys)
                {
                    var lib = await context.GetReferenceSourceLibraryByName(library);
                                        foreach (string assembly in Common.ReferenceSourceLibraryReferenceAssemblies[library]) {
                        sourceLibraryAssembly.Add(new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = lib, ReferenceAssembly = await context.GetReferenceAssemblyByName(assembly, Common.DotNetVersion.Net35) });
                        sourceLibraryAssembly.Add(new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = lib, ReferenceAssembly = await context.GetReferenceAssemblyByName(assembly, Common.DotNetVersion.Net40) });
                        sourceLibraryAssembly.Add(new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = lib, ReferenceAssembly = await context.GetReferenceAssemblyByName(assembly, Common.DotNetVersion.Net45) });
                    };
                };
                await context.AddRangeAsync(sourceLibraryAssembly);
                await context.SaveChangesAsync();
            }

            //tasks
            if (!context.GruntTasks.Any())
            {
                var GruntTasks = new List<GruntTask>();
                foreach (string task in Common.Tasks)
                {
                    GruntTasks.Add(new GruntTask
                    {
                        Name = task,
                        AlternateNames = new List<string>(),
                        Description = task + ".",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, task + ".task")),
                        Options = new List<GruntTaskOption>(),
                    });
                }

                await context.GruntTasks.AddRangeAsync(GruntTasks);
                await context.SaveChangesAsync();

                //taskReferenceSourceLibrary
                List<GruntTaskReferenceSourceLibrary> taskReferenceSourceLibrary = new List<GruntTaskReferenceSourceLibrary>();
                foreach (string library in Common.TaskReferenceSourceLibraries.Keys)
                {
                    var lib = await context.GetReferenceSourceLibraryByName(library);
                    foreach (string task in Common.TaskReferenceSourceLibraries[library])
                    {
                        taskReferenceSourceLibrary.Add(new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = lib, GruntTask = await context.GetGruntTaskByName(task) });
                    }
                }
                await context.AddRangeAsync(taskReferenceSourceLibrary);
                await context.SaveChangesAsync();

                //taskEmbeddedResource
                List<GruntTaskEmbeddedResource> gruntTaskEmbeddedResource = new List<GruntTaskEmbeddedResource>();
                foreach (string embeddedResource in Common.TaskEmbeddedResource.Keys)
                { 
                    var er = await context.GetEmbeddedResourceByName(embeddedResource);
                    foreach (string task in Common.TaskEmbeddedResource[embeddedResource]) 
                    {
                        gruntTaskEmbeddedResource.Add(new GruntTaskEmbeddedResource { EmbeddedResource = er, GruntTask = await context.GetGruntTaskByName(task) });
                    }
                }
                await context.AddRangeAsync(gruntTaskEmbeddedResource);
                await context.SaveChangesAsync();


                //taskReferenceAssembly
                List<GruntTaskReferenceAssembly> taskReferenceAssembly = new List<GruntTaskReferenceAssembly>();
                foreach (string task in Common.TaskReferenceAssembly.Keys)
                {
                    var t = await context.GetGruntTaskByName(task);
                    foreach (string assembly in Common.TaskReferenceAssembly[task])
                    {
                        taskReferenceAssembly.Add(new GruntTaskReferenceAssembly { GruntTask = t, ReferenceAssembly = await context.GetReferenceAssemblyByName(assembly, Common.DotNetVersion.Net35) });
                        taskReferenceAssembly.Add(new GruntTaskReferenceAssembly { GruntTask = t, ReferenceAssembly = await context.GetReferenceAssemblyByName(assembly, Common.DotNetVersion.Net40) });
                        taskReferenceAssembly.Add(new GruntTaskReferenceAssembly { GruntTask = t, ReferenceAssembly = await context.GetReferenceAssemblyByName(assembly, Common.DotNetVersion.Net45) });
                    }
                }
                await context.AddRangeAsync(taskReferenceAssembly);
                await context.SaveChangesAsync();
            }
        }
    }
}
