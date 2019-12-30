// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;

namespace EmpireCompiler
{
    public class CovenantContext: DbContext
    {
        public DbSet<GruntTask> GruntTasks { get; set; }
        public DbSet<ReferenceSourceLibrary> ReferenceSourceLibraries { get; set; }
        public DbSet<ReferenceAssembly> ReferenceAssemblies { get; set; }
        public DbSet<EmbeddedResource> EmbeddedResources { get; set; }
        
        protected override void OnConfiguring(DbContextOptionsBuilder options)
            => options.UseSqlite("Data Source="+ Common.CovenantDatabaseFile);
        public CovenantContext(DbContextOptions<CovenantContext> options) : base(options)
        {

        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<GruntTaskOption>().ToTable("GruntTaskOption");
            builder.Entity<ReferenceSourceLibraryReferenceAssembly>()
                .HasKey(t => new { t.ReferenceSourceLibraryId, t.ReferenceAssemblyId });
            builder.Entity<ReferenceSourceLibraryReferenceAssembly>()
                .HasOne(rslra => rslra.ReferenceSourceLibrary)
                .WithMany("ReferenceSourceLibraryReferenceAssemblies");
            builder.Entity<ReferenceSourceLibraryReferenceAssembly>()
                .HasOne(rslra => rslra.ReferenceAssembly)
                .WithMany("ReferenceSourceLibraryReferenceAssemblies");

            builder.Entity<ReferenceSourceLibraryEmbeddedResource>()
                .HasKey(t => new { t.ReferenceSourceLibraryId, t.EmbeddedResourceId });
            builder.Entity<ReferenceSourceLibraryEmbeddedResource>()
                .HasOne(rslra => rslra.ReferenceSourceLibrary)
                .WithMany("ReferenceSourceLibraryEmbeddedResources");
            builder.Entity<ReferenceSourceLibraryEmbeddedResource>()
                .HasOne(rslra => rslra.EmbeddedResource)
                .WithMany("ReferenceSourceLibraryEmbeddedResources");


            builder.Entity<GruntTaskReferenceAssembly>()
                .HasKey(t => new { t.GruntTaskId, t.ReferenceAssemblyId });
            builder.Entity<GruntTaskReferenceAssembly>()
                .HasOne(gtra => gtra.GruntTask)
                .WithMany("GruntTaskReferenceAssemblies");
            builder.Entity<GruntTaskReferenceAssembly>()
                .HasOne(gtra => gtra.ReferenceAssembly)
                .WithMany("GruntTaskReferenceAssemblies");

            builder.Entity<GruntTaskEmbeddedResource>()
                .HasKey(t => new { t.GruntTaskId, t.EmbeddedResourceId });
            builder.Entity<GruntTaskEmbeddedResource>()
                .HasOne(gter => gter.GruntTask)
                .WithMany("GruntTaskEmbeddedResources");
            builder.Entity<GruntTaskEmbeddedResource>()
                .HasOne(gter => gter.EmbeddedResource)
                .WithMany("GruntTaskEmbeddedResources");

            builder.Entity<GruntTaskReferenceSourceLibrary>()
                .HasKey(t => new { t.GruntTaskId, t.ReferenceSourceLibraryId });
            builder.Entity<GruntTaskReferenceSourceLibrary>()
                .HasOne(gtrsl => gtrsl.GruntTask)
                .WithMany("GruntTaskReferenceSourceLibraries");
            builder.Entity<GruntTaskReferenceSourceLibrary>()
                .HasOne(gtrsl => gtrsl.ReferenceSourceLibrary)
                .WithMany("GruntTaskReferenceSourceLibraries");


            builder.Entity<GruntTask>().Property(GT => GT.AlternateNames).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            );

            builder.Entity<GruntTaskOption>().Property(GTO => GTO.SuggestedValues).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            );

            builder.Entity<ReferenceSourceLibrary>().Property(RA => RA.SupportedDotNetVersions).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<Common.DotNetVersion>() : JsonConvert.DeserializeObject<List<Common.DotNetVersion>>(v)
            );
            base.OnModelCreating(builder);
        }

        public async Task<GruntTask> GetGruntTaskByName(string name)
        {
            GruntTask task = await this.GruntTasks
                .Where(T => T.Name.ToUpper().Equals(name.ToUpper()) || T.AlternateNames.Contains(name.ToUpper()))
                .Include(T => T.Options)
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .Include("GruntTaskReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskEmbeddedResources.EmbeddedResource")
                .FirstOrDefaultAsync();
            if (task == null)
            {
                throw new Exception($"NotFound - GruntTask with Name: {name}");
            }
            return task;
        }
        public async Task<GruntTask[]> GetGrantTaskAll() {
            List<GruntTask> tasks = new List<GruntTask>();
            var taskNames = this.GruntTasks.Select(t => t.Name);
            foreach (var taskName in taskNames) {
                GruntTask task = await GetGruntTaskByName(taskName);
                tasks.Add(task);
            }
            return tasks.ToArray();
        }

        public async Task<ReferenceSourceLibrary> GetReferenceSourceLibraryByName(string name)
        {
            ReferenceSourceLibrary library = await this.ReferenceSourceLibraries
                .Where(RSL => RSL.Name == name)
                .Include("ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .FirstOrDefaultAsync();
            if (library == null)
            {
                throw new Exception($"NotFound - ReferenceSourceLibrary with Name: {name}");
            }
            return library;
        }
        public async Task<ReferenceAssembly> GetReferenceAssemblyByName(string name, Common.DotNetVersion version)
        {
            ReferenceAssembly assembly = await this.ReferenceAssemblies
                .Where(RA => RA.Name == name && RA.DotNetVersion == version)
                .FirstOrDefaultAsync();
            if (assembly == null)
            {
                throw new Exception($"NotFound - ReferenceAssembly with Name: {name} and DotNetVersion: {version}");
            }
            return assembly;
        }
        public async Task<EmbeddedResource> GetEmbeddedResourceByName(string name)
        {
            EmbeddedResource resource = await this.EmbeddedResources
                .Where(ER => ER.Name == name)
                .FirstOrDefaultAsync();
            if (resource == null)
            {
                throw new Exception($"NotFound - EmbeddedResource with Name: {name}");
            }
            return resource;
        }

        public void CompileGruntCode(string CodeTemplate, Common.DotNetVersion version, bool Compress = false)
        {
            byte[] ILBytes = Compiler.Compile(new Compiler.CompilationRequest
            {
                Source = CodeTemplate,
                TargetDotNetVersion = version,
                OutputKind = Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary,
                References = version == Common.DotNetVersion.Net35 ? Common.DefaultNet35References : Common.DefaultNet40References
            });
            if (ILBytes == null || ILBytes.Length == 0)
            {
                throw new Exception("Compiling Grunt code failed");
            }
            if (Compress)
            {
                ILBytes = Compiler.Compress(ILBytes);
            }
            File.WriteAllBytes(Common.CovenantTaskCSharpCompiledNet35Directory + "Agent.compiled", ILBytes);
            //return ILBytes;
        }
    }
}
