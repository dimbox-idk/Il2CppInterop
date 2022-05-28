﻿using System.CommandLine;
using System.CommandLine.NamingConventionBinder;
using System.Text.RegularExpressions;
using Il2CppInterop.Common;
using Il2CppInterop.Generator;
using Il2CppInterop.Generator.Runners;
using Il2CppInterop.StructGenerator;
using Microsoft.Extensions.Logging;
using Mono.Cecil;

var command = new RootCommand
{
    new Option<bool>("--verbose", "Produce more verbose output")
};
command.Description = "Generate Managed<->IL2CPP interop assemblies from Cpp2IL's output.";

var generateCommand = new Command("generate")
{
    new Option<DirectoryInfo>("--input", "Directory with Il2CppDumper's dummy assemblies") {IsRequired = true}
        .ExistingOnly(),
    new Option<DirectoryInfo>("--output", "Directory to write generated assemblies to") {IsRequired = true},
    new Option<DirectoryInfo>("--unity", "Directory with original Unity assemblies for unstripping").ExistingOnly(),
    new Option<FileInfo>("--game-assembly", "Path to GameAssembly.dll. Used for certain analyses").ExistingOnly(),
    new Option<bool>("--no-xref-cache", "Don't generate xref scanning cache. All scanning will be done at runtime."),
    new Option<string[]>("--add-prefix-to",
        "Assemblies and namespaces starting with these will get an Il2Cpp prefix in generated assemblies. Allows multiple values."),
    new Option<FileInfo>("--deobf-map",
        "Specifies a file specifying deobfuscation map for obfuscated types and members.").ExistingOnly(),
    new Option<int>("--deobf-uniq-chars", "How many characters per unique token to use during deobfuscation"),
    new Option<int>("--deobf-uniq-max", "How many maximum unique tokens per type are allowed during deobfuscation"),
    new Option<string[]>("--blacklist-assembly", "Don't write specified assembly to output. Allows multiple values."),
    new Option<Regex>("--obf-regex",
        "Specifies a regex for obfuscated names. All types and members matching will be renamed."),
    new Option<bool>("--passthrough-names",
        "If specified, names will be copied from input assemblies as-is without renaming or deobfuscation.")
};
generateCommand.Description = "Generate wrapper assemblies that can be used to interop with Il2Cpp";
generateCommand.Handler = CommandHandler.Create((GenerateCommandOptions opts) =>
{
    var buildResult = opts.Build();
    Il2CppInteropGenerator.Create(buildResult.Options)
        .AddLogger(buildResult.Logger)
        .AddInteropAssemblyGenerator()
        .Run();
});

var deobfCommand = new Command("deobf");
deobfCommand.Description = "Tools for deobfuscating assemblies";
var deobfAnalyzeCommand = new Command("analyze")
{
    new Option<DirectoryInfo>("--input", "Directory of assemblies to deobfuscate") {IsRequired = true}.ExistingOnly()
};
deobfAnalyzeCommand.Description =
    "Analyze deobfuscation performance with different parameter values. Will not generate assemblies.";
// TODO: Command implementation

var deobfGenerateCommand = new Command("generate")
{
    new Option<DirectoryInfo>("--old-assemblies", "Directory with old unobfuscated assemblies") {IsRequired = true}
        .ExistingOnly(),
    new Option<DirectoryInfo>("--new-assemblies", "Directory to write obfuscation maps to") {IsRequired = true}
        .ExistingOnly(),
    new Option<DirectoryInfo>("--output", "Directory to write obfuscation maps to") {IsRequired = true},
    new Option<string[]>("--include",
        "Include these assemblies for deobfuscation map generation. If none are specified, all assemblies will be included."),
    new Option<int>("--deobf-uniq-chars", "How many characters per unique token to use during deobfuscation"),
    new Option<int>("--deobf-uniq-max", "How many maximum unique tokens per type are allowed during deobfuscation")
};
deobfGenerateCommand.Description =
    "Generate a deobfuscation map from original unobfuscated assemblies. Will not generate assemblies.";
// TODO: Command implementation

var wrapperCommand = new Command("wrapper-gen")
{
    new Option<DirectoryInfo>("--headers",
            "Directory that contains libil2cpp headers. Directory must contains subdirectories named after libil2cpp version.")
        {IsRequired = true}.ExistingOnly(),
    new Option<DirectoryInfo>("--output", "Directory to write managed struct wrapper sources to") {IsRequired = true}
};
wrapperCommand.Description = "Tools for generating Il2Cpp struct wrappers from libi2lcpp source";
wrapperCommand.Handler = CommandHandler.Create((WrapperCommandOptions opts) =>
{
    Il2CppStructWrapperGenerator.Generate(opts.Build());
});

deobfCommand.Add(deobfAnalyzeCommand);
deobfCommand.Add(deobfGenerateCommand);
command.Add(deobfCommand);
command.Add(generateCommand);
command.Add(wrapperCommand);

return command.Invoke(args);

internal record CmdOptionsResult(GeneratorOptions Options, ILogger Logger);

internal record BaseCmdOptions(bool Verbose)
{
    public virtual CmdOptionsResult Build()
    {
        var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder
                .AddFilter("Il2CppInterop", Verbose ? LogLevel.Trace : LogLevel.Information)
                .AddSimpleConsole(opt => { opt.SingleLine = true; });
        });

        var logger = loggerFactory.CreateLogger("Il2CppInterop");

        return new(new GeneratorOptions
        {
            Verbose = Verbose
        }, logger);
    }
}

internal record WrapperCommandOptions(DirectoryInfo Headers, DirectoryInfo Output, bool Verbose)
{
    public virtual Il2CppStructWrapperGeneratorOptions Build()
    {
        var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder
                .AddFilter("Il2CppInterop", Verbose ? LogLevel.Trace : LogLevel.Information)
                .AddSimpleConsole(opt => { opt.SingleLine = true; });
        });
        var logger = loggerFactory.CreateLogger("Il2CppInterop");
        return new Il2CppStructWrapperGeneratorOptions(Headers.FullName, Output.FullName, logger);
    }
}

internal record GenerateCommandOptions(
    bool Verbose,
    DirectoryInfo Input,
    DirectoryInfo Output,
    DirectoryInfo? Unity,
    FileInfo? GameAssembly,
    bool NoXrefCache,
    string[]? AddPrefixTo,
    FileInfo? DeobfMap,
    int DeobfUniqChars,
    int DeobfUniqMax,
    string[]? BlacklistAssembly,
    Regex? ObfRegex,
    bool PassthroughNames
) : BaseCmdOptions(Verbose)
{
    public override CmdOptionsResult Build()
    {
        var res = base.Build();
        var opts = res.Options;

        var resolver = new BasicResolver();
        var inputAssemblies = Input.EnumerateFiles("*.dll").Select(f => AssemblyDefinition.ReadAssembly(f.FullName,
            new ReaderParameters
            {
                AssemblyResolver = resolver
            })).ToList();
        foreach (var assembly in inputAssemblies)
            resolver.Register(assembly);

        opts.Source = inputAssemblies;
        opts.OutputDir = Output.FullName;
        opts.UnityBaseLibsDir = Unity?.FullName;
        opts.GameAssemblyPath = GameAssembly?.FullName ?? "";
        opts.NoXrefCache = NoXrefCache;
        opts.TypeDeobfuscationCharsPerUniquifier = DeobfUniqChars;
        opts.TypeDeobfuscationMaxUniquifiers = DeobfUniqMax;
        opts.AdditionalAssembliesBlacklist.AddRange(BlacklistAssembly ?? Array.Empty<string>());
        opts.ObfuscatedNamesRegex = ObfRegex;
        opts.PassthroughNames = PassthroughNames;

        if (AddPrefixTo is not null)
            foreach (var s in AddPrefixTo)
                opts.NamespacesAndAssembliesToPrefix.Add(s);
        if (DeobfMap is not null)
            opts.ReadRenameMap(DeobfMap.FullName);

        return res;
    }
}

// TODO: Remove once separated into subcommands
internal record CmdOptions(
    bool Verbose,
    DirectoryInfo Input,
    DirectoryInfo Output,
    DirectoryInfo? Unity,
    FileInfo? GameAssembly,
    int DeobfUniqChars,
    int DeobfUniqMax,
    bool DeobfAnalyze,
    string[]? BlacklistAssembly,
    string[]? AddPrefixTo,
    bool NoXrefCache,
    Regex? ObfRegex,
    FileInfo? RenameMap,
    bool PassthroughNames,
    bool DeobfGenerate,
    string[]? DeobfGenerateAsm,
    DirectoryInfo? DeobfGenerateNew
)
{
    public GeneratorOptions BuildOptions()
    {
        var resolver = new BasicResolver();
        var inputAssemblies = Input.EnumerateFiles("*.dll").Select(f => AssemblyDefinition.ReadAssembly(f.FullName,
            new ReaderParameters
            {
                AssemblyResolver = resolver
            })).ToList();
        foreach (var assembly in inputAssemblies)
            resolver.Register(assembly);

        var result = new GeneratorOptions
        {
            Verbose = Verbose,
            NoXrefCache = NoXrefCache,
            Source = inputAssemblies,
            OutputDir = Output.FullName,
            UnityBaseLibsDir = Unity?.FullName,
            GameAssemblyPath = GameAssembly?.FullName ?? "",
            TypeDeobfuscationCharsPerUniquifier = DeobfUniqChars,
            TypeDeobfuscationMaxUniquifiers = DeobfUniqMax,
            ObfuscatedNamesRegex = ObfRegex,
            DeobfuscationNewAssembliesPath = DeobfGenerateNew?.FullName ?? "",
            PassthroughNames = PassthroughNames
        };
        result.AdditionalAssembliesBlacklist.AddRange(BlacklistAssembly ?? Array.Empty<string>());
        if (AddPrefixTo is not null)
            foreach (var s in AddPrefixTo)
                result.NamespacesAndAssembliesToPrefix.Add(s);
        if (RenameMap is not null)
            result.ReadRenameMap(RenameMap.FullName);
        result.DeobfuscationGenerationAssemblies.AddRange(DeobfGenerateAsm ?? Array.Empty<string>());
        return result;
    }
}

internal class BasicResolver : DefaultAssemblyResolver
{
    public void Register(AssemblyDefinition ad)
    {
        RegisterAssembly(ad);
    }
}
