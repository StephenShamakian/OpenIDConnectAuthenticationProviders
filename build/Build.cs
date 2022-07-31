using System;
using Nuke.Common;
using Nuke.Common.CI;
using Nuke.Common.Execution;
using Nuke.Common.IO;
using Nuke.Common.ProjectModel;
using Nuke.Common.Tools.DotNet;
using Nuke.Common.Utilities.Collections;
using static Nuke.Common.IO.FileSystemTasks;
using static Nuke.Common.Tools.DotNet.DotNetTasks;
using Nuke.Common.Tools.OctoVersion;

[CheckBuildProjectConfigurations]
[ShutdownDotNetAfterServerBuild]
class Build : NukeBuild
{
    /// Support plugins are available for:
    ///   - JetBrains ReSharper        https://nuke.build/resharper
    ///   - JetBrains Rider            https://nuke.build/rider
    ///   - Microsoft VisualStudio     https://nuke.build/visualstudio
    ///   - Microsoft VSCode           https://nuke.build/vscode

    public static int Main () => Execute<Build>(x => x.Default);

    [Parameter("Configuration to build - 'Release' (server)")]
    readonly Configuration Configuration = Configuration.Release;

    [Solution] readonly Solution Solution;
    [OctoVersion] readonly OctoVersionInfo OctoVersionInfo;

    AbsolutePath SourceDirectory => RootDirectory / "source";
    AbsolutePath ArtifactsDirectory => RootDirectory / "artifacts";
    AbsolutePath PublishDirectory => RootDirectory / "publish";
    AbsolutePath LocalPackagesDir => RootDirectory / ".." / "LocalPackages";

    Target Clean => _ => _
        .Executes(() =>
        {
            SourceDirectory.GlobDirectories("**/bin", "**/obj").ForEach(EnsureCleanDirectory);
            EnsureCleanDirectory(ArtifactsDirectory);
            EnsureCleanDirectory(PublishDirectory);
        });

    Target Restore => _ => _
        .DependsOn(Clean)
        .Executes(() =>
        {
            DotNetRestore(s => s
                .SetProjectFile(Solution));
        });

    Target Compile => _ => _
        .DependsOn(Restore)
        .Executes(() =>
        {
            Logger.Info("Building Octopus Server OpenID Connect Authentication Provider v{0}", OctoVersionInfo.FullSemVer);
            
            // This is done to pass the data to github actions
            Console.Out.WriteLine($"::set-output name=semver::{OctoVersionInfo.FullSemVer}");
            Console.Out.WriteLine($"::set-output name=prerelease_tag::{OctoVersionInfo.PreReleaseTagWithDash}");

            DotNetBuild(s => s
                .SetProjectFile(Solution)
                .SetConfiguration(Configuration)
                .SetVersion(OctoVersionInfo.NuGetVersion)
                .EnableNoRestore());
        });
    
    Target Test => _ => _
        .DependsOn(Compile)
        .Executes(() =>
        {
            DotNetTest(_ => _
                .SetProjectFile(SourceDirectory / "Tests" / "Tests.csproj")
                .SetConfiguration(Configuration)
                .EnableNoBuild());
        });

    Target Pack => _ => _
        .DependsOn(Test)
        .Produces(ArtifactsDirectory / "*.nupkg")
        .Executes(() =>
        {
            Logger.Info("Packing Octopus Server OpenID Connect Authentication Provider v{0}", OctoVersionInfo.FullSemVer);
            
            CopyFileToDirectory(BuildProjectDirectory / "Octopus.Server.Extensibility.Authentication.OpenIDConnect.nuspec", PublishDirectory);
            
            CopyFileToDirectory(RootDirectory / "LICENSE.txt", PublishDirectory);
            CopyFileToDirectory(BuildProjectDirectory / "icon.png", PublishDirectory);
            CopyFileToDirectory(SourceDirectory / "Server.OpenIDConnect.Common" / "bin" / Configuration / "net5.0" / "Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.dll" , PublishDirectory);
            CopyFileToDirectory(SourceDirectory / "Server.AzureAD" / "bin" / Configuration / "net5.0" / "Octopus.Server.Extensibility.Authentication.AzureAD.dll" , PublishDirectory);
            CopyFileToDirectory(SourceDirectory / "Server.GoogleApps" / "bin" / Configuration / "net5.0" / "Octopus.Server.Extensibility.Authentication.GoogleApps.dll", PublishDirectory);
            CopyFileToDirectory(SourceDirectory / "Server.Okta" / "bin" / Configuration / "net5.0" / "Octopus.Server.Extensibility.Authentication.Okta.dll", PublishDirectory);
            CopyFileToDirectory(SourceDirectory / "Server.OctopusID" / "bin" / Configuration / "net5.0" / "Octopus.Server.Extensibility.Authentication.OctopusID.dll", PublishDirectory);

            DotNetPack(_ => _
                .SetProject(SourceDirectory / "Server.OpenIDConnect.Common" / "Server.OpenIDConnect.Common.csproj") 
                // we need a placeholder csproj here even though nuspec is what is being honoured - https://github.com/NuGet/Home/issues/4254 
                .SetVersion(OctoVersionInfo.FullSemVer)
                .SetConfiguration(Configuration)
                .SetOutputDirectory(ArtifactsDirectory)
                .EnableNoBuild()
                .DisableIncludeSymbols()
                .SetVerbosity(DotNetVerbosity.Normal)
                .SetProperty("NuspecFile", PublishDirectory / "Octopus.Server.Extensibility.Authentication.OpenIDConnect.nuspec")
                .SetProperty("NuspecProperties", $"Version={OctoVersionInfo.FullSemVer}"));

            
            DotNetPack(_ => _
                .SetProject(SourceDirectory / "Server.OpenIDConnect.Common" /"Server.OpenIDConnect.Common.csproj")
                .SetVersion(OctoVersionInfo.FullSemVer)
                .SetConfiguration(Configuration)
                .SetOutputDirectory(ArtifactsDirectory)
                .EnableNoBuild()
                .DisableIncludeSymbols()
                .SetVerbosity(DotNetVerbosity.Normal));
            
            DotNetPack(_ => _
                .SetProject(SourceDirectory / "Client.OpenIDConnect" / "Client.OpenIDConnect.csproj")
                .SetVersion(OctoVersionInfo.FullSemVer)
                .SetConfiguration(Configuration)
                .SetOutputDirectory(ArtifactsDirectory)
                .EnableNoBuild()
                .DisableIncludeSymbols()
                .SetVerbosity(DotNetVerbosity.Normal));
            
            DotNetPack(_ => _
                .SetProject(SourceDirectory / "Client.AzureAD" / "Client.AzureAD.csproj")
                .SetVersion(OctoVersionInfo.FullSemVer)
                .SetConfiguration(Configuration)
                .SetOutputDirectory(ArtifactsDirectory)
                .EnableNoBuild()
                .DisableIncludeSymbols()
                .SetVerbosity(DotNetVerbosity.Normal));
            
            DotNetPack(_ => _
                .SetProject(SourceDirectory / "Client.GoogleApps" / "Client.GoogleApps.csproj")
                .SetVersion(OctoVersionInfo.FullSemVer)
                .SetConfiguration(Configuration)
                .SetOutputDirectory(ArtifactsDirectory)
                .EnableNoBuild()
                .DisableIncludeSymbols()
                .SetVerbosity(DotNetVerbosity.Normal));
            
            DotNetPack(_ => _
                .SetProject(SourceDirectory / "Client.Okta" / "Client.Okta.csproj")
                .SetVersion(OctoVersionInfo.FullSemVer)
                .SetConfiguration(Configuration)
                .SetOutputDirectory(ArtifactsDirectory)
                .EnableNoBuild()
                .DisableIncludeSymbols()
                .SetVerbosity(DotNetVerbosity.Normal));
            
            DotNetPack(_ => _
                .SetProject(SourceDirectory / "Client.OctopusID" / "Client.OctopusID.csproj")
                .SetVersion(OctoVersionInfo.FullSemVer)
                .SetConfiguration(Configuration)
                .SetOutputDirectory(ArtifactsDirectory)
                .EnableNoBuild()
                .DisableIncludeSymbols()
                .SetVerbosity(DotNetVerbosity.Normal));
        });
    
        Target CopyToLocalPackages => _ => _
            .OnlyWhenStatic(() => IsLocalBuild)
            .TriggeredBy(Pack)
            .Executes(() =>
            {
                EnsureExistingDirectory(LocalPackagesDir);
                ArtifactsDirectory.GlobFiles("*.nupkg")
                    .ForEach(package =>
                    {
                        CopyFileToDirectory(package, LocalPackagesDir);
                    });
            });

        Target Default => _ => _
            .DependsOn(Pack)
            .DependsOn(CopyToLocalPackages);
}