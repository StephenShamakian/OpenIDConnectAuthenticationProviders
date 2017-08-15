//////////////////////////////////////////////////////////////////////
// TOOLS
//////////////////////////////////////////////////////////////////////
#tool "nuget:?package=GitVersion.CommandLine&prerelease"

using Path = System.IO.Path;
using IO = System.IO;
using Cake.Common.Tools;

//////////////////////////////////////////////////////////////////////
// ARGUMENTS
//////////////////////////////////////////////////////////////////////
var target = Argument("target", "Default");
var configuration = Argument("configuration", "Release");

///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES
///////////////////////////////////////////////////////////////////////////////
var publishDir = "./publish";
var artifactsDir = "./artifacts";
var assetDir = "./BuildAssets";
var localPackagesDir = "../LocalPackages";
var globalAssemblyFile = "./source/Solution Items/VersionInfo.cs";
var extensionName = "Octopus.Server.Extensibility.Authentication.OpenIDConnect";
var solutionToBuild = "./source/OpenIDConnectAuthenticationProvider.sln";
var cleanups = new List<IDisposable>(); 

var gitVersionInfo = GitVersion(new GitVersionSettings {
    OutputType = GitVersionOutput.Json
});

var nugetVersion = gitVersionInfo.NuGetVersion;

///////////////////////////////////////////////////////////////////////////////
// SETUP / TEARDOWN
///////////////////////////////////////////////////////////////////////////////
Setup(context =>
{
    if(BuildSystem.IsRunningOnTeamCity)
        BuildSystem.TeamCity.SetBuildNumber(gitVersionInfo.NuGetVersion);
    if(BuildSystem.IsRunningOnAppVeyor)
        AppVeyor.UpdateBuildVersion(gitVersionInfo.NuGetVersion);

    Information("Building " + extensionName + " v{0}", nugetVersion);
});

Teardown(context =>
{
    Information("Cleaning up");
    foreach(var item in cleanups)
        item.Dispose();

	Information("Finished running tasks.");
});

//////////////////////////////////////////////////////////////////////
//  PRIVATE TASKS
//////////////////////////////////////////////////////////////////////

Task("__Default")
    .IsDependentOn("__Clean")
    .IsDependentOn("__Restore")
    .IsDependentOn("__UpdateAssemblyVersionInformation")
    .IsDependentOn("__Build")
    .IsDependentOn("__Pack")
	.IsDependentOn("__Publish")
	.IsDependentOn("__CopyToLocalPackages");

Task("__Clean")
    .Does(() =>
{
    CleanDirectory(artifactsDir);
    CleanDirectory(publishDir);
    CleanDirectories("./source/**/bin");
    CleanDirectories("./source/**/obj");
});

Task("__Restore")
    .Does(() => NuGetRestore(solutionToBuild));
	
Task("__UpdateAssemblyVersionInformation")
    .Does(() =>
{
	cleanups.Add(new AutoRestoreFile(globalAssemblyFile));
    GitVersion(new GitVersionSettings {
		UpdateAssemblyInfo = true,
        UpdateAssemblyInfoFilePath = globalAssemblyFile
    });

    Information("AssemblyVersion -> {0}", gitVersionInfo.AssemblySemVer);
    Information("AssemblyFileVersion -> {0}", $"{gitVersionInfo.MajorMinorPatch}.0");
    Information("AssemblyInformationalVersion -> {0}", gitVersionInfo.InformationalVersion);
});

Task("__Build")
    .IsDependentOn("__UpdateAssemblyVersionInformation")
    .Does(() =>
{
    DotNetBuild(solutionToBuild, settings => settings.SetConfiguration(configuration));
});


Task("__Pack")
    .Does(() => {
        var nugetPackDir = Path.Combine(publishDir, "nuget");
        var nuspecFile = extensionName + ".nuspec";
        
		CreateDirectory(nugetPackDir);
        CopyFileToDirectory(Path.Combine(assetDir, nuspecFile), nugetPackDir);
		
		var solutionDir = "./source/";

		Information(solutionDir + extensionName + "/bin/System.IdentityModel.Tokens.Jwt.dll");
		CopyFileToDirectory(solutionDir + extensionName + "/bin/System.IdentityModel.Tokens.Jwt.dll", nugetPackDir);
		CopyFileToDirectory(solutionDir + extensionName + "/bin/" + extensionName + ".dll", nugetPackDir);
		
		CopyFileToDirectory(solutionDir + "Octopus.Server.Extensibility.Authentication.AzureAD/bin/Octopus.Server.Extensibility.Authentication.AzureAD.dll", nugetPackDir);
		CopyFileToDirectory(solutionDir + "Octopus.Server.Extensibility.Authentication.GoogleApps/bin/Octopus.Server.Extensibility.Authentication.GoogleApps.dll", nugetPackDir);
		CopyFileToDirectory(solutionDir + "Octopus.Server.Extensibility.Authentication.Okta/bin/Octopus.Server.Extensibility.Authentication.Okta.dll", nugetPackDir);
		
        NuGetPack(Path.Combine(nugetPackDir, nuspecFile), new NuGetPackSettings {
            Version = nugetVersion,
            OutputDirectory = artifactsDir
        });
    });


Task("__Publish")
    .WithCriteria(BuildSystem.IsRunningOnTeamCity)
    .Does(() =>
{
    NuGetPush($"{artifactsDir}/{extensionName}.{nugetVersion}.nupkg", new NuGetPushSettings {
		Source = "https://octopus.myget.org/F/octopus-dependencies/api/v3/index.json",
		ApiKey = EnvironmentVariable("MyGetApiKey")
	});
	
    if (gitVersionInfo.PreReleaseLabel == "")
    {
        NuGetPush($"{artifactsDir}/{extensionName}.{nugetVersion}.nupkg", new NuGetPushSettings {
            Source = "https://www.nuget.org/api/v2/package",
            ApiKey = EnvironmentVariable("NuGetApiKey")
        });
    }
});


Task("__CopyToLocalPackages")
    .WithCriteria(BuildSystem.IsLocalBuild)
    .IsDependentOn("__Pack")
    .Does(() =>
{
    CreateDirectory(localPackagesDir);
    CopyFileToDirectory(Path.Combine(artifactsDir, $"{extensionName}.{nugetVersion}.nupkg"), localPackagesDir);
});

private class AutoRestoreFile : IDisposable
{
	private byte[] _contents;
	private string _filename;
	public AutoRestoreFile(string filename)
	{
		_filename = filename;
		_contents = IO.File.ReadAllBytes(filename);
	}

	public void Dispose() => IO.File.WriteAllBytes(_filename, _contents);
}

//////////////////////////////////////////////////////////////////////
// TASKS
//////////////////////////////////////////////////////////////////////
Task("Default")
    .IsDependentOn("__Default");

//////////////////////////////////////////////////////////////////////
// EXECUTION
//////////////////////////////////////////////////////////////////////
RunTarget(target);
