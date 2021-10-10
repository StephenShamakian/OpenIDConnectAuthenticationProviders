# Run this script after installing a new version of Octopus Server, but before starting it (due to file lock and dependency load issues).

$OctopusServerBinaryLocation = "E:\Program Files\Octopus Deploy\Octopus" # Make sure this points to where you install the Octopus Server binaries
$OctopusServerCustomExtensionsLocation = "C:\ProgramData\Octopus\CustomExtensions\" # This should always point to where the Octopus Server CustomExtenions folder lives

Copy-Item "$OctopusServerBinaryLocation\Octopus.Data.dll" -Destination "$OctopusServerCustomExtensionsLocation" -Force
Copy-Item "$OctopusServerBinaryLocation\Octopus.Server.Extensibility.Authentication.dll" -Destination "$OctopusServerCustomExtensionsLocation" -Force
Copy-Item "$OctopusServerBinaryLocation\BuiltInExtensions\Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.dll" -Destination "$OctopusServerCustomExtensionsLocation" -Force
