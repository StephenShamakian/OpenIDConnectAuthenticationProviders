namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Certificates
{
    public interface IKeyJsonParser
    {
        KeyDetails[] Parse(string content);
    }
}