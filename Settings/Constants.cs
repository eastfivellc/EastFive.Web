
namespace EastFive.Web.Configuration
{
    [Config]
    public class Constants
    {
        [Config]
        public static class KeyVault
        {
            [ConfigKeyAttribute("Location of the KeyVault", DeploymentOverrides.Suggested,
                Location ="Azure Portal -> KeyValue -> Settings -> (I'm making this up)",
                DeploymentSecurityConcern = true)]
            public const string Url = "KeyVault.Url";
            [ConfigKeyAttribute("The KeyValue at the url is multitennant so the client id specifies the tennant",
                DeploymentOverrides.Suggested,
                DeploymentSecurityConcern = true)]
            public const string ClientId = "KeyVault.ClientId";
            [ConfigKeyAttribute("Used by the application to authenticate to the KeyVault",
                DeploymentOverrides.Suggested,
                DeploymentSecurityConcern = true)]
            public const string ClientSecret = "KeyVault.ClientSecret";
        }
    }
}