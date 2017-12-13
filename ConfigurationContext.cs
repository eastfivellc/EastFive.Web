using System;
using System.Collections.Generic;
using System.Linq;
using BlackBarLabs.Extensions;
using BlackBarLabs.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using EastFive.Web.Configuration;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using EastFive.Collections.Generic;

namespace BlackBarLabs.Web
{
    /// <summary>
    /// Configuration singleton that merges web.config app settings with KeyVault keys
    /// </summary>
    public sealed class ConfigurationContext
    {
        private static volatile ConfigurationContext instance;
        private static object syncRoot = new Object();
        private static Dictionary<string, string> appSettings;

        private ConfigurationContext() { }

        public static ConfigurationContext Instance
        {
            get
            {
                if (instance == null)
                {
                    lock (syncRoot)
                    {
                        if (instance == null)
                            instance = new ConfigurationContext();
                    }
                }
                return instance;
            }
        }

        private void Initialize()
        {
            var appSettingsFromConfigFile = System.Configuration.ConfigurationManager.AppSettings;
            appSettings = appSettingsFromConfigFile.AllKeys.Select(
                key =>
                {
                    return key.PairWithValue(appSettingsFromConfigFile[key]);
                }).ToDictionary();

            // Merge Key Vault keys into app settings dictionary.  If there is a key conflict, favor Key Vault.
            Task.Run(()=> GetKeyVaultSecretsAsync(
                keyVaultValues =>
                {
                    appSettings = appSettings.Where(appSetting => !keyVaultValues.Keys.Contains(appSetting.Key)).Concat(keyVaultValues).ToDictionary();
                    return true;
                },
                ()=>false,
                ()=>false,
                ()=>false)).GetAwaiter().GetResult();
        }

        public Dictionary<string, string> AppSettings
        {
            get
            {
                if (appSettings == null)
                    Initialize();
                return appSettings;
            }
        }

        #region Key Vault Support

        private async static Task<TResult> GetKeyVaultSecretsAsync<TResult>(
             Func<Dictionary<string, string>, TResult> onFound,
             Func<TResult> onNotFound,
             Func<TResult> onKeyVaultTokenInvalid,
             Func<TResult> onKeyVaultNotConfigured)
        {
            try
            {
                var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetTokenAsync));
                var vaultUrl = EastFive.Web.Configuration.Settings.GetString(Constants.KeyVault.Url, value => value, (reason) => string.Empty);
                if (string.IsNullOrEmpty(vaultUrl))
                    return onKeyVaultNotConfigured();

                var secretBundle = await keyVaultClient.GetSecretsAsync(vaultUrl);
                if (null == secretBundle)
                    return onNotFound();

                var secrets = await secretBundle.Select(
                    async secret =>
                    {
                        var secretValue = await GetKeyVaultSecretAsync(secret.Identifier.Name,
                            value => value,
                            () => string.Empty,
                            () => string.Empty);


                        return secret.Identifier.Name.PairWithValue(secretValue);
                    }).WhenAllAsync();

                return onFound(secrets.ToDictionary());
            }
            catch (Exception e)
            {
                return onKeyVaultTokenInvalid();
            }
        }

        private async static Task<TResult> GetKeyVaultSecretAsync<TResult>(string key,
             Func<string, TResult> onFound,
             Func<TResult> onNotFound,
             Func<TResult> onKeyVaultTokenInvalid)
        {
            try
            {
                var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetTokenAsync));
                var vaultUrl = appSettings[Constants.KeyVault.Url];

                var secretBundle = await keyVaultClient.GetSecretAsync(vaultUrl, key);
                if (null == secretBundle)
                    return onNotFound();

                return onFound(secretBundle.Value);
            }
            catch (Exception e)
            {
                return onKeyVaultTokenInvalid();
            }
        }

        /// <summary>
        /// Delegate for KeyVaultClient.AuthenticationCallback that gets the auth token for Key Vault access
        /// </summary>
        /// <param name="authority"></param>
        /// <param name="resource"></param>
        /// <param name="scope"></param>
        /// <returns></returns>
        private static async Task<string> GetTokenAsync(string authority, string resource, string scope)
        {
            var clientId = appSettings[Constants.KeyVault.ClientId];
            var clientSecret = appSettings[Constants.KeyVault.ClientSecret];

            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(clientId, clientSecret);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }
        #endregion
    }
}

