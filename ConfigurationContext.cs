using System;
using System.Collections.Generic;
using System.Linq;
using BlackBarLabs.Extensions;
using BlackBarLabs.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using EastFive.Web.Configuration;
using EastFive.Collections.Generic;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Threading;

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
        private static object syncAppSettings = new Object();

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

        private Dictionary<string, string> Initialize()
        {
            var appSettingsFromConfigFile = System.Configuration.ConfigurationManager.AppSettings;
            var settings = appSettingsFromConfigFile.AllKeys.Select(
                key =>
                {
                    return key.PairWithValue(appSettingsFromConfigFile[key]);
                }).ToDictionary();

            // Set appSettings at the last moment so that the lock keeps everybody out until all is initialized 
            if (!settings.TryGetValue(EastFive.Web.AppSettings.KeyVault.Url, out string vaultUrl) ||
                !settings.TryGetValue(EastFive.Web.AppSettings.KeyVault.ClientId, out string clientId) ||
                !settings.TryGetValue(EastFive.Web.AppSettings.KeyVault.ClientSecret, out string clientSecret))
            {
                return settings;
            }

            // Merge Key Vault keys into app settings dictionary.  If there is a key conflict, favor Key Vault.
            return GetKeyVaultSecretsAsync(vaultUrl, clientId, clientSecret,
                keyVaultValues =>
                {
                    return settings.Where(pair => !keyVaultValues.Keys.Contains(pair.Key)).Concat(keyVaultValues).ToDictionary();
                },
                ()=> 
                {
                    return settings;
                },
                () =>
                {
                    return settings;
                },
                () =>
                {
                    return settings;
                }).GetAwaiter().GetResult();
        }

        private static EventWaitHandle appSettingsLock = new AutoResetEvent(true);
        public Dictionary<string, string> AppSettings
        {
            get
            {
                try
                {
                    appSettingsLock.WaitOne();
                    if (appSettings == null)
                        appSettings = Initialize();
                    return appSettings;
                } finally
                {
                    appSettingsLock.Set();
                }
            }
        }

        public TResult GetSettingValue<TResult>(string key,
            Func<string, TResult> onFound,
            Func<TResult> onKeyDoesNotExist)
        {
            if (!AppSettings.ContainsKey(key))
                return onKeyDoesNotExist();

            return onFound(appSettings[key]);
        }

        #region Key Vault Support

        private async static Task<TResult> GetKeyVaultSecretsAsync<TResult>(string vaultUrl, string clientId, string clientSecret,
             Func<Dictionary<string, string>, TResult> onFound,
             Func<TResult> onNotFound,
             Func<TResult> onKeyVaultTokenInvalid,
             Func<TResult> onKeyVaultNotConfigured)
        {
            if (string.IsNullOrEmpty(vaultUrl) ||
                string.IsNullOrEmpty(clientId) ||
                string.IsNullOrEmpty(clientSecret))
                return onKeyVaultNotConfigured();

            try
            {
                var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(
                    async (authority, resource, scope) => await GetTokenAsync(clientId, clientSecret, authority, resource, scope)));

                var secretBundle = await keyVaultClient.GetSecretsAsync(vaultUrl);
                if (null == secretBundle)
                    return onNotFound();

                // The api returns 25 keys at a time
                var names = secretBundle.Select(secret => secret.Identifier.Name).ToArray();
                while (!string.IsNullOrEmpty(secretBundle.NextPageLink))
                {
                    secretBundle = await keyVaultClient.GetSecretsNextAsync(secretBundle.NextPageLink);
                    if (secretBundle == null)
                        break;
                    names = names.Concat(secretBundle.Select(secret => secret.Identifier.Name)).ToArray();
                };

                var secrets = await names
                    .Select(
                        async name =>
                        {
                            var secret = await keyVaultClient.GetSecretAsync(vaultUrl, name);
                            var value = (null == secret) ? string.Empty : secret.Value;
                            // KeyVault will only allow Alphanumberic characters and dashes.  Replace - with . to keep our  
                            // current naming convention.  Yes - this means we cannot have dashes in our names.
                            return name.Replace("-", ".").PairWithValue(value);
                        }).WhenAllAsync(1);

                return onFound(secrets.ToDictionary());
            }
            catch (Exception)
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
        private static async Task<string> GetTokenAsync(string clientId, string clientSecret, string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            var clientCred = new ClientCredential(clientId, clientSecret);
            var result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }
        #endregion
    }
}

