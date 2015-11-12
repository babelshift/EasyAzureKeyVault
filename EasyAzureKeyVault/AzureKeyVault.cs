using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Core;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace EasyAzureKeyVault
{
    public class AzureKeyVault
    {
        private KeyVaultKeyResolver keyResolver;
        private Dictionary<string, IKey> keyDictionary;
        private string clientId { get; set; }
        private string clientSecret { get; set; }

        /// <summary>
        /// Key resolver used during decryption of objects protected with Azure Key Vault keys.
        /// </summary>
        public KeyVaultKeyResolver KeyResolver
        {
            get
            {
                if (keyResolver == null)
                {
                    keyResolver = new KeyVaultKeyResolver(GetTokenAsync);
                }

                return keyResolver;
            }
        }

        /// <summary>
        /// Default constructor requires the Azure Active Directory client ID and client secret to authenticate against.
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        public AzureKeyVault(string clientId, string clientSecret)
        {
            keyDictionary = new Dictionary<string, IKey>();
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }

        /// <summary>
        /// Returns the key located at the provided keyUri. If the key is found in the cache, it is returned. If not, it is queried
        /// from the Key Vault and returned. This helps reduce the number of operations performed on the Key Vault and thus reduces the
        /// cost of using the Key Vault.
        /// </summary>
        /// <param name="keyUri"></param>
        /// <returns></returns>
        public async Task<IKey> GetKeyAsync(string keyUri)
        {
            IKey key = null;

            // do we already have a key for this uri in our cached collection?
            bool doesKeyExist = keyDictionary.TryGetValue(keyUri, out key);

            // key exists and isn't null, return it now
            if (doesKeyExist && key != null)
            {
                return key;
            }

            // key exists but is null, remove the null key from the dictionary
            if (doesKeyExist && key == null)
            {
                keyDictionary.Remove(keyUri);
            }

            // generate a new key and add to the dictionary
            key = await KeyResolver.ResolveKeyAsync(keyUri, CancellationToken.None);
            keyDictionary.Add(keyUri, key);

            return key;
        }

        /// <summary>
        /// Callback when KeyResolver is created. Provides authentication against Active Directory which will indicate that our
        /// application has access to the KeyVault.
        /// </summary>
        /// <param name="authority"></param>
        /// <param name="resource"></param>
        /// <param name="scope"></param>
        /// <returns></returns>
        private async Task<string> GetTokenAsync(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);

            ClientCredential clientCred = new ClientCredential(clientId, clientSecret);

            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
            {
                throw new InvalidOperationException("Failed to obtain the JWT token.");
            }

            return result.AccessToken;
        }
    }
}
