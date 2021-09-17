using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace ServicebusHttp
{
    class Program
    {
        static readonly string queueOrTopicUrl = "https://xxxx.servicebus.windows.net/xxxx"; // Format: "https://<service bus namespace>.servicebus.windows.net/<topic name or queue>/messages";
        static readonly string signatureKeyName = "";
        static readonly string signatureKey = "";
        static readonly TimeSpan timeToLive = TimeSpan.FromDays(30);

        static void Main(string[] args)
        {
            var token = GetSasToken(queueOrTopicUrl, signatureKeyName, signatureKey, timeToLive);
            Console.WriteLine("Authorization: " + token);
        }

        public static string GetSasToken(string resourceUri, string keyName, string key, TimeSpan ttl)
        {
            var expiry = GetExpiry(ttl);
            string stringToSign = HttpUtility.UrlEncode(resourceUri) + "\n" + expiry;
            HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            var signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
            var sasToken = string.Format(CultureInfo.InvariantCulture, "SharedAccessSignature sr={0}&sig={1}&se={2}&skn={3}",
            HttpUtility.UrlEncode(resourceUri), HttpUtility.UrlEncode(signature), expiry, keyName);
            return sasToken;
        }

        private static string GetExpiry(TimeSpan ttl)
        {
            TimeSpan expirySinceEpoch = DateTime.UtcNow - new DateTime(1970, 1, 1) + ttl;
            return Convert.ToString((int)expirySinceEpoch.TotalSeconds);
        }
    }
}
