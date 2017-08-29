using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;

namespace MixLibAuthentication.Authentication
{
    public class SignedHeaderAuth
    {
        private readonly HttpMethod _method;
        private readonly string _path;
        private readonly string _body;
        private readonly string _host;
        private readonly string _userId;
        private readonly DateTime? _timeStamp;
        private const string DefaultSignAlgorithm = "SHA2";
        private const string DefaultProtoVersion = "1.0";
        private readonly string[] _supportedAlgorithms = { DefaultSignAlgorithm };
        private readonly string[] _supportedVersions = { DefaultProtoVersion, "1.1" };

        public string ProtoVersion { get; set; }

        public string CanonicalTime => _timeStamp.GetValueOrDefault(DateTime.UtcNow).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");

        public string CanonicalPath
        {
            get
            {
                var p = Regex.Replace(_path, "/+", "/");
                return p.Length > 1 ? p.TrimEnd('/') : p;
            }
        }

        public string HashedBody => Digester.HashString(_body);

        /// <summary>
        /// Initializes a new instance of the <see cref="SignedHeaderAuth" /> class.
        /// </summary>
        /// <param name="method">The HTTP method. e.g., get | put | post | delete</param>
        /// <param name="path">The path part of the URI.</param>
        /// <param name="body">An object representing the body of the request. Use an empty String for bodiless requests.</param>
        /// <param name="host">The host part of the URI. Not currently used in computation of signature.</param>
        /// <param name="userId">The user or client name. This is used by the server to lookup the public key necessary to verify the signature.</param>
        /// <param name="timeStamp">The timestamp object. The server may reject the request if the timestamp is not close to the server's current time. Defaults to current UTC time.</param>
        /// <param name="protoVersion">The version of the signing protocol to use. Currently defaults to 1.0, but version 1.1 is also available.</param>
        public SignedHeaderAuth(HttpMethod method, string path, string body, string host, string userId,
                    DateTime? timeStamp = null, string protoVersion = DefaultProtoVersion)
        {
            _method = method;
            _path = path;
            _body = body;
            _host = host;
            _userId = userId;
            ProtoVersion = protoVersion;
            _timeStamp = timeStamp;
        }


        /// <summary>
        /// Initializes a new instance of the <see cref="SignedHeaderAuth" /> class.
        /// </summary>
        /// <param name="method">The HTTP method. e.g., get | put | post | delete</param>
        /// <param name="path">The path part of the URI.</param>
        /// <param name="fileStream">A file stream to be used as request body.</param>
        /// <param name="host">The host part of the URI. Not currently used in computation of signature.</param>
        /// <param name="userId">The user or client name. This is used by the server to lookup the public key necessary to verify the signature.</param>
        /// <param name="timeStamp">The timestamp object. The server may reject the request if the timestamp is not close to the server's current time. Defaults to current UTC time.</param>
        /// <param name="protoVersion">The version of the signing protocol to use. Currently defaults to 1.0, but version 1.1 is also available.</param>
        public SignedHeaderAuth(HttpMethod method, string path, Stream fileStream, string host, string userId,
                    DateTime? timeStamp = null, string protoVersion = DefaultProtoVersion) : this(method, path, new StreamReader(fileStream).ReadToEnd(), host, userId, timeStamp, protoVersion)
        {

        }


        /// <summary>
        /// Build the canonicalized request headers based on the method, other headers, etc.
        /// compute the signature from the request, using the looked-up user secret
        /// </summary>
        /// <param name="privateKey">User's RSA private key.</param>
        /// <param name="signAlgorithm">The version of the signing algorithm to use. Currently only SHA1 is supported.</param>
        /// <param name="signVersion">The version of the signing protocol to use.</param>
        /// <returns></returns>
        public IDictionary<string, string> Sign(string privateKey, string signAlgorithm, string signVersion)
        {
            var headers = new Dictionary<string, string>
            {
                {"X-Ops-Sign", $"algorithm={signAlgorithm};version={signVersion};"},
                {"X-Ops-Userid", _userId},
                {"X-Ops-Timestamp", CanonicalTime},
                {"X-Ops-Content-Hash", HashedBody}
            };

            var stringToSign = CanonicalizeRequest(signAlgorithm, signVersion);
            var signature = SignWithPrivateKey(privateKey, stringToSign);

            // Our multiline hash for authorization will be encoded in multiple header
            // lines - X-Ops-Authorization-1, ... (starts at 1, not 0!)
            var idx = 0;
            foreach (var line in signature.Split(60))
            {
                headers.Add($"X-Ops-Authorization-{++idx}", line);
            }

            return headers;
        }

        public IDictionary<string, string> Sign(string privateKey, string signAlgorithm)
        {
            return Sign(privateKey, signAlgorithm, ProtoVersion);
        }

        public IDictionary<string, string> Sign(string privateKey)
        {
            return Sign(privateKey, DefaultSignAlgorithm);
        }

        private string SignWithPrivateKey(string privateKey, string stringToSign)
        {
            var stringToSignBytes = Encoding.Default.GetBytes(stringToSign);
            var pemReader = new PemReader(new StringReader(privateKey));
            var key = ((AsymmetricCipherKeyPair) pemReader.ReadObject()).Private;

            ISigner signer = new RsaDigestSigner(new NullDigest());
            signer.Init(true, key);
            signer.BlockUpdate(stringToSignBytes, 0, stringToSignBytes.Length);

            return Convert.ToBase64String(signer.GenerateSignature());
        }

        public string CanonicalizeUserId(string userId, string protoVersion)
        {
            switch (protoVersion)
            {
                case "1.1":
                    return Digester.HashString(userId);
                case "1.0":
                default:
                    return userId;
            }
        }

        public string CanonicalizeRequest(string signAlgorithm = null,
            string signVersion = null)
        {
            if (signAlgorithm != null && !_supportedAlgorithms.Contains(signAlgorithm))
                throw new ArgumentOutOfRangeException(signAlgorithm, "Unsupported algorithm");

            if (signVersion != null && !_supportedVersions.Contains(signVersion))
                throw new ArgumentOutOfRangeException(signVersion, "Unsupported version");

            var canonicalXOpsUserId = CanonicalizeUserId(_userId, signVersion ?? ProtoVersion);
            
            return
                $"Method:{_method.ToString().ToUpper()}\nHashed Path:{Digester.HashString(CanonicalPath)}\nX-Ops-Content-Hash:{HashedBody}\nX-Ops-Timestamp:{CanonicalTime}\nX-Ops-UserId:{canonicalXOpsUserId}";
        }


    }
}