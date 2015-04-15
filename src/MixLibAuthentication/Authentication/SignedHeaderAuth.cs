using System;
using System.Linq;
using System.Net.Http;

namespace MixLibAuthentication.Authentication
{
    public class SignedHeaderAuth
    {
        private readonly HttpRequestMessage _request;
        private readonly string _userId;
        private readonly string _protoVersion;
        private const string DefaultSignAlgorithm = "SHA1";
        private const string DefaultProtoVersion = "1.0";
        private readonly string[] _supportedAlgorithms = { DefaultSignAlgorithm };
        private readonly string[] _supportedVersions = { DefaultProtoVersion, "1.1" };

        public string CanonicalTime => DateTime.UtcNow.ToString("O");
        public string CanonicalPath => _request.RequestUri.AbsolutePath;

        public SignedHeaderAuth(HttpRequestMessage request, string userId, string protoVersion = DefaultProtoVersion)
        {
            _request = request;
            _userId = userId;
            _protoVersion = protoVersion;
        }

        public void Sign() { }

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

        public HttpRequestMessage CanonicalizeRequest(string signAlgorithm = DefaultSignAlgorithm,
            string signVersion = DefaultProtoVersion)
        {
            if (!_supportedAlgorithms.Contains(signAlgorithm))
                throw new ArgumentOutOfRangeException(signAlgorithm, "Unsupported algorithm");

            if (!_supportedVersions.Contains(signVersion))
                throw new ArgumentOutOfRangeException(signVersion, "Unsupported version");

            var canonicalXOpsUserId = CanonicalizeUserId(_userId, signVersion);
            var hashedBody = _request.Content;

            return
                $"Method:{_request.Method.Method.ToUpper()}\nHashed Path:{Digester.HashString(CanonicalPath)}\nX-Ops-Content-Hash:{hashedBody}\nX-Ops-Timestamp:{CanonicalTime}\nX-Ops-UserId:{canonicalXOpsUserId}";
        }

        
    }
}