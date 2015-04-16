using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace MixLibAuthentication.Authentication
{
    public class SignedHeaderAuth
    {
        private readonly HttpRequestMessage _request;
        private readonly HttpMethod _method;
        private readonly string _path;
        private readonly string _body;
        private readonly string _host;
        private readonly string _userId;
        private readonly string _protoVersion;
        private readonly DateTime? _timeStamp;
        private const string DefaultSignAlgorithm = "SHA1";
        private const string DefaultProtoVersion = "1.0";
        private const string _fakeHost = "http://dummy.com";
        private readonly string[] _supportedAlgorithms = { DefaultSignAlgorithm };
        private readonly string[] _supportedVersions = { DefaultProtoVersion, "1.1" };

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

        public SignedHeaderAuth(HttpMethod method, string path, string body, string host, string userId,
            DateTime? timeStamp = null, string protoVersion = DefaultProtoVersion)
        {
            _method = method;
            _path = path;
            _body = body;
            _host = host;
            _userId = userId;
            _protoVersion = protoVersion;
            _timeStamp = timeStamp;
        }

        public SignedHeaderAuth(HttpMethod method, string path, Stream fileStream, string host, string userId,
            DateTime? timeStamp = null, string protoVersion = DefaultProtoVersion) :this(method, path, new StreamReader(fileStream).ReadToEnd(), host, userId, timeStamp, protoVersion)
        {

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

        public string CanonicalizeRequest(string signAlgorithm = DefaultSignAlgorithm,
            string signVersion = DefaultProtoVersion)
        {
            if (!_supportedAlgorithms.Contains(signAlgorithm))
                throw new ArgumentOutOfRangeException(signAlgorithm, "Unsupported algorithm");

            if (!_supportedVersions.Contains(signVersion))
                throw new ArgumentOutOfRangeException(signVersion, "Unsupported version");

            var canonicalXOpsUserId = CanonicalizeUserId(_userId, signVersion);
            
            return
                $"Method:{_method.ToString().ToUpper()}\nHashed Path:{Digester.HashString(CanonicalPath)}\nX-Ops-Content-Hash:{HashedBody}\nX-Ops-Timestamp:{CanonicalTime}\nX-Ops-UserId:{canonicalXOpsUserId}";
        }


    }
}