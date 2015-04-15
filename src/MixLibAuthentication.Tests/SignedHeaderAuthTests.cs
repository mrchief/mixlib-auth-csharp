using System;
using System.Linq;
using System.Net.Http;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using MixLibAuthentication.Authentication;

namespace MixLibAuthentication.Tests
{
    [TestClass]
    public class SignedHeaderAuthTests
    {
        string _userId;
        string _digestedUserId;
        string _body;
        string _hashedBody;
        string _timestampIso8601;
        DateTime _timestampObj;
        string _path;
        string _hashedCanonicalPath;
        string _v10CanonicalRequest;
        string _v11CanonicalRequest;
        private SignedHeaderAuth _v10Request;


        [TestInitialize]
        public void Setup()
        {
            _userId = "spec-user";

            _digestedUserId = Digester.HashString(_userId);

            _body = "Spec Body";

            _hashedBody = "DFteJZPVv6WKdQmMqZUQUumUyRs=";  // Convert.ToBase64String(Digester.HashString("Spec Body")) ;

            _timestampIso8601 = "2009-01-01T12:00:00Z";

            _timestampObj = DateTime.Parse(_timestampIso8601);

            _path = "/organizations/clownco";

            _hashedCanonicalPath = "YtBWDn1blGGuFIuKksdwXzHU9oE=";

            _v10CanonicalRequest =
                $"Method:POST\nHashed Path:{_hashedCanonicalPath}\nX-Ops-Content-Hash:{_hashedBody}\nX-Ops-Timestamp:{_timestampIso8601}\nX-Ops-UserId:{_userId}";

            _v11CanonicalRequest =
                $"Method:POST\nHashed Path:{_hashedCanonicalPath}\nX-Ops-Content-Hash:{_hashedBody}\nX-Ops-Timestamp:{_timestampIso8601}\nX-Ops-UserId:{_digestedUserId}";

            _v10Request = new SignedHeaderAuth(HttpMethod.Post, _path, _body, null, _userId, _timestampObj);
        }


        [TestMethod]
        public void ShouldGenerateTheCorrectStringToSignAndSignatureForVersion10Default()
        {
            Assert.AreEqual(_v10CanonicalRequest, _v10Request.CanonicalizeRequest());
        }


        [TestMethod]
        public void ShouldGenerateTheCorrectStringToSignAndSignatureForVersion11()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldGenerateTheCorrectStringToSignAndSignatureForNonDefaultProtoVersionWhenUsedAsAMixin()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldNotChokeWhenSigningARequestForALongUserIdWithVersion11()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldChokeWhenSigningARequestForALongUserIdWithVersion10()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldChokeWhenSigningARequestWithABadVersion()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldChokeWhenSigningARequestWithABadAlgorithm()
        {
            Assert.Inconclusive();
        }


        private bool HeaderEquals(HttpRequestMessage request, string name, string value)
        {
            return request.Headers.Any(x => x.Key == name && x.Value.Any() && x.Value.First() == value);
        }
    }
}