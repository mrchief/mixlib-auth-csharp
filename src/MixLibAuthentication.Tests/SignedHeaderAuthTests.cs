using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
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
        private SignedHeaderAuth _v11Request;

        private readonly string _privateKeyData = "-----BEGIN RSA PRIVATE KEY-----"
                                        + "\n" + "MIIEpAIBAAKCAQEA0ueqo76MXuP6XqZBILFziH/9AI7C6PaN5W0dSvkr9yInyGHS"
                                        + "\n" + "z/IR1+4tqvP2qlfKVKI4CP6BFH251Ft9qMUBuAsnlAVQ1z0exDtIFFOyQCdR7iXm"
                                        + "\n" + "jBIWMSS4buBwRQXwDK7id1OxtU23qVJv+xwEV0IzaaSJmaGLIbvRBD+qatfUuQJB"
                                        + "\n" + "MU/04DdJIwvLtZBYdC2219m5dUBQaa4bimL+YN9EcsDzD9h9UxQo5ReK7b3cNMzJ"
                                        + "\n" + "BKJWLzFBcJuePMzAnLFktr/RufX4wpXe6XJxoVPaHo72GorLkwnQ0HYMTY8rehT4"
                                        + "\n" + "mDi1FI969LHCFFaFHSAaRnwdXaQkJmSfcxzCYQIDAQABAoIBAQCW3I4sKN5B9jOe"
                                        + "\n" + "xq/pkeWBq4OvhW8Ys1yW0zFT8t6nHbB1XrwscQygd8gE9BPqj3e0iIEqtdphbPmj"
                                        + "\n" + "VHqTYbC0FI6QDClifV7noTwTBjeIOlgZ0NSUN0/WgVzIOxUz2mZ2vBZUovKILPqG"
                                        + "\n" + "TOi7J7RXMoySMdcXpP1f+PgvYNcnKsT72UcWaSXEV8/zo+Zm/qdGPVWwJonri5Mp"
                                        + "\n" + "DVm5EQSENBiRyt028rU6ElXORNmoQpVjDVqZ1gipzXkifdjGyENw2rt4V/iKYD7V"
                                        + "\n" + "5iqXOsvP6Cemf4gbrjunAgDG08S00kiUgvVWcdXW+dlsR2nCvH4DOEe3AYYh/aH8"
                                        + "\n" + "DxEE7FbtAoGBAPcNO8fJ56mNw0ow4Qg38C+Zss/afhBOCfX4O/SZKv/roRn5+gRM"
                                        + "\n" + "KRJYSVXNnsjPI1plzqR4OCyOrjAhtuvL4a0DinDzf1+fiztyNohwYsW1vYmqn3ti"
                                        + "\n" + "EN0GhSgE7ppZjqvLQ3f3LUTxynhA0U+k9wflb4irIlViTUlCsOPkrNJDAoGBANqL"
                                        + "\n" + "Q+vvuGSsmRLU/Cenjy+Mjj6+QENg51dz34o8JKuVKIPKU8pNnyeLa5fat0qD2MHm"
                                        + "\n" + "OB9opeQOcw0dStodxr6DB3wi83bpjeU6BWUGITNiWEaZEBrQ0aiqNJJKrrHm8fAZ"
                                        + "\n" + "9o4l4oHc4hI0kYVYYDuxtKuVJrzZiEapTwoOcYiLAoGBAI/EWbeIHZIj9zOjgjEA"
                                        + "\n" + "LHvm25HtulLOtyk2jd1njQhlHNk7CW2azIPqcLLH99EwCYi/miNH+pijZ2aHGCXb"
                                        + "\n" + "/bZrSxM0ADmrZKDxdB6uGCyp+GS2sBxjEyEsfCyvwhJ8b3Q100tqwiNO+d5FCglp"
                                        + "\n" + "HICx2dgUjuRVUliBwOK93nx1AoGAUI8RhIEjOYkeDAESyhNMBr0LGjnLOosX+/as"
                                        + "\n" + "qiotYkpjWuFULbibOFp+WMW41vDvD9qrSXir3fstkeIAW5KqVkO6mJnRoT3Knnra"
                                        + "\n" + "zjiKOITCAZQeiaP8BO5o3pxE9TMqb9VCO3ffnPstIoTaN4syPg7tiGo8k1SklVeH"
                                        + "\n" + "2S8lzq0CgYAKG2fljIYWQvGH628rp4ZcXS4hWmYohOxsnl1YrszbJ+hzR+IQOhGl"
                                        + "\n" + "YlkUQYXhy9JixmUUKtH+NXkKX7Lyc8XYw5ETr7JBT3ifs+G7HruDjVG78EJVojbd"
                                        + "\n" + "8uLA+DdQm5mg4vd1GTiSK65q/3EeoBlUaVor3HhLFki+i9qpT8CBsg=="
                                        + "\n" + "-----END RSA PRIVATE KEY-----";

        private readonly string[] _xOpsAuthorizationLinesV10 =
        {
            "jVHrNniWzpbez/eGWjFnO6lINRIuKOg40ZTIQudcFe47Z9e/HvrszfVXlKG4",
            "NMzYZgyooSvU85qkIUmKuCqgG2AIlvYa2Q/2ctrMhoaHhLOCWWoqYNMaEqPc",
            "3tKHE+CfvP+WuPdWk4jv4wpIkAz6ZLxToxcGhXmZbXpk56YTmqgBW2cbbw4O",
            "IWPZDHSiPcw//AYNgW1CCDptt+UFuaFYbtqZegcBd2n/jzcWODA7zL4KWEUy",
            "9q4rlh/+1tBReg60QdsmDRsw/cdO1GZrKtuCwbuD4+nbRdVBKv72rqHX9cu0",
            "utju9jzczCyB+sSAQWrxSsXB/b8vV2qs0l4VD2ML+w=="
        };

        private readonly string[] _xOpsAuthorizationLines =
        {
            "UfZD9dRz6rFu6LbP5Mo1oNHcWYxpNIcUfFCffJS1FQa0GtfU/vkt3/O5HuCM",
            "1wIFl/U0f5faH9EWpXWY5NwKR031Myxcabw4t4ZLO69CIh/3qx1XnjcZvt2w",
            "c2R9bx/43IWA/r8w8Q6decuu0f6ZlNheJeJhaYPI8piX/aH+uHBH8zTACZu8",
            "vMnl5MF3/OIlsZc8cemq6eKYstp8a8KYq9OmkB5IXIX6qVMJHA6fRvQEB/7j",
            "281Q7oI/O+lE8AmVyBbwruPb7Mp6s4839eYiOdjbDwFjYtbS3XgAjrHlaD7W",
            "FDlbAG7H8Dmvo+wBxmtNkszhzbBnEYtuwQqT8nM/8A=="
        };


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
            _v11Request = new SignedHeaderAuth(HttpMethod.Post, _path, _body, null, _userId, _timestampObj, "1.1");

           
        }


        [TestMethod]
        public void ShouldGenerateTheCorrectStringToSignAndSignatureForVersion10Default()
        {
            Assert.AreEqual(_v10CanonicalRequest, _v10Request.CanonicalizeRequest());

            var expectedSignedResults = new Dictionary<string, string>{
                {"X-Ops-Sign", "algorithm=SHA1;version=1.0;"},
                {"X-Ops-Userid", _userId},
                {"X-Ops-Timestamp", _timestampIso8601},
                {"X-Ops-Content-Hash", _hashedBody},
                {"X-Ops-Authorization-1", _xOpsAuthorizationLinesV10[0] },
                {"X-Ops-Authorization-2", _xOpsAuthorizationLinesV10[1] },
                {"X-Ops-Authorization-3", _xOpsAuthorizationLinesV10[2] },
                {"X-Ops-Authorization-4", _xOpsAuthorizationLinesV10[3] },
                {"X-Ops-Authorization-5", _xOpsAuthorizationLinesV10[4] },
                {"X-Ops-Authorization-6", _xOpsAuthorizationLinesV10[5] },
            };
            var actual = _v10Request.Sign(_privateKeyData);

            Assert.AreEqual(expectedSignedResults.Keys.Count, actual.Keys.Count);

            Assert.IsTrue(
                actual.Keys.All(k => expectedSignedResults.ContainsKey(k) && Equals(actual[k], expectedSignedResults[k])));
        }


        [TestMethod]
        public void ShouldGenerateTheCorrectStringToSignAndSignatureForVersion11()
        {
            Assert.AreEqual(_v11CanonicalRequest, _v11Request.CanonicalizeRequest());

            var expectedSignedResults = new Dictionary<string, string>{
                {"X-Ops-Sign", "algorithm=SHA1;version=1.1;"},
                {"X-Ops-Userid", _userId},
                {"X-Ops-Timestamp", _timestampIso8601},
                {"X-Ops-Content-Hash", _hashedBody},
                {"X-Ops-Authorization-1", _xOpsAuthorizationLines[0] },
                {"X-Ops-Authorization-2", _xOpsAuthorizationLines[1] },
                {"X-Ops-Authorization-3", _xOpsAuthorizationLines[2] },
                {"X-Ops-Authorization-4", _xOpsAuthorizationLines[3] },
                {"X-Ops-Authorization-5", _xOpsAuthorizationLines[4] },
                {"X-Ops-Authorization-6", _xOpsAuthorizationLines[5] },
            };
            var actual = _v11Request.Sign(_privateKeyData);

            Assert.AreEqual(expectedSignedResults.Keys.Count, actual.Keys.Count);

            Assert.IsTrue(
                actual.Keys.All(k => expectedSignedResults.ContainsKey(k) && Equals(actual[k], expectedSignedResults[k])));
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