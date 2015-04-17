using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace MixLibAuthentication.Tests
{
    [TestClass]
    public class HttpRequestAuthenticationTests
    {
        [TestInitialize]
        public void Setup()
        {
            var timestamp_iso8601 = "2009-01-01T12:00:00Z";
            var x_ops_content_hash = "DFteJZPVv6WKdQmMqZUQUumUyRs=";    // hash of "Spec Body"
            var user_id = "spec-user";
            var httpXOpsLines = new[]
            {
                "jVHrNniWzpbez/eGWjFnO6lINRIuKOg40ZTIQudcFe47Z9e/HvrszfVXlKG4",
                "NMzYZgyooSvU85qkIUmKuCqgG2AIlvYa2Q/2ctrMhoaHhLOCWWoqYNMaEqPc",
                "3tKHE+CfvP+WuPdWk4jv4wpIkAz6ZLxToxcGhXmZbXpk56YTmqgBW2cbbw4O",
                "IWPZDHSiPcw//AYNgW1CCDptt+UFuaFYbtqZegcBd2n/jzcWODA7zL4KWEUy",
                "9q4rlh/+1tBReg60QdsmDRsw/cdO1GZrKtuCwbuD4+nbRdVBKv72rqHX9cu0",
                "utju9jzczCyB+sSAQWrxSsXB/b8vV2qs0l4VD2ML+w=="
            };

            var request = new HttpRequestMessage(HttpMethod.Post, "http://127.0.0.1/organizations/local-test-org/cookbooks");
            //request.Headers.Add("HTTP_HOST", "127.0.0.1");
            request.Headers.Add("HTTP_X_OPS_SIGN", "version=1.0");
            request.Headers.Add("HTTP_X_OPS_REQUESTID", "127.0.0.1 1258566194.85386");
            request.Headers.Add("HTTP_X_OPS_TIMESTAMP", timestamp_iso8601);
            request.Headers.Add("HTTP_X_OPS_CONTENT_HASH", x_ops_content_hash);
            request.Headers.Add("HTTP_X_OPS_USERID", user_id);
            request.Headers.Add("HTTP_X_OPS_AUTHORIZATION_1", httpXOpsLines[0]);
            request.Headers.Add("HTTP_X_OPS_AUTHORIZATION_2", httpXOpsLines[1]);
            request.Headers.Add("HTTP_X_OPS_AUTHORIZATION_3", httpXOpsLines[2]);
            request.Headers.Add("HTTP_X_OPS_AUTHORIZATION_4", httpXOpsLines[3]);
            request.Headers.Add("HTTP_X_OPS_AUTHORIZATION_5", httpXOpsLines[4]);
            request.Headers.Add("HTTP_X_OPS_AUTHORIZATION_6", httpXOpsLines[5]);

            // Random sampling
            request.Headers.Add("REMOTE_ADDR", "127.0.0.1");
            //request.Headers.Add("PATH_INFO", "/organizations/local-test-org/cookbooks");
            //request.Headers.Add("REQUEST_PATH", "/organizations/local-test-org/cookbooks");
            var content = new MultipartFormDataContent("---RubyMultipartClient6792ZZZZZ")
            {
                new StringContent("Spec Body")
            };
            request.Content = content;
            //request.Headers.Add("CONTENT_TYPE", "multipart/form-data; boundary=----RubyMultipartClient6792ZZZZZ");
            //request.Headers.Add("CONTENT_LENGTH", "394");

        }


        [TestMethod]
        public void ShouldNormalizeHeadersToLowercaseSymbols()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void ShouldRaiseErrorWhenNotAllRequiredHeadersAreGiven()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void ShouldExtractThePathFromTheRequest()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void ShouldExtractTheRequestMethodFromTheRequest()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void ShouldExtractTheSigningDescriptionFromTheRequestHeaders()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void ShouldExtractTheUser_idFromTheRequestHeaders()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void ShouldExtractTheTimestampFromTheRequestHeaders()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void ShouldExtractTheHostFromTheRequestHeaders()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void ShouldExtractTheContentHashFromTheRequestHeaders()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void ShouldRebuildTheRequestSignatureFromTheHeaders()
        {
            Assert.Inconclusive();
        }

    }
}
