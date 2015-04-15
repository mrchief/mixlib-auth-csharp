using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace MixLibAuthentication.Tests
{
    [TestClass]
    public class SignatureVerificationTests
    {
        [TestInitialize]
        public void Setup()
        {
        }

        
        [TestMethod]
        public void ShouldAuthenticateAFileContainingRequestFromMerb()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldAuthenticateAFileContainingRequestFromAVersion10ClientPassenger()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldAuthenticateANormalPostBodyRequestMerb()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldAuthenticateANormalPostBodyRequestFromAVersion10ClientMerb()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldNotAuthenticateIfAnAuthorizationHeaderIsMissing()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldNotAuthenticateIfAuthorizationHeaderIsWrong()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldNotAuthenticateIfTheTimestampIsNotWithinBounds()
        {
            Assert.Inconclusive();
        }


        [TestMethod]
        public void ShouldNotAuthenticateIfTheSignatureIsWrong()
        {
            Assert.Inconclusive();
        }
    }
}