using System.Net.Http;
using MixLibAuthentication.Authentication;

namespace MixLibAuthentication
{
    public static class HttpRequestMessageExtensions
    {
        public static HttpRequestMessage SignWithMixLibAuthentication(this HttpRequestMessage request, string userId, string privatePemKey)
        {
            var auth = new SignedHeaderAuth(request.Method, SafeGetRequestPath(request), SafeGetRequestBody(request), SafeGetRequestHost(request), userId);
            var signedHeaders = auth.Sign(privatePemKey);
            foreach (var header in signedHeaders)
            {
                request.Headers.Add(header.Key, header.Value);
            }
            return request;
        }

        private static string SafeGetRequestHost(HttpRequestMessage request)
        {
            return request.RequestUri.IsAbsoluteUri ? request.RequestUri.Host : "";
        }

        private static string SafeGetRequestBody(HttpRequestMessage request)
        {
            if (request.Method == HttpMethod.Get || request.Content == null)
                return "";

            // Reading request.Content.ReadAsStringAsync().Result directly will cause the request body to become empty in WebApi
            // Reassign the content after reading to bypass this WebAPi stupidity.
            var contentType = request.Content.Headers.ContentType;
            var content = request.Content.ReadAsStringAsync().Result;
            request.Content = new StringContent(content);
            request.Content.Headers.ContentType = contentType;
            return content;
        }

        private static string SafeGetRequestPath(HttpRequestMessage request)
        {
            // TODO: Handle request.RequestUri.IsFile

            if (request.RequestUri.IsAbsoluteUri)
            {
                return string.Join("/", request.RequestUri.Segments);
            }
            else
            {
                return request.RequestUri.OriginalString;
            }
        }
    }
}
