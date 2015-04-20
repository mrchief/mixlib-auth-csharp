# mixlib-auth-csharp
A full C# port of [chef's mixlib authentication](https://github.com/chef/mixlib-authentication) library.

## Installation

To install mixlib-authentication, run the following command in the [Package Manager Console](http://docs.nuget.org/docs/start-here/using-the-package-manager-console):

```	
PM> Install-Package mixlib-authentication 
``` 

## Usage
In order to make any call to Chef API, you would need to setup an authorized user in Chef Server and export the user's private PEM key in Base64 encoded format<sup>1</sup>.


Both the examples assume that you have done the previous setup and have the following info:

```csharp
var userId = "authorizedChefUser";
var userPrivatePemKey = "some crypto string";
```

### Classic Usage (the core library way)

```csharp
var request = new HttpRequestMessage(HttpMethod.Get, "http://path/to/chef/server/api/endpoint");
// do stuff with HttpRequestMessage

// Sigining before making an API call
var auth = new SignedHeaderAuth(request.Method, request.AbsolutePath, "", request.RequestUri.Host, userId);
var signedHeaders = auth.Sign(userPrivatePemKey);
foreach (var header in signedHeaders)
{
	request.Headers.Add(header.Key, header.Value);
}

// make the API call
```

### Easy Usage (via the HttpRequestMessage extension)

```csharp
var request = new HttpRequestMessage(HttpMethod.Get, "http://path/to/chef/server/api/endpoint");
// do stuff with HttpRequestMessage

request.SignWithMixLibAuthentication(userId, userPrivatePemKey);

// make the API call
```

The `HttpRequestMessage` extension also takes care of certain nuances of the `Uri` object (which is responsible for providing `Path`, `Host` parameter) and the `HttpRequestMessage` object such as:

 - handling Uri created with relative path
 - handling the case where reading the content body (of HttpRequestMessage) makes it empty for subsequent calls.
 
### Other usages
If you're not using ASP.Net MVC or WEB API or for whatever reasons need to use something else, such as `HttpWebRequest`, you can still use this library via one of 2 methods:

 - Follow the classic way usage, obtain headers (which is just a name-value pair dictionary), and add those to existing headers.
 - Write your extension method which does that for you, similar to [HttpRequestMessageExtensions.cs](https://github.com/mrchief/mixlib-auth-csharp/blob/master/src/MixLibAuthentication/HttpRequestMessageExtensions.cs)


### Tests

Tests can be found **MixLibAuthentication.Tests** project. 

**Note**: Not all tests defined in the core library are applicable 1:1, primarily since .Net provides useful classes (like `HttpRequestMessage` or `HttpWebRequest`) and some of the language constructs do not have equivalent in .Net world (based on my limited understanding of Ruby language). I plan on adding more tests in the future and I welcome any PRs for more tests.

### References
 1. For details on Chef Authentication & Authorization, read the [docs](https://docs.chef.io/auth.html).