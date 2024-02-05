using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http.Json;
using UrlEncryption.Tests.Fixtures;

namespace UrlEncryption.Tests.Integration
{
    public class QueryTests : TestFixture
    {
        private const string Endpoint = "/Query";

        private readonly HttpClient _client;

        public QueryTests(WebApplicationFactory<Program> factory)
            : base(factory)
        {
            _client = Factory.CreateClient();
        }

        private async Task<TestViewModel?> GetDataFromResponseAsync(HttpResponseMessage response)
        {
            return await response.Content
                .ReadFromJsonAsync<TestViewModel>();
        }

        [Fact]
        public async void Returns_200OK()
        {
            var response = await _client.GetAsync(Endpoint);

            Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async void UnencryptedQueryParameters_PassedToTheAction_AreUnchanged()
        {
            QueryString query = new QueryString()
                .Add("lastName", "Doe")
                .Add("firstName", "John");

            var response = await _client.GetAsync(Endpoint + query);
            var data = await GetDataFromResponseAsync(response);

            Assert.NotNull(data);
            Assert.NotNull(data.FirstName);
            Assert.Equal("John", data.FirstName);
        }

        [Fact]
        public async void EncryptedQueryParameters_PassedToTheAction_AreDecrypted()
        {
            // Arrange

            IDataProtector protector = Factory.Services
                .GetRequiredService<IQueryEncryptionDataProtectionProvider>()
                .CreateProtector();

            string encryptedLastName = protector.Protect("Doe");

            QueryString query = new QueryString()
                .Add("lastName", encryptedLastName)
                .Add("firstName", "John");

            // Act

            var response = await _client.GetAsync(Endpoint + query);
            var data = await GetDataFromResponseAsync(response);

            // Assert

            Assert.NotEqual("Doe", encryptedLastName);

            Assert.NotNull(data);
            Assert.NotNull(data.LastName);
            Assert.Equal("Doe", data.LastName);
        }
    }
}