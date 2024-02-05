using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using UrlEncryption;
using UrlEncryption.Tests.Fixtures;

namespace UrlEncryption.Tests.Integration
{
    public class RouteTests(WebApplicationFactory<Program> factory)
        : TestFixture(factory)
    {
        private readonly HttpClient _client = factory.CreateClient();

        private string Endpoint<T>(T id) => $"/Routes/{id}";

        [Fact]
        public async void Returns_200OK()
        {
            // Arrange

            string endpoint = Endpoint(1);

            // Act

            var response = await _client.GetAsync(endpoint);

            // Assert

            Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        }


        [Fact]
        public async void EncryptedRouteId_IsDecrypted()
        {
            // Arrange

            IDataProtector dataProtector = Factory.Services
                .GetRequiredService<IPathEncryptionDataProtectionProvider>()
                .CreateProtector();

            string encryptedValue = dataProtector.Protect(1.ToString());

            // Act

            var response = await _client.GetAsync(Endpoint(encryptedValue));

            string? json = await response.Content.ReadAsStringAsync();
            var data = JsonConvert.DeserializeObject<TestViewModel>(json);

            // Assert

            Assert.NotNull(data);
            Assert.NotNull(data.Id);
            Assert.Equal(1, data.Id);
        }
    }
}
