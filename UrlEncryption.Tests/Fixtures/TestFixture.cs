using Microsoft.AspNetCore.Mvc.Testing;

namespace UrlEncryption.Tests.Fixtures
{
    public class TestFixture : IClassFixture<WebApplicationFactory<Program>>
    {
        protected readonly WebApplicationFactory<Program> Factory;

        public TestFixture(WebApplicationFactory<Program> factory)
        {
            Factory = factory;
        }
    }
}
