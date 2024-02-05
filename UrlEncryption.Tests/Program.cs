using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using UrlEncryption;
using UrlEncryption.Tests;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddUrlEncryption();

var app = builder.Build();

app.UseUrlEncryption();

app.UseRouting();

app.MapControllers();

app.Run();


// Exposes the application for integration testing
public partial class Program { }

[ApiController]
[Route("[action]")]
public class TestController : ControllerBase
{
    public IActionResult Query()
    {
        var model = TestViewModelFactory.FromQueryCollection(HttpContext.Request.Query);

        return Ok(model);
    }

    [HttpGet("{id:int}")]
    public IActionResult Routes(int? id)
    {
        var model = new TestViewModel
        {
            Id = id,
        };

        return Ok(model);
    }
}
