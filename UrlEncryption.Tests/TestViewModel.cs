using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;
using UrlEncryption;

namespace UrlEncryption.Tests;

public class TestViewModel
{
    public int? Id { get; set; }

    [FromQuery(Name = "lastName"), Encrypted]
    [JsonPropertyName("lastName")]
    public string? LastName { get; set; }

    [FromQuery(Name = "firstName")]
    [JsonPropertyName("firstName")]
    public string? FirstName { get; set; }

    [FromQuery(Name = "dob"), Encrypted]
    [JsonPropertyName("dob")]
    public DateOnly? DateOfBirth { get; set; }
}

public static class TestViewModelFactory
{
    public static TestViewModel FromQueryCollection(IQueryCollection collection)
    {
        DateOnly? dob = null;
        if (DateOnly.TryParse(collection["dob"], out DateOnly result))
        {
            dob = result;
        }

        return new TestViewModel
        {
            LastName = collection["lastName"],
            FirstName = collection["firstName"],
            DateOfBirth = dob,
        };
    }
}
