using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace UrlCryptography;

/// <summary>
/// Middleware for decrypting URL path values.
/// 
/// <para>
/// This middleware should be added before any routing is performed (i.e. before <c>app.UseRouting()</c>.
/// </para>
/// </summary>
/// <param name="next"></param>
public class PathDecryptionMiddleware(RequestDelegate next)
{
    private readonly RequestDelegate _next = next;

    public async Task InvokeAsync(HttpContext context, IPathDecryption pathDecryption)
    {
        pathDecryption.UpdateContext(context);

        await _next(context);
    }
}

/// <summary>
/// Extension methods for configuring <see cref="PathDecryptionMiddleware"/>.
/// </summary>
public static class PathDecryptionMiddlewareExtensions
{
    /// <summary>
    /// Adds necessary services for the <see cref="PathDecryptionMiddleware"/> using the default <see cref="PathDecryptionOptions"/> values.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns></returns>
    public static IServiceCollection AddPathDecryption(this IServiceCollection services)
    {
        AddPathDecryption(services, options => { });

        return services;
    }

    /// <summary>
    /// Adds services for the <see cref="PathDecryptionMiddleware"/>.
    /// 
    /// Uses greedy
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions"></param>
    /// <returns></returns>
    public static IServiceCollection AddPathDecryption(this IServiceCollection services, Action<PathDecryptionOptions> configureOptions)
    {
        services.AddDataProtection();
        services.AddTransient<IPathCryptographyDataProtectionProvider, PathDecryptionDataProtectionProvider>();
        services.AddTransient<IPathDecryption, GreedyPathDecryption>();

        services.Configure<PathDecryptionOptions>(configureOptions);

        return services;
    }

    /// <summary>
    /// <para>
    /// Adds the <see cref="PathDecryptionMiddleware"/>.
    /// </para>
    /// <para>
    /// Must be called before <c>app.UseRouting()</c>.
    /// </para>
    /// </summary>
    /// <param name="app"></param>
    /// <returns></returns>
    public static IApplicationBuilder UsePathDecryption(this IApplicationBuilder app)
    {
        app.UseMiddleware<PathDecryptionMiddleware>();

        return app;
    }

    /// <summary>
    /// <para>
    /// Adds the <see cref="PathDecryptionMiddleware"/> and <see cref="EndpointRoutingMiddleware"/> to the <paramref name="app"/>.
    /// </para>
    /// <para>
    /// Use this in place of <c>app.UseRouting()</c>.
    /// </para>
    /// </summary>
    /// <param name="app"></param>
    /// <returns></returns>
    public static IApplicationBuilder UseRoutingWithDecryption(this IApplicationBuilder app)
    {
        app.UsePathDecryption();

        app.UseRouting();

        return app;
    }
}

public class PathDecryptionOptions
{
    public string Purpose { get; set; } = typeof(PathDecryptionMiddleware).FullName
        ?? nameof(PathDecryptionMiddleware);

    public bool ShowFullCryptographicException { get; set; } = false;
}

public interface IPathCryptographyDataProtectionProvider
    : ICryptographyMiddlewareDataProtectionProvider
{
}

public class PathDecryptionDataProtectionProvider(
    IDataProtectionProvider provider,
    IOptions<PathDecryptionOptions> pathDecryptionOptions) : IPathCryptographyDataProtectionProvider
{
    private readonly IDataProtectionProvider _provider = provider;
    private readonly PathDecryptionOptions _options = pathDecryptionOptions.Value;

    public IDataProtector CreateProtector() => _provider.CreateProtector(_options.Purpose);
}

/// <summary>
/// An interface that provides path decryption services.
/// </summary>
public interface IPathDecryption
{
    /// <summary>
    /// Decrypts 
    /// </summary>
    /// <param name="path"></param>
    /// <returns></returns>
    void UpdateContext(HttpContext context);
}

/// <summary>
/// An <see cref="IPathProvider"/> implementation that attempts to decrypt each path segment.
/// </summary>
/// <param name="dataProtectionProvider"></param>
public class GreedyPathDecryption(
    IPathCryptographyDataProtectionProvider dataProtectionProvider) : IPathDecryption
{
    private readonly IDataProtector _dataProtector = dataProtectionProvider.CreateProtector();

    public void UpdateContext(HttpContext context)
    {
        PathString? decryptedPath = DecryptPath(context.Request.Path);

        if (decryptedPath != null)
        {
            // Update path
            context.Request.Path = decryptedPath.Value;
        }
    }

    private PathString? DecryptPath(PathString path)
    {
        return path.Value?
            .Split('/')
            .Select(segment =>
            {
                try
                {
                    return _dataProtector.Unprotect(segment);
                }
                catch (CryptographicException)
                {
                    return segment;
                }
            })
            .Where(segment => !string.IsNullOrWhiteSpace(segment))
            .Aggregate("", (prev, next) => $"{prev}/{next}");
    }
}
