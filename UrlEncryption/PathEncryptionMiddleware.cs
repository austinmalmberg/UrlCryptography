using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace UrlEncryption;

/// <summary>
/// Middleware for decrypting URL path values.
/// 
/// <para>
/// This middleware should be added before any routing is performed (i.e. before <c>app.UseRouting()</c>.
/// </para>
/// </summary>
/// <param name="next"></param>
public class PathEncryptionMiddleware(RequestDelegate next)
{
    private readonly RequestDelegate _next = next;

    public async Task InvokeAsync(HttpContext context, IPathEncryption pathEncryption)
    {
        pathEncryption.Decrypt(context);

        await _next(context);

        pathEncryption.Encrypt(context);
    }
}

/// <summary>
/// Extension methods for configuring <see cref="PathEncryptionMiddleware"/>.
/// </summary>
public static class PathDecryptionMiddlewareExtensions
{
    /// <summary>
    /// Adds necessary services for the <see cref="PathEncryptionMiddleware"/> using the default <see cref="PathDecryptionOptions"/> values.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns></returns>
    public static IServiceCollection AddPathEncryption(this IServiceCollection services)
    {
        AddPathEncryption(services, options => { });

        return services;
    }

    /// <summary>
    /// Adds services for the <see cref="PathEncryptionMiddleware"/>.
    /// 
    /// Uses greedy
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions"></param>
    /// <returns></returns>
    public static IServiceCollection AddPathEncryption(this IServiceCollection services, Action<PathDecryptionOptions> configureOptions)
    {
        services.AddDataProtection();
        services.AddTransient<IPathEncryptionDataProtectionProvider, PathDecryptionDataProtectionProvider>();
        services.AddTransient<IPathEncryption, PathEncryptionWithGreedyDecryption>();

        services.Configure<PathDecryptionOptions>(configureOptions);

        return services;
    }

    /// <summary>
    /// <para>
    /// Adds the <see cref="PathEncryptionMiddleware"/>.
    /// </para>
    /// <para>
    /// Must be called before <c>app.UseRouting()</c>.
    /// </para>
    /// </summary>
    /// <param name="app"></param>
    /// <returns></returns>
    public static IApplicationBuilder UsePathEncryption(this IApplicationBuilder app)
    {
        app.UseMiddleware<PathEncryptionMiddleware>();

        return app;
    }

    /// <summary>
    /// <para>
    /// Adds the <see cref="PathEncryptionMiddleware"/> and <see cref="EndpointRoutingMiddleware"/> to the <paramref name="app"/>.
    /// </para>
    /// <para>
    /// Use this in place of <c>app.UseRouting()</c>.
    /// </para>
    /// </summary>
    /// <param name="app"></param>
    /// <returns></returns>
    public static IApplicationBuilder UseRoutingWithPathEncryption(this IApplicationBuilder app)
    {
        app.UsePathEncryption();

        app.UseRouting();

        return app;
    }
}

public class PathDecryptionOptions
{
    /// <summary>
    /// The string used to create the <see cref="IDataProtector"/>.
    /// </summary>
    public string Purpose { get; set; } = typeof(PathEncryptionMiddleware).FullName
        ?? nameof(PathEncryptionMiddleware);

    public bool ShowFullCryptographicException { get; set; } = false;
}

public interface IPathEncryptionDataProtectionProvider
    : ICryptographyMiddlewareDataProtectionProvider
{
}

public class PathDecryptionDataProtectionProvider(
    IDataProtectionProvider provider,
    IOptions<PathDecryptionOptions> pathDecryptionOptions) : IPathEncryptionDataProtectionProvider
{
    private readonly IDataProtectionProvider _provider = provider;
    private readonly PathDecryptionOptions _options = pathDecryptionOptions.Value;

    public IDataProtector CreateProtector() => _provider.CreateProtector(_options.Purpose);
}

/// <summary>
/// An interface that provides path decryption services.
/// </summary>
public interface IPathEncryption
{
    /// <summary>
    /// Decrypts URL path variables.
    /// </summary>
    /// <param name="path"></param>
    /// <returns></returns>
    void Decrypt(HttpContext context);

    /// <summary>
    /// Encrypts URL path variables.
    /// </summary>
    /// <param name="context"></param>
    void Encrypt(HttpContext context);
}

/// <summary>
/// An <see cref="IPathEncryption"/> implementation that attempts to decrypt each path segment.
/// </summary>
/// <param name="dataProtectionProvider"></param>
public class PathEncryptionWithGreedyDecryption(
    IPathEncryptionDataProtectionProvider dataProtectionProvider) : IPathEncryption
{
    private readonly IDataProtector _dataProtector = dataProtectionProvider.CreateProtector();

    public void Encrypt(HttpContext context)
    {
    }

    public void Decrypt(HttpContext context)
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
