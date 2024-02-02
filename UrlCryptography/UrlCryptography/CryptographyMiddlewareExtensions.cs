namespace UrlCryptography;

/// <summary>
/// Extension methods for adding cryptography middleware.
/// </summary>
public static class CryptographyMiddlewareExtensions
{
    /// <summary>
    /// Adds services necessary for <see cref="PathDecryptionMiddleware"/> and <see cref="QueryDecryptionMiddleware"/>.
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static IServiceCollection AddUrlCryptography(this IServiceCollection services)
    {
        services.AddQueryDecryption();

        services.AddPathDecryption();

        return services;
    }

    /// <summary>
    /// Adds <see cref="PathDecryptionMiddleware"/> <see cref="QueryDecryptionMiddleware"/>.
    /// 
    /// <para>
    /// Must be called before <c>app.UseRouting()</c>.
    /// </para>
    /// </summary>
    /// <param name="app"></param>
    /// <returns></returns>
    public static IApplicationBuilder UseUrlCryptography(this IApplicationBuilder app)
    {
        app.UsePathDecryption();

        return app;
    }
}
