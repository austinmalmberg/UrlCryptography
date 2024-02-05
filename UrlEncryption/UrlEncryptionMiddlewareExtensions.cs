namespace UrlEncryption;

/// <summary>
/// Extension methods for adding cryptography middleware.
/// </summary>
public static class UrlEncryptionMiddlewareExtensions
{
    /// <summary>
    /// Adds services necessary for path and query encryption.
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static IServiceCollection AddUrlEncryption(this IServiceCollection services)
    {
        services.AddQueryEncryption();

        services.AddPathEncryption();

        return services;
    }

    /// <summary>
    /// Adds path and query encryption middleware.
    /// 
    /// <para>
    /// Must be called before <c>app.UseRouting()</c>.
    /// </para>
    /// </summary>
    /// <param name="app"></param>
    /// <returns></returns>
    public static IApplicationBuilder UseUrlEncryption(this IApplicationBuilder app)
    {
        app.UsePathEncryption();

        return app;
    }
}
