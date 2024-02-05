using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System.Reflection;
using System.Security.Cryptography;

namespace UrlEncryption;

/// <summary>
/// An <see cref="IResourceFilter"/> that runs before model binding and sets the <see cref="QueryEncryptionFeature"/> on the request.
/// </summary>
public class QueryCollectionEncryptionFilter : IResourceFilter
{
    public void OnResourceExecuting(ResourceExecutingContext context)
    {
        IQueryFeature queryFeature = new QueryEncryptionFeature(context.HttpContext);
        context.HttpContext.Features.Set<IQueryFeature>(queryFeature);
    }

    public void OnResourceExecuted(ResourceExecutedContext context)
    {
    }
}

/// <summary>
/// Extension methods for configuring query encryption.
/// </summary>
public static class QueryEncryptionMiddlewareExtensions
{
    /// <summary>
    /// Configures necessary services for the middleware to function.
    /// 
    /// Uses default <see cref="QueryEncryptionOptions"/> values.
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static IServiceCollection AddQueryEncryption(this IServiceCollection services)
    {
        services.AddQueryEncryption(options => { });

        return services;
    }

    /// <summary>
    /// Configures necessary services for the middleware to function.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configureOptions"></param>
    /// <returns></returns>
    public static IServiceCollection AddQueryEncryption(this IServiceCollection services, Action<QueryEncryptionOptions> configureOptions)
    {
        services.Configure<MvcOptions>(options =>
        {
            options.Filters.Add<QueryCollectionEncryptionFilter>();
        });

        services.AddDataProtection();
        services.AddTransient<IQueryEncryptionDataProtectionProvider, QueryEncryptionDataProtectionProvider>();

        services.AddTransient<IQueryCollectionProvider, GreedyQueryCollectionDecryptionProvider>();

        services.Configure<QueryEncryptionOptions>(configureOptions);

        return services;
    }
}

public class QueryEncryptionFeature : QueryFeature
{
    public QueryEncryptionFeature(HttpContext context)
        : base(context.Features)
    {
        IQueryCollectionProvider queryCollectionProvider = context.RequestServices
            .GetRequiredService<IQueryCollectionProvider>();

        // overwrite the base query collection
        Query = queryCollectionProvider.GetQueryCollection(context);
    }
}

/// <summary>
/// An interface that provides functionality for generating a new <see cref="IQueryCollection"/> from an existing one. 
/// </summary>
public interface IQueryCollectionProvider
{
    /// <summary>
    /// Creates and returns a new <see cref="IQueryCollection"/> iteration from the existing <paramref name="query"/>.
    /// </summary>
    /// <param name="query">The existing query collection.</param>
    /// <returns>A new iteration on the <paramref name="query"/>.</returns>
    IQueryCollection GetQueryCollection(HttpContext context);
}

/// <summary>
/// Attempts to decode all query parameters.
/// </summary>
/// <param name="dataProtectionProvider"></param>
public class GreedyQueryCollectionDecryptionProvider(
    IQueryEncryptionDataProtectionProvider dataProtectionProvider) : IQueryCollectionProvider
{
    private readonly IDataProtector _dataProtector = dataProtectionProvider.CreateProtector();

    public IQueryCollection GetQueryCollection(HttpContext context)
    {
        Dictionary<string, StringValues> decryptedQueryDictionary = context.Request.Query
            .Select(kv =>
            {
                StringValues value = kv.Value;

                if (!StringValues.IsNullOrEmpty(value))
                {
                    try
                    {
                        value = _dataProtector.Unprotect(value!);
                    }
                    catch (CryptographicException) { }
                }

                return new KeyValuePair<string, StringValues>(kv.Key, value);
            }).ToDictionary();

        return new QueryCollection(decryptedQueryDictionary);
    }
}


/// <summary>
/// Attempts to decode query parameters for the action marked with the <see cref="EncryptedAttribute"/>.
/// </summary>
/// <param name="logger"></param>
/// <param name="dataProtectionProvider"></param>
/// <param name="decryptionOptions"></param>
public class DynamicQueryCollectionDecryptionProvider(
    ILogger<DynamicQueryCollectionDecryptionProvider> logger,
    IQueryEncryptionDataProtectionProvider dataProtectionProvider,
    IOptions<QueryEncryptionOptions> decryptionOptions) : IQueryCollectionProvider
{
    private readonly ILogger<DynamicQueryCollectionDecryptionProvider> _logger = logger;
    private readonly IDataProtector _dataProtector = dataProtectionProvider.CreateProtector();
    private readonly QueryEncryptionOptions _decryptionOptions = decryptionOptions.Value;

    public IQueryCollection GetQueryCollection(HttpContext context)
    {
        Dictionary<string, StringValues> queryDictionary = new Dictionary<string, StringValues>(context.Request.Query);

        // TODO: Get ActionDescriptor parameters
        // Not currently possible since the middleware is added before routing
        IList<ParameterDescriptor> parameterDescriptors = [];

        HashSet<string> keysWithErrors = [];

        List<QueryParameterDecryptionContext> queryParameterDecryptionContexts = [];

        foreach (ControllerParameterDescriptor parameterDescriptor in parameterDescriptors)
        {
            if (parameterDescriptor == null) continue;

            // TODO: find more reliable way to determine whether this is complex object
            if (parameterDescriptor.ParameterType.IsClass &&
                parameterDescriptor.ParameterType != typeof(string))
            {
                var nestedContexts = GetDecryptionContexts(parameterDescriptor.ParameterType
                    .GetProperties(BindingFlags.Instance | BindingFlags.Public));

                queryParameterDecryptionContexts.AddRange(nestedContexts);
            }
            else
            {
                if (parameterDescriptor.ParameterInfo.Name == null) continue;

                EncryptedAttribute? decryptAttribute = parameterDescriptor.ParameterInfo.GetCustomAttribute<EncryptedAttribute>();

                if (decryptAttribute == null) continue;

                FromQueryAttribute? fromQueryAttribute = parameterDescriptor.ParameterInfo.GetCustomAttribute<FromQueryAttribute>();

                // Resolve the query parameter name if different from the action parameter name
                // TODO: ensure upper/lower case names have the intended result
                string name = fromQueryAttribute?.Name ?? parameterDescriptor.ParameterInfo.Name;

                var queryDecryptionContext = new QueryParameterDecryptionContext
                {
                    Attribute = decryptAttribute,
                    Name = name
                };

                queryParameterDecryptionContexts.Add(queryDecryptionContext);
            }
        }

        foreach (QueryParameterDecryptionContext queryParameterDecryptionContext in queryParameterDecryptionContexts)
        {
            string name = queryParameterDecryptionContext.Name;

            if (!queryDictionary.ContainsKey(name)) continue;
            if (string.IsNullOrEmpty(queryDictionary[name]!)) continue;

            try
            {
                queryDictionary[name] = _dataProtector.Unprotect(queryDictionary[name]!);
            }
            catch (CryptographicException)
            {
                // resolve whether the warning should be displayed
                bool ignoreWarning = _decryptionOptions.IgnoreUnencryptedQueryParameterWarnings || queryParameterDecryptionContext.Attribute.IgnoreWarning;

                if (!ignoreWarning) keysWithErrors.Add(name);
            }
        }

        if (keysWithErrors.Count > 0)
        {
            _logger.LogWarning("Errors occurred when attempting to decode one or more query parameters. This generally occurs because the parameter was not encrypted to begin with. Parameters: {0}", keysWithErrors);
        }

        return new QueryCollection(queryDictionary);
    }

    private IEnumerable<QueryParameterDecryptionContext> GetDecryptionContexts(PropertyInfo[] propertyInfo)
    {
        return propertyInfo
            .SelectMany(GetDecryptionContexts);
    }

    /// <summary>
    /// Returns a resursive list of <see cref="QueryParameterDecryptionContext"/> for the given <paramref name="propertyInfo"/>.
    /// </summary>
    /// <param name="propertyInfo"></param>
    /// <returns></returns>
    private IEnumerable<QueryParameterDecryptionContext> GetDecryptionContexts(PropertyInfo propertyInfo)
    {
        List<QueryParameterDecryptionContext> result = [];

        if (propertyInfo.PropertyType.IsClass && propertyInfo.PropertyType != typeof(string))
        {

            PropertyInfo[] propertyInfos = propertyInfo.PropertyType
                .GetProperties(BindingFlags.Instance | BindingFlags.Public);

            foreach (var nestedPropertyInfo in propertyInfos)
            {
                var nestedResult = GetDecryptionContexts(nestedPropertyInfo);

                result.AddRange(nestedResult);
            }
        }
        else
        {
            EncryptedAttribute? attribute = propertyInfo.GetCustomAttribute<EncryptedAttribute>();

            if (attribute != null)
            {
                string name = propertyInfo.GetCustomAttribute<FromQueryAttribute>()?.Name
                    ?? propertyInfo.Name;

                QueryParameterDecryptionContext context = new QueryParameterDecryptionContext
                {
                    Attribute = attribute,
                    Name = name,
                };

                result.Add(context);
            }
        }

        return result;
    }

    private class QueryParameterDecryptionContext
    {
        public required string Name { get; set; }

        public required EncryptedAttribute Attribute { get; set; }
    }
}

public class QueryEncryptionOptions
{
    /// <summary>
    /// Gets or sets the purpose used by the <see cref="IQueryEncryptionDataProtectionProvider"/> to encrypt and decrypt query parameters.
    /// 
    /// <para>
    /// See <see cref="IDataProtectionProvider.CreateProtector(string)"/>.
    /// </para>
    /// </summary>
    public string Purpose { get; set; } = typeof(QueryEncryptionOptions).FullName
        ?? nameof(QueryEncryptionOptions);

    public bool IgnoreUnencryptedQueryParameterWarnings { get; set; } = false;

    [Obsolete("TODO: implement")]
    public bool EncryptEntireQueryString { get; set; } = false;
}

public interface IQueryEncryptionDataProtectionProvider : ICryptographyMiddlewareDataProtectionProvider { }

public class QueryEncryptionDataProtectionProvider(
    IDataProtectionProvider provider,
    IOptions<QueryEncryptionOptions> queryEncryptionOptions) : IQueryEncryptionDataProtectionProvider
{
    private readonly IDataProtectionProvider _provider = provider;
    private readonly QueryEncryptionOptions _options = queryEncryptionOptions.Value;

    public IDataProtector CreateProtector() => _provider.CreateProtector(_options.Purpose);
}
