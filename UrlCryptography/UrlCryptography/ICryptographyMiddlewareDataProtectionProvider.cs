using Microsoft.AspNetCore.DataProtection;

namespace UrlCryptography;

/// <summary>
/// An <see cref="IDataProtectionProvider"/> wrapper used to create <see cref="IDataProtector"/> instances using a predefined purpose.
/// </summary>
public interface ICryptographyMiddlewareDataProtectionProvider
{
    /// <summary>
    /// Creates a new <see cref="IDataProtector"/>.
    /// </summary>
    /// <returns></returns>
    IDataProtector CreateProtector();
}
