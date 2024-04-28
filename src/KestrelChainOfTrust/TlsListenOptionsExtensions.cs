using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace KestrelChainOfTrust;

public static class TlsListenOptionsExtensions
{
    public static ListenOptions UseHttpsWithFullChain(this ListenOptions listenOptions, string certPath, string keyPath)
    {
        var leafCertWithKey = X509Certificate2.CreateFromPemFile(certPath, keyPath);

        var fullChain = new X509Certificate2Collection();
        fullChain.ImportFromPemFile(certPath);

        var options = new SslServerAuthenticationOptions
        {
            ServerCertificateContext = SslStreamCertificateContext.Create(leafCertWithKey, fullChain, offline: true)
        };

        return listenOptions.UseHttps(new TlsHandshakeCallbackOptions
        {
            OnConnection = context => new ValueTask<SslServerAuthenticationOptions>(options)
        });
    }
}