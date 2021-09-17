#region License
// Copyright 2021 AppMotor Framework (https://github.com/skrysmanski/AppMotor)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#endregion

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using AppMotor.CliApp.CommandLine;
using AppMotor.CliApp.CommandLine.Hosting;
using AppMotor.Core.Certificates;
using AppMotor.Core.Exceptions;
using AppMotor.Core.Logging;
using AppMotor.Core.Net;
using AppMotor.Core.Net.Http;
using AppMotor.Core.Utils;

using JetBrains.Annotations;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using Reproducer.Utils;

using Shouldly;

using Xunit;
using Xunit.Abstractions;

namespace Reproducer
{
    public sealed class ReproducerTests
    {
        private static readonly Lazy<string> s_ownIPv6Address = new(GetLocalIpAddress);

        private ITestOutputHelper TestConsole { get; }

        public ReproducerTests(ITestOutputHelper testOutputHelper)
        {
            this.TestConsole = testOutputHelper;
        }

        [Theory]
        [InlineData(SocketListenAddresses.Loopback, "::1")]
        [InlineData(SocketListenAddresses.Any, "::1")]
        [InlineData(SocketListenAddresses.Any, "public")]
        public async Task TestConnection(SocketListenAddresses listenAddress, string targetHostIpAddress)
        {
            int testPort = ServerPortProvider.GetNextTestPort();

            using var cts = new CancellationTokenSource();

            var serverPort = new HttpServerPort(listenAddress, testPort)
            {
                IPVersion = IPVersions.IPv6,
            };
            var app = new CliApplicationWithCommand(new TestHttpServerCommand(serverPort, this.TestConsole));
            Task appTask = app.RunAsync(cts.Token);

            try
            {
                using var httpClient = HttpClientFactory.CreateHttpClient();

                if (targetHostIpAddress == "public")
                {
                    targetHostIpAddress = s_ownIPv6Address.Value;
                }

                await ExecuteRequest(httpClient, targetHostIpAddress, testPort);
            }
            finally
            {
                this.TestConsole.WriteLine("");

                cts.Cancel();

                await appTask;
            }
        }

        private async Task ExecuteRequest(HttpClient httpClient, string targetHostIpAddress, int testPort)
        {
            this.TestConsole.WriteLine("");
            this.TestConsole.WriteLine($"Running query against: {targetHostIpAddress}");

            var requestUri = new Uri($"http://[{targetHostIpAddress}]:{testPort}/api/ping");

            this.TestConsole.WriteLine($"IDN host: {requestUri.IdnHost}");

            var requestMessage = new HttpRequestMessage(HttpMethod.Get, requestUri);

            HttpResponseMessage response;
            try
            {
                response = await httpClient.SendAsync(requestMessage);
            }
            catch (Exception ex)
            {
                this.TestConsole.WriteLine(ex.ToStringExtended());
                throw;
            }

            try
            {
                response.EnsureSuccessStatusCode();
            }
            catch (Exception)
            {
                var errorResponseString = await response.Content.ReadAsStringAsync();
                this.TestConsole.WriteLine("[START ERROR RESPONSE]");
                this.TestConsole.WriteLine(errorResponseString);
                this.TestConsole.WriteLine("[END ERROR RESPONSE]");
                throw;
            }

            var responseString = await response.Content.ReadAsStringAsync();

            responseString.ShouldBe($"Caller ip address family: {AddressFamily.InterNetworkV6}");

            this.TestConsole.WriteLine("Done");
        }

        [MustUseReturnValue]
        private static string GetLocalIpAddress()
        {
            foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (networkInterface.OperationalStatus != OperationalStatus.Up || !networkInterface.Supports(NetworkInterfaceComponent.IPv6))
                {
                    continue;
                }

                var ipProperties = networkInterface.GetIPProperties();

                if (ipProperties.GatewayAddresses.Count == 0)
                {
                    continue;
                }

                foreach (var ip in ipProperties.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily != AddressFamily.InterNetworkV6 || IPAddress.IsLoopback(ip.Address))
                    {
                        continue;
                    }

                    return ip.Address.ToString();
                }
            }

            throw new InvalidOperationException("No usable IPv6 network interface exists.");
        }

        private sealed class TestHttpServerCommand : CliCommand
        {
            protected override CliCommandExecutor Executor => new(Execute);

            private readonly HttpServerPort _testPort;

            private IHostBuilderFactory HostBuilderFactory { get; }

            public TestHttpServerCommand(HttpServerPort testPort, ITestOutputHelper testOutputHelper)
            {
                this._testPort = testPort;

                this.HostBuilderFactory = new DefaultHostBuilderFactory()
                {
                    LoggingConfigurationProvider = (ctx, builder) =>
                    {
                        ctx.Configuration["Logging:LogLevel:Default"] = "Debug";
                        //ctx.Configuration["Logging:LogLevel:Default"] = "Trace";
                        builder.AddXUnitLogger(testOutputHelper);
                    },
                };
            }

            private async Task<int> Execute(CancellationToken cancellationToken)
            {
                IHostBuilder hostBuilder = this.HostBuilderFactory.CreateHostBuilder();

                ConfigureApplication(hostBuilder);

                IHost host = hostBuilder.Build();

                try
                {
                    await host.StartAsync(cancellationToken).ConfigureAwait(false);

                    await host.WaitForShutdownAsync(cancellationToken).ConfigureAwait(false);

                    return 0;
                }
                finally
                {
                    await DisposeHelper.DisposeWithAsyncSupport(host).ConfigureAwait(false);
                }
            }

            private void ConfigureApplication(IHostBuilder hostBuilder)
            {
                hostBuilder.ConfigureWebHostDefaults(webBuilder => // Create the HTTP host
                {
                    // Clear any "pre-defined" list of URLs (otherwise there will be a warning when
                    // this app runs).
                    webBuilder.UseUrls("");

                    // Configure Kestrel.
                    webBuilder.UseKestrel(ConfigureKestrel);

                    // Use our "Startup" class for any further configuration.
                    webBuilder.UseStartup(CreateStartupClass);
                });
            }

            private void ConfigureKestrel(KestrelServerOptions options)
            {
                var logger = options.ApplicationServices.GetRequiredService<ILogger<TestHttpServerCommand>>();

                options.ConfigureHttpsDefaults(configureOptions =>
                {
                    configureOptions.SslProtocols = TlsSettings.EnabledTlsProtocols;
                });

                foreach (var serverPort in GetServerPorts())
                {
                    Action<ListenOptions> configure;

                    if (serverPort is HttpsServerPort httpsServerPort)
                    {
                        var certificate = httpsServerPort.CertificateProvider();

                        if (OperatingSystem.IsWindows())
                        {
                            //
                            // Workaround for error "No credentials are available in the security package".
                            //
                            // Basically, the problem is that on Windows TLS is handled out-of-process. But
                            // if the private key for certificate only in-memory of the current process,
                            // the out-of-process TLS handler is unable to get the private key (see
                            // https://github.com/dotnet/runtime/issues/23749#issuecomment-485947319 )
                            //
                            // Full discussion: https://github.com/dotnet/runtime/issues/23749
                            //
                            // Workaround: https://github.com/dotnet/runtime/issues/23749#issuecomment-739895373
                            //
                            var originalCertificate = certificate;

                            byte[] exportedCertificateBytes = ((X509Certificate2)originalCertificate).Export(X509ContentType.Pkcs12);
    #pragma warning disable CA2000 // Dispose objects before losing scope
                            var reimportedCertificate = new X509Certificate2(exportedCertificateBytes, password: (string?)null, X509KeyStorageFlags.Exportable);
                            certificate = new TlsCertificate(reimportedCertificate, allowPrivateKeyExport: true);
    #pragma warning restore CA2000 // Dispose objects before losing scope

                            if (httpsServerPort.CertificateProviderCallerOwnsCertificates)
                            {
                                originalCertificate.Dispose();
                            }
                        }

                        logger.LogInformation("Using certificate '{thumbprint}' for server port {port}.", certificate.Thumbprint, httpsServerPort.Port);

                        configure = listenOptions =>
                        {
                            listenOptions.UseHttps(certificate);
                        };
                    }
                    else
                    {
                        configure = listenOptions =>
                        {
                            listenOptions.UseConnectionLogging();
                        };
                    }

                    switch (serverPort.ListenAddress)
                    {
                        case SocketListenAddresses.Any:
                            switch (serverPort.IPVersion)
                            {
                                case IPVersions.IPv4:
                                    options.Listen(IPAddress.Any, serverPort.Port, configure);
                                    break;
                                case IPVersions.IPv6:
                                    options.Listen(IPAddress.IPv6Any, serverPort.Port, configure);
                                    break;
                                case IPVersions.DualStack:
                                    options.ListenAnyIP(serverPort.Port, configure);
                                    break;
                                default:
                                    throw new UnexpectedSwitchValueException(nameof(serverPort.IPVersion), serverPort.IPVersion);
                            }
                            break;

                        case SocketListenAddresses.Loopback:
                            switch (serverPort.IPVersion)
                            {
                                case IPVersions.IPv4:
                                    options.Listen(IPAddress.Loopback, serverPort.Port, configure);
                                    break;
                                case IPVersions.IPv6:
                                    options.Listen(IPAddress.IPv6Loopback, serverPort.Port, configure);
                                    break;
                                case IPVersions.DualStack:
                                    options.ListenLocalhost(serverPort.Port, configure);
                                    break;
                                default:
                                    throw new UnexpectedSwitchValueException(nameof(serverPort.IPVersion), serverPort.IPVersion);
                            }
                            break;

                        default:
                            throw new UnexpectedSwitchValueException(nameof(serverPort.ListenAddress), serverPort.ListenAddress);
                    }
                }
            }

            private IEnumerable<HttpServerPort> GetServerPorts()
            {
                yield return this._testPort;
            }

            private static object CreateStartupClass(WebHostBuilderContext context)
            {
                return new Startup();
            }
        }

        private sealed class Startup
        {
            public void Configure(IApplicationBuilder app)
            {
                // Enable routing feature; required for defining endpoints below.
                // See: https://docs.microsoft.com/en-us/aspnet/core/fundamentals/routing#routing-basics
                app.UseRouting();

                // Define endpoints (invokable actions). Requires call to "UseRouting()" above.
                // See: https://docs.microsoft.com/en-us/aspnet/core/fundamentals/routing#endpoint
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/api/ping", async context =>
                    {
                        IPAddress? callerIpAddress = context.Request.HttpContext.Connection.RemoteIpAddress;
                        callerIpAddress.ShouldNotBeNull();

                        var addressFamily = callerIpAddress.IsIPv4MappedToIPv6 ? AddressFamily.InterNetwork : callerIpAddress.AddressFamily;

                        await context.Response.WriteAsync($"Caller ip address family: {addressFamily}");
                    });
                });
            }
        }
    }
}
