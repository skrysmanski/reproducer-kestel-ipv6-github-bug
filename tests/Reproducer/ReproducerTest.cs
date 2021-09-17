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
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

using AppMotor.CliApp.CommandLine;
using AppMotor.Core.Exceptions;
using AppMotor.Core.IO;
using AppMotor.Core.Logging;
using AppMotor.Core.Net;
using AppMotor.Core.Net.Http;
using AppMotor.Core.Utils;

using JetBrains.Annotations;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.EnvironmentVariables;
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

            private readonly ITestOutputHelper _testOutputHelper;

            public TestHttpServerCommand(HttpServerPort testPort, ITestOutputHelper testOutputHelper)
            {
                this._testPort = testPort;
                this._testOutputHelper = testOutputHelper;
            }

            private async Task<int> Execute(CancellationToken cancellationToken)
            {
                var hostBuilderFactory = new TestHostBuilderFactory()
                {
                    LoggingConfigurationProvider = (ctx, builder) =>
                    {
                        ctx.Configuration["Logging:LogLevel:Default"] = "Debug";
                        //ctx.Configuration["Logging:LogLevel:Default"] = "Trace";
                        builder.AddXUnitLogger(this._testOutputHelper);
                    },
                };

                IHostBuilder hostBuilder = hostBuilderFactory.CreateHostBuilder();

                hostBuilder.ConfigureWebHostDefaults(webBuilder => // Create the HTTP host
                {
                    // Clear any "pre-defined" list of URLs (otherwise there will be a warning when
                    // this app runs).
                    webBuilder.UseUrls("");

                    // Configure Kestrel.
                    webBuilder.UseKestrel(ConfigureKestrel);

                    // Use our "Startup" class for any further configuration.
                    webBuilder.UseStartup<Startup>();
                });

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

            private void ConfigureKestrel(KestrelServerOptions options)
            {
                static void Configure(ListenOptions listenOptions)
                {
                    listenOptions.UseConnectionLogging();
                }

                switch (this._testPort.ListenAddress)
                {
                    case SocketListenAddresses.Any:
                        switch (this._testPort.IPVersion)
                        {
                            case IPVersions.IPv4:
                                options.Listen(IPAddress.Any, this._testPort.Port, Configure);
                                break;
                            case IPVersions.IPv6:
                                options.Listen(IPAddress.IPv6Any, this._testPort.Port, Configure);
                                break;
                            case IPVersions.DualStack:
                                options.ListenAnyIP(this._testPort.Port, Configure);
                                break;
                            default:
                                throw new UnexpectedSwitchValueException(nameof(this._testPort.IPVersion), this._testPort.IPVersion);
                        }
                        break;

                    case SocketListenAddresses.Loopback:
                        switch (this._testPort.IPVersion)
                        {
                            case IPVersions.IPv4:
                                options.Listen(IPAddress.Loopback, this._testPort.Port, Configure);
                                break;
                            case IPVersions.IPv6:
                                options.Listen(IPAddress.IPv6Loopback, this._testPort.Port, Configure);
                                break;
                            case IPVersions.DualStack:
                                options.ListenLocalhost(this._testPort.Port, Configure);
                                break;
                            default:
                                throw new UnexpectedSwitchValueException(nameof(this._testPort.IPVersion), this._testPort.IPVersion);
                        }
                        break;

                    default:
                        throw new UnexpectedSwitchValueException(nameof(this._testPort.ListenAddress), this._testPort.ListenAddress);
                }
            }
        }

        private sealed class TestHostBuilderFactory
        {
            /// <summary>
            /// The configures the <see cref="IServiceProviderFactory{TContainerBuilder}"/> (i.e. the dependency injection system) by
            /// calling one of the <c>UseServiceProviderFactory()</c> methods on the provided <see cref="IHostBuilder"/> instance.
            /// Defaults to <see cref="ApplyDefaultServiceProviderConfiguration"/>.
            /// </summary>
            /// <remarks>
            /// <para>For more details, see: https://docs.microsoft.com/en-us/dotnet/core/extensions/dependency-injection </para>
            ///
            /// <para>This is an action (rather than a function that returns the service provider) because <see cref="IServiceProviderFactory{TContainerBuilder}"/>
            /// is generic and its type parameter may not always be <see cref="IServiceCollection"/> for all service providers - and we could
            /// not provide this flexibility with a function (because then we would need to hard code the type of <c>TContainerBuilder</c>).</para>
            /// </remarks>
            [PublicAPI]
            public Action<IHostBuilder> ServiceProviderConfigurationProvider { get; init; } = ApplyDefaultServiceProviderConfiguration;

            /// <summary>
            /// Configures the configuration providers (e.g. settings files) that provide configuration values for the application. Defaults to
            /// <see cref="ApplyDefaultAppConfiguration"/>.
            /// </summary>
            /// <remarks>
            /// For more details, see: https://docs.microsoft.com/en-us/dotnet/core/extensions/configuration
            /// </remarks>
            [PublicAPI]
            public Action<HostBuilderContext, IConfigurationBuilder>? AppConfigurationProvider { get; init; } = ApplyDefaultAppConfiguration;

            /// <summary>
            /// The name of the configuration section (<see cref="IConfiguration.GetSection"/>) used to configure log levels, etc. for
            /// all loggers that are enabled via <see cref="LoggingConfigurationProvider"/>. Defaults to "Logging" (the .NET default).
            /// Can be set to <c>null</c> to disable setting the section.
            /// </summary>
            /// <remarks>
            /// For more details, see: https://docs.microsoft.com/en-us/dotnet/core/extensions/logging#configure-logging
            /// </remarks>
            [PublicAPI]
            public string? LoggingConfigurationSectionName { get; init; } = "Logging";

            /// <summary>
            /// Configures the logging for the application. You can use the various <c>loggingBuilder.Add...()</c>
            /// methods to configure the desired logging. Defaults to <see cref="ApplyDefaultLoggingConfiguration"/>.
            /// Note that the configuration section for configuring the log levels etc. is specified via
            /// <see cref="LoggingConfigurationSectionName"/>.
            /// </summary>
            /// <remarks>
            /// For more details, see https://docs.microsoft.com/en-us/dotnet/core/extensions/logging-providers and
            /// https://docs.microsoft.com/en-us/dotnet/core/extensions/console-log-formatter
            /// </remarks>
            [PublicAPI]
            public Action<HostBuilderContext, ILoggingBuilder>? LoggingConfigurationProvider { get; init; } = ApplyDefaultLoggingConfiguration;

            /// <summary>
            /// The content root to use. Defaults to <see cref="DirectoryPath.GetCurrentDirectory"/>. Can later be accessed
            /// via <see cref="IHostEnvironment.ContentRootFileProvider"/>. Can be <c>null</c> in which case no content root
            /// will be set (explicitly).
            /// </summary>
            /// <remarks>
            /// For more details on the content root, see: https://docs.microsoft.com/en-us/aspnet/core/fundamentals/#content-root
            /// </remarks>
            /// <seealso cref="HostingHostBuilderExtensions.UseContentRoot"/>
            [PublicAPI]
            public DirectoryPath? ContentRoot { get; init; } = DirectoryPath.GetCurrentDirectory();

            public IHostBuilder CreateHostBuilder()
            {
                var hostBuilder = new HostBuilder();

                var contentRoot = this.ContentRoot;
                if (contentRoot is not null)
                {
                    hostBuilder.UseContentRoot(contentRoot.Value.Value);
                }

                this.ServiceProviderConfigurationProvider(hostBuilder);

                if (this.AppConfigurationProvider is not null)
                {
                    hostBuilder.ConfigureAppConfiguration(this.AppConfigurationProvider);
                }

                if (this.LoggingConfigurationSectionName is not null)
                {
                    hostBuilder.ConfigureLogging((context, loggingBuilder) =>
                    {
                        // Load the logging configuration from the specified configuration section.
                        loggingBuilder.AddConfiguration(context.Configuration.GetSection(this.LoggingConfigurationSectionName));
                    });
                }

                if (this.LoggingConfigurationProvider is not null)
                {
                    hostBuilder.ConfigureLogging(this.LoggingConfigurationProvider);
                }

                return hostBuilder;
            }

            /// <summary>
            /// Creates a <see cref="DefaultServiceProviderFactory"/> with all scope validations enabled (see <see cref="ServiceProviderOptions.ValidateScopes"/>)
            /// and sets it as service provider.
            /// </summary>
            /// <seealso cref="ServiceProviderConfigurationProvider"/>
            [PublicAPI]
            public static void ApplyDefaultServiceProviderConfiguration(IHostBuilder hostBuilder)
            {
                var options = new ServiceProviderOptions()
                {
                    // Enable all validations
                    ValidateScopes = true,
                    ValidateOnBuild = true,
                };

                hostBuilder.UseServiceProviderFactory(new DefaultServiceProviderFactory(options));
            }

            /// <summary>
            /// Enables the configuration files "appsettings.json" and "appsettings.{<see cref="HostBuilderContext.HostingEnvironment"/>}.json".
            /// Also enables loading configuration values from the environment variables (via <see cref="EnvironmentVariablesConfigurationSource"/>).
            /// </summary>
            /// <remarks>
            /// Whether the .json configuration files are reloaded when changed is configured via the "hostBuilder:reloadConfigOnChange" configuration
            /// value. The default is <c>true</c>.
            /// </remarks>
            /// <seealso cref="AppConfigurationProvider"/>
            [PublicAPI]
            public static void ApplyDefaultAppConfiguration(HostBuilderContext context, IConfigurationBuilder configurationBuilder)
            {
                IHostEnvironment env = context.HostingEnvironment;

                bool reloadOnChange = context.Configuration.GetValue("hostBuilder:reloadConfigOnChange", defaultValue: true);

                configurationBuilder.AddJsonFile("appsettings.json", optional: true, reloadOnChange: reloadOnChange);
                configurationBuilder.AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange: reloadOnChange);

                configurationBuilder.Add(new EnvironmentVariablesConfigurationSource());
            }

            /// <summary>
            /// Enables Console logging.
            /// </summary>
            /// <seealso cref="LoggingConfigurationProvider"/>
            /// <seealso cref="LoggingConfigurationSectionName"/>
            [PublicAPI]
            public static void ApplyDefaultLoggingConfiguration(HostBuilderContext context, ILoggingBuilder loggingBuilder)
            {
                loggingBuilder.AddConsole();
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
