using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

using JetBrains.Annotations;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
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
        private static readonly HttpClient s_httpClient = new();

        private ITestOutputHelper TestConsole { get; }

        private readonly int _testPort;

        public ReproducerTests(ITestOutputHelper testOutputHelper)
        {
            this.TestConsole = testOutputHelper;
            this._testPort = ServerPortProvider.GetNextTestPort();
        }

        public static IEnumerable<object[]> TestData
        {
            get
            {
                yield return new object[] { "::1" };
                foreach (var address in GetOwnLinkLocalIpV6Addresses())
                {
                    yield return new object[] { address };
                }
            }
        }

        [Theory]
        [MemberData(nameof(TestData))]
        public async Task TestConnection(string targetHostIpAddress)
        {
            using var cts = new CancellationTokenSource();

            Task appTask = RunServerAsync(cts.Token);

            try
            {
                await ExecuteRequest(targetHostIpAddress);
            }
            finally
            {
                cts.Cancel();

                await appTask;
            }
        }

        private async Task ExecuteRequest(string targetHostIpAddress)
        {
            //targetHostIpAddress = System.Text.RegularExpressions.Regex.Replace(targetHostIpAddress, @"^(.+)%\d+$", "$1");

            var requestUri = new Uri($"http://[{targetHostIpAddress}]:{this._testPort}/api/ping");

            this.TestConsole.WriteLine($"\n[CLIENT] Target host: {targetHostIpAddress}\n[CLIENT] Running query against: {requestUri}\n");

            var requestMessage = new HttpRequestMessage(HttpMethod.Get, requestUri);

            HttpResponseMessage response = await s_httpClient.SendAsync(requestMessage);

            try
            {
                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                this.TestConsole.WriteLine($"\n[CLIENT] Error: {ex.Message}\n");

                var errorResponseString = await response.Content.ReadAsStringAsync();
                if (!string.IsNullOrWhiteSpace(errorResponseString))
                {
                    this.TestConsole.WriteLine("\n[CLIENT] Error Response:");
                    this.TestConsole.WriteLine(errorResponseString);
                    this.TestConsole.WriteLine("");
                }

                throw;
            }

            var responseString = await response.Content.ReadAsStringAsync();

            responseString.ShouldBe("Pong");

            this.TestConsole.WriteLine("\n[CLIENT] Done\n");
        }

        [MustUseReturnValue]
        private static List<string> GetOwnLinkLocalIpV6Addresses()
        {
            var allAddresses = new List<string>();

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

                    if (!ip.Address.IsIPv6LinkLocal)
                    {
                        continue;
                    }

                    allAddresses.Add(ip.Address.ToString());
                }
            }

            return allAddresses;
        }

        private async Task RunServerAsync(CancellationToken cancellationToken)
        {
            var hostBuilder = Host.CreateDefaultBuilder();

            hostBuilder.ConfigureLogging((context, loggingBuilder) =>
            {
                // Load the logging configuration from the specified configuration section.
                loggingBuilder.AddConfiguration(context.Configuration.GetSection("Logging"));

                // For log level names, see: https://docs.microsoft.com/en-us/aspnet/core/fundamentals/logging/?view=aspnetcore-5.0#configure-logging-1
                context.Configuration["Logging:LogLevel:Default"] = "Debug";
                //context.Configuration["Logging:LogLevel:Default"] = "Trace";

                loggingBuilder.AddXUnitLogger(this.TestConsole);
            });

            hostBuilder.ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseKestrel(options =>
                {
                    options.Listen(IPAddress.IPv6Any, this._testPort);
                });

                // Use our "Startup" class for any further configuration.
                webBuilder.UseStartup<Startup>();
            });

            IHost host = hostBuilder.Build();

            await host.RunAsync(cancellationToken);
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
                        await context.Response.WriteAsync("Pong");
                    });
                });
            }
        }
    }
}
