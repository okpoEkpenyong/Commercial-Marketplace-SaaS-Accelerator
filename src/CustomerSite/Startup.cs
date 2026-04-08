// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

using Azure.Identity;
using Marketplace.SaaS.Accelerator.CustomerSite.Controllers;
using Marketplace.SaaS.Accelerator.CustomerSite.WebHook;
using Marketplace.SaaS.Accelerator.DataAccess.Context;
using Marketplace.SaaS.Accelerator.DataAccess.Contracts;
using Marketplace.SaaS.Accelerator.DataAccess.Services;
using Marketplace.SaaS.Accelerator.Services.Configurations;
using Marketplace.SaaS.Accelerator.Services.Contracts;
using Marketplace.SaaS.Accelerator.Services.Services;
using Marketplace.SaaS.Accelerator.Services.Utilities;
using Marketplace.SaaS.Accelerator.Services.WebHook;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Marketplace.SaaS;
using System;
using Azure.Core;
using System.Diagnostics;
using System.Reflection;

namespace Marketplace.SaaS.Accelerator.CustomerSite;

/// <summary>
/// Defines the <see cref="Startup" />.
/// </summary>
public class Startup
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Startup"/> class.
    /// </summary>
    /// <param name="configuration">The configuration<see cref="IConfiguration"/>.</param>
    public Startup(IConfiguration configuration)
    {
        this.Configuration = configuration;
    }

    /// <summary>
    /// Gets the Configuration.
    /// </summary>
    public IConfiguration Configuration { get; }

    /// <summary>
    /// The ConfigureServices.
    /// </summary>
    /// <param name="services">The services<see cref="IServiceCollection"/>.</param>
    public void ConfigureServices(IServiceCollection services)
    {
        services.Configure<CookiePolicyOptions>(options =>
        {
            // This lambda determines whether user consent for non-essential cookies is needed for a given request.
            options.CheckConsentNeeded = context => true;
            options.MinimumSameSitePolicy = SameSiteMode.None;
        });

        var config = new SaaSApiClientConfiguration()
        {
            AdAuthenticationEndPoint = this.Configuration["SaaSApiConfiguration:AdAuthenticationEndPoint"],
            ClientId = this.Configuration["SaaSApiConfiguration:ClientId"],
            ClientSecret = this.Configuration["SaaSApiConfiguration:ClientSecret"],
            MTClientId = this.Configuration["SaaSApiConfiguration:MTClientId"],
            FulFillmentAPIBaseURL = this.Configuration["SaaSApiConfiguration:FulFillmentAPIBaseURL"],
            FulFillmentAPIVersion = this.Configuration["SaaSApiConfiguration:FulFillmentAPIVersion"],
            GrantType = this.Configuration["SaaSApiConfiguration:GrantType"],
            Resource = this.Configuration["SaaSApiConfiguration:Resource"],
            SaaSAppUrl = this.Configuration["SaaSApiConfiguration:SaaSAppUrl"],
            SignedOutRedirectUri = this.Configuration["SaaSApiConfiguration:SignedOutRedirectUri"],
            TenantId = this.Configuration["SaaSApiConfiguration:TenantId"],
            Environment = this.Configuration["SaaSApiConfiguration:Environment"]
        };
        // Accept alternate key spellings used in appsettings.json files from samples or manual edits.
        // Common variants: "AdAuthenticationEndpoint" (no capital P) and using ClientId as MTClientId.
        if (string.IsNullOrWhiteSpace(config.AdAuthenticationEndPoint))
        {
            config.AdAuthenticationEndPoint = this.Configuration["SaaSApiConfiguration:AdAuthenticationEndpoint"];
        }

        if (string.IsNullOrWhiteSpace(config.MTClientId))
        {
            // Some configs set MTClientId under different keys or reuse ClientId — accept those as fallbacks.
            config.MTClientId = this.Configuration["SaaSApiConfiguration:MTClientId"] ?? this.Configuration["SaaSApiConfiguration:ClientId"];
        }

        if (string.IsNullOrWhiteSpace(config.FulFillmentAPIBaseURL))
        {
            config.FulFillmentAPIBaseURL = this.Configuration["SaaSApiConfiguration:FulfillmentApiBaseUrl"] ?? this.Configuration["SaaSApiConfiguration:FulFillmentAPIBaseURL"];
        }
        // Create a TokenCredential only when all required configuration values are present.
        // Fall back to DefaultAzureCredential which will attempt other auth mechanisms
        // (environment, managed identity, etc.). This avoids throwing when tenant/client
        // configuration is missing during local development.
        var tenantId = config.TenantId;
        var clientId = config.ClientId;
        var clientSecret = config.ClientSecret;

        TokenCredential creds;
        if (!string.IsNullOrWhiteSpace(tenantId) && !string.IsNullOrWhiteSpace(clientId) && !string.IsNullOrWhiteSpace(clientSecret))
        {
            try
            {
                creds = new ClientSecretCredential(tenantId, clientId, clientSecret);
            }
            catch (ArgumentException)
            {
                // Invalid tenant id or other argument issue — fall back to DefaultAzureCredential
                creds = new DefaultAzureCredential();
            }
        }
        else
        {
            creds = new DefaultAzureCredential();
        }

        // Only enable OpenID Connect if an MT client id and authority are configured.
        var envName = this.Configuration["ASPNETCORE_ENVIRONMENT"] ?? Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        var isDevelopment = !string.IsNullOrWhiteSpace(envName) && envName.Equals("Development", StringComparison.OrdinalIgnoreCase);

        // Validate the AD authority and allow non-HTTPS only for Development when necessary.
        Uri adAuthorityUri = null;
        if (!string.IsNullOrWhiteSpace(config.AdAuthenticationEndPoint))
        {
            Uri.TryCreate(config.AdAuthenticationEndPoint, UriKind.Absolute, out adAuthorityUri);
        }

        var enableOidc = !string.IsNullOrWhiteSpace(config.MTClientId) && adAuthorityUri != null && (adAuthorityUri.Scheme == Uri.UriSchemeHttps || isDevelopment);

        if (enableOidc)
        {
            services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = OpenIdConnectDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddCookie(options =>
                {
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                    options.Cookie.MaxAge = options.ExpireTimeSpan;
                    options.SlidingExpiration = true;
                    options.LoginPath = "/Account/SignIn";
                    options.AccessDeniedPath = "/Account/AccessDenied"; // optional
                })
                .AddOpenIdConnect(options =>
                {
                    options.Authority = $"{config.AdAuthenticationEndPoint}/common/v2.0";
                    options.ClientId = config.MTClientId;
                    options.ResponseType = OpenIdConnectResponseType.IdToken;
                    options.CallbackPath = "/Home/Index";
                    options.SignedOutRedirectUri = config.SignedOutRedirectUri;
                    options.TokenValidationParameters.NameClaimType = ClaimConstants.CLAIM_SHORT_NAME;
                    options.TokenValidationParameters.ValidateIssuer = false;

                    // If running in Development and the authority is not HTTPS, allow fetching the metadata over HTTP.
                    if (isDevelopment && adAuthorityUri != null && adAuthorityUri.Scheme != Uri.UriSchemeHttps)
                    {
                        // Ensure a Metadata/Configuration address is set and allow non-HTTPS retrieval for development only.
                        var metadataAddress = options.Authority.TrimEnd('/') + "/.well-known/openid-configuration";
                        options.MetadataAddress = metadataAddress;
                        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                            metadataAddress,
                            new OpenIdConnectConfigurationRetriever(),
                            new HttpDocumentRetriever { RequireHttps = false });
                    }
                });
        }
        else
        {
            // Fall back to cookie-only authentication for local/dev scenarios when OIDC isn't configured.
            services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddCookie(options =>
                {
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                    options.Cookie.MaxAge = options.ExpireTimeSpan;
                    options.SlidingExpiration = true;
                });
        }
        services
            .AddTransient<IClaimsTransformation, CustomClaimsTransformation>()
            .AddScoped<ExceptionHandlerAttribute>()
            .AddScoped<RequestLoggerActionFilter>();

        if (!Uri.TryCreate(config.FulFillmentAPIBaseURL, UriKind.Absolute, out var fulfillmentBaseApi)) 
        {
            fulfillmentBaseApi = new Uri("https://marketplaceapi.microsoft.com/api");
        }

        services
            .AddSingleton<IFulfillmentApiService>(new FulfillmentApiService(new MarketplaceSaaSClient(fulfillmentBaseApi, creds), config, new FulfillmentApiClientLogger()))
            .AddSingleton<SaaSApiClientConfiguration>(config)
            .AddSingleton<ValidateJwtToken>();

        // Add the assembly version
        services.AddSingleton<IAppVersionService>(new AppVersionService(Assembly.GetExecutingAssembly()?.GetName()?.Version));

        var defaultConnection = this.Configuration.GetConnectionString("DefaultConnection");
        if (!string.IsNullOrWhiteSpace(defaultConnection))
        {
            services.AddDbContext<SaasKitContext>(options => options.UseSqlServer(defaultConnection));
        }
        else
        {
            // No DefaultConnection configured. For Development, prefer an InMemory database to avoid SQL Server errors.
            // Otherwise fall back to LocalDB as a secondary option.
            try
            {
                Trace.TraceWarning("No connection string named 'DefaultConnection' was found. Using InMemory database in Development or LocalDB if available.");
            }
            catch
            {
            }

            var dbEnvName = this.Configuration["ASPNETCORE_ENVIRONMENT"] ?? Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            if (!string.IsNullOrWhiteSpace(dbEnvName) && dbEnvName.Equals("Development", StringComparison.OrdinalIgnoreCase))
            {
                // Use InMemory database during development to allow the app to start without a SQL Server instance.
                services.AddDbContext<SaasKitContext>(options => options.UseInMemoryDatabase("SaasKit_DevInMemory"));
            }
            else
            {
                var localDb = "Server=(localdb)\\mssqllocaldb;Database=SaasKit;Trusted_Connection=True;MultipleActiveResultSets=true";
                services.AddDbContext<SaasKitContext>(options => options.UseSqlServer(localDb));
            }
        }

        InitializeRepositoryServices(services);

        services.AddMvc(option => {
            option.EnableEndpointRouting = false;
            option.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
        });
    }

    /// <summary>
    /// The Configure.
    /// </summary>
    /// <param name="app">The app<see cref="IApplicationBuilder" />.</param>
    /// <param name="env">The env<see cref="IWebHostEnvironment" />.</param>
    /// <param name="loggerFactory">The loggerFactory<see cref="ILoggerFactory" />.</param>
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILoggerFactory loggerFactory)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Home/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();
        app.UseCookiePolicy();
        app.UseAuthentication();
        app.UseMvc(routes =>
        {
            routes.MapRoute(
                name: "default",
                template: "{controller=Home}/{action=Index}/{id?}");
        });
    }

    private static void InitializeRepositoryServices(IServiceCollection services)
    {
        services.AddScoped<ISubscriptionsRepository, SubscriptionsRepository>();
        services.AddScoped<IPlansRepository, PlansRepository>();
        services.AddScoped<IUsersRepository, UsersRepository>();
        services.AddScoped<ISubscriptionLogRepository, SubscriptionLogRepository>();
        services.AddScoped<IApplicationLogRepository, ApplicationLogRepository>();
        services.AddScoped<IWebhookProcessor, WebhookProcessor>();
        services.AddScoped<IWebhookHandler, WebHookHandler>();
        services.AddScoped<IApplicationConfigRepository, ApplicationConfigRepository>();
        services.AddScoped<IEmailTemplateRepository, EmailTemplateRepository>();
        services.AddScoped<IOffersRepository, OffersRepository>();
        services.AddScoped<IOfferAttributesRepository, OfferAttributesRepository>();
        services.AddScoped<IPlanEventsMappingRepository, PlanEventsMappingRepository>();
        services.AddScoped<IEventsRepository, EventsRepository>();
        services.AddScoped<IEmailService, SMTPEmailService>();
        services.AddScoped<SaaSClientLogger<HomeController>>();
        services.AddScoped<IWebNotificationService, WebNotificationService>();
    }
}