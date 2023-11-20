using Keycloak.AuthServices.Authentication;
using Keycloak.AuthServices.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

var keycloackAuthenticationOptions = builder
                                        .Configuration
                                        .GetSection(KeycloakAuthenticationOptions.Section)
                                        .Get<KeycloakAuthenticationOptions>();


builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.LoginPath = "/Account/Login";
})
.AddOpenIdConnect(options =>
{
    options.Authority = $"{keycloackAuthenticationOptions.AuthServerUrl}realms/{keycloackAuthenticationOptions.Realm}";
    options.ClientId = keycloackAuthenticationOptions.Resource;
    options.ClientSecret = keycloackAuthenticationOptions.Credentials.Secret;
    options.ResponseType = "code";
    options.SaveTokens = true;
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.CallbackPath = "/signin-oidc"; // Set the callback path
    options.SignedOutCallbackPath = "/signout-callback-oidc"; // Set the signout callback path
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "preferred_username",
        RoleClaimType = "roles"
    };
});

var keycloakAutheticationOptions = builder
                                        .Configuration
                                        .GetSection(KeycloakProtectionClientOptions.Section)
                                        .Get<KeycloakProtectionClientOptions >();

builder.Services.AddKeycloakAuthorization(keycloakAutheticationOptions);


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

 
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.UseEndpoints(endpoints => {
endpoints.MapControllerRoute(
        name: "login-callback",
        pattern: "login-callback",
        defaults: new { controller = "Account", action = "LoginCallback" });

});

// Add routes for callback handling
    app.Map("/signin-oidc", signinApp =>
    {
        signinApp.Run(async context =>
        {
            // Handle the callback from Keycloak after successful authentication
            await context.Response.WriteAsync("Authentication successful");
        });
    });

    app.Map("/signout-callback-oidc", signoutApp =>
    {
        signoutApp.Run(async context =>
        {
            // Handle the callback from Keycloak after sign-out
            await context.Response.WriteAsync("Sign-out successful");
        });
    });


app.Run();
