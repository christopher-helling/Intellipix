using Owin;
using System;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.Notifications;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Intellipix
{
    public partial class Startup
    {
        // Config settings
        public static string AadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        public static string Tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        public static string ClientId = ConfigurationManager.AppSettings["ida:ClientId"];
        public static string RedirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];

        // B2C policies
        public static string SignUpSignInPolicyId = ConfigurationManager.AppSettings["ida:SignUpSignInPolicyId"];
        public static string EditProfilePolicyId = ConfigurationManager.AppSettings["ida:EditProfilePolicyId"];
        public static string ResetPasswordPolicyId = ConfigurationManager.AppSettings["ida:ResetPasswordPolicyId"];
        public static string DefaultPolicy = SignUpSignInPolicyId;

        // Authority
        private static string Authority = String.Format(AadInstance, Tenant, DefaultPolicy);

        private void ConfigureAuth(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
             // Set the OpenID Connect settings from config values
             MetadataAddress = Authority,
                    ClientId = ClientId,
                    RedirectUri = RedirectUri,
                    PostLogoutRedirectUri = RedirectUri,

             // Set the notification callbacks
             Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        RedirectToIdentityProvider = OnRedirectToIdentityProvider,
                        AuthenticationFailed = OnAuthenticationFailed
                    },

             // Set the claim to validate
             TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = "name"
                    }
                }
            );

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
        }

        private Task OnRedirectToIdentityProvider(
         RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            var policy = notification.OwinContext.Get<string>("Policy");

            // Update the appropriate settings when a policy is set during an authentication call
            if (!string.IsNullOrEmpty(policy) && !policy.Equals(DefaultPolicy))
            {
                notification.ProtocolMessage.Scope = OpenIdConnectScope.OpenId;
                notification.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
                notification.ProtocolMessage.IssuerAddress =
                    notification.ProtocolMessage.IssuerAddress.ToLower()
                    .Replace(DefaultPolicy.ToLower(), policy.ToLower());
            }

            return Task.CompletedTask;
        }

        private Task OnAuthenticationFailed(
            AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();

            // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page 
            // because password reset is not supported by a "sign-up or sign-in policy"
            if (notification.ProtocolMessage.ErrorDescription != null
                && notification.ProtocolMessage.ErrorDescription.Contains("AADB2C90118"))
            {
                // If the user clicked the reset password link, redirect to the reset password route
                notification.Response.Redirect("/Account/ResetPassword");
            }

            else if (notification.Exception.Message == "access_denied")
            {
                notification.Response.Redirect("/");
            }
            else
            {
                notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            }

            return Task.CompletedTask;
        }

    }
}