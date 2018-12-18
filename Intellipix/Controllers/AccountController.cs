using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;

namespace Intellipix.Controllers
{
    public class AccountController : Controller
    {

        // Called when doing sign-up/sign-in
        public void SignUpSignIn()
        {
            if (!Request.IsAuthenticated)
            {
                // Use the default policy to process sign-up/sign-in
                HttpContext.GetOwinContext().Authentication.Challenge();
                return;
            }

            Response.Redirect("/");
        }

        // Called when doing profile edit
        public void EditProfile()
        {
            if (Request.IsAuthenticated)
            {
                // Set the policy for the middleware to use
                HttpContext.GetOwinContext().Set("Policy", Startup.EditProfilePolicyId);

                // Set the page to redirect to after editing a profile
                var authenticationProperties = new AuthenticationProperties { RedirectUri = "/" };
                HttpContext.GetOwinContext().Authentication.Challenge(authenticationProperties);

                return;
            }

            Response.Redirect("/");
        }

        // Called when doing a password reset
        public void ResetPassword()
        {
            // Set the policy for the middleware to use
            HttpContext.GetOwinContext().Set("Policy", Startup.ResetPasswordPolicyId);

            // Set the page to redirect to after resetting a password
            var authenticationProperties = new AuthenticationProperties { RedirectUri = "/" };
            HttpContext.GetOwinContext().Authentication.Challenge(authenticationProperties);
        }

        // Called to sign out
        public void SignOut()
        {
            if (Request.IsAuthenticated)
            {
                // To sign out, issue an OpenIDConnect sign-out request.
                var authTypes = HttpContext.GetOwinContext().Authentication.GetAuthenticationTypes();
                HttpContext.GetOwinContext().Authentication.SignOut(authTypes.Select(x => x.AuthenticationType).ToArray());
            }
        }
    }
}
