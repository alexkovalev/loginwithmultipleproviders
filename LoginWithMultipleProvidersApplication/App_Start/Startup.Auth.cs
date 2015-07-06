using System.Web.Helpers;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Providers.LinkedIn;

namespace LoginWithMultipleProvidersApplication
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login")
            });

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.UseGoogleAuthentication(
                clientId: "284015851574-iru1o6p9e3fd18nks93eb6hvsms9ui0c.apps.googleusercontent.com",
                clientSecret: "wjCS-n1xc5v9Q-NY6GpGTj9R");

            app.UseFacebookAuthentication(
                appId: "783341745111788",
                appSecret: "d61a307bdf69d87fd1af95f3a567ceeb");

            app.UseLinkedInAuthentication(
                clientId: "772a62zo1m8dtw",
                clientSecret: "ziWXtzAk0yJeau56");
        }
    }
}