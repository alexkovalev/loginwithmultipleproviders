using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(LoginWithMultipleProvidersApplication.Startup))]
namespace LoginWithMultipleProvidersApplication
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
