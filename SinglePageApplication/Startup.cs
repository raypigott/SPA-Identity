using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(SinglePageApplication.Startup))]

namespace SinglePageApplication
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
