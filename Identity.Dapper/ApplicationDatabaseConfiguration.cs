using System;

namespace Identity.Dapper
{
    public sealed class ApplicationDatabaseConfiguration : IApplicationDatabaseConfiguration, IDisposable
    {
        public string GetConnectionString()
        {
            return ApplicationConfiguration.ConnectionString;
        }

        /// <summary>
        /// Create the object so it can be passed into the Owin Context.
        /// </summary>
        /// <returns>The ApplicationDatabaseConfiguration</returns>
        public static ApplicationDatabaseConfiguration Create()
        {
            return new ApplicationDatabaseConfiguration();
        }

        /// <summary>
        /// IAppBuilder CreatePerOwinContext requires that the object it takes is IDisposable.
        /// </summary>
        public void Dispose()
        {
            // nothing to dispose. added for owin context.
        }
    }
}