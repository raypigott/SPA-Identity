using FluentAssertions;
using NUnit.Framework;

namespace Identity.Dapper.IntegrationTests
{
    [TestFixture]
    class ApplicationDatabaseConfigurationTests
    {
        [Test]
        public void Create_WhenCalled_ReturnsANewApplicationDatabaseConfiguration()
        {
            var applicationDatabaseConfiguration = ApplicationDatabaseConfiguration.Create();

            applicationDatabaseConfiguration.Should().BeOfType<ApplicationDatabaseConfiguration>();
        }
    }
}
