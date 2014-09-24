using FluentAssertions;
using Identity.Dapper.Models;
using Identity.Dapper.Stores;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace Identity.Dapper.IntegrationTests
{
    [TestFixture]
    class UserLoginStoreTests
    {
        [Test]
        public async void FindAsync_GivenUserLoginInfo_ReturnsTheCorrectUser()
        {
            var applicationDatabaseConfiguration = new ApplicationDatabaseConfiguration();
            var userStore = new UserStore<User>(applicationDatabaseConfiguration);

            var user = new User
            {
                Email = "someemail@domain.com",
                IsEmailConfirmed = true,
                PasswordHash = "PasswordHash",
                PhoneNumber = "PhoneNumber",
                IsPhoneNumberConfirmed = true,
                IsTwoFactorEnabled = false,
                LockoutEndDateUtc = null,
                IsLockoutEnabled = false,
                AccessFailedCount = 0,
                UserName = "UserName",
                IsAccountActive = true
            };

            var userLoginInfo = new UserLoginInfo("loginProvider", "providerKey");

            await userStore.CreateAsync(user);

            await userStore.AddLoginAsync(user, userLoginInfo);

            var foundUser = await userStore.FindAsync(userLoginInfo);

            foundUser.Email.Should().Be("someemail@domain.com");
        }

        [Test]
        public async void GetLogins_GivenAUser_ReturnsAllLoginsForUser()
        {
            var applicationDatabaseConfiguration = new ApplicationDatabaseConfiguration();
            var userStore = new UserStore<User>(applicationDatabaseConfiguration);

            var user = new User
            {
                Email = "someemail@domain.com",
                IsEmailConfirmed = true,
                PasswordHash = "PasswordHash",
                PhoneNumber = "PhoneNumber",
                IsPhoneNumberConfirmed = true,
                IsTwoFactorEnabled = false,
                LockoutEndDateUtc = null,
                IsLockoutEnabled = false,
                AccessFailedCount = 0,
                UserName = "UserName",
                IsAccountActive = true
            };

            await userStore.CreateAsync(user);

            await userStore.AddLoginAsync(user, new UserLoginInfo("loginProvider", "providerKey"));

            await userStore.AddLoginAsync(user, new UserLoginInfo("loginProvider1", "providerKey1"));

            var userLoginInfo = new UserLoginInfo("loginProvider2", "providerKey2");

            await userStore.AddLoginAsync(user, userLoginInfo);

            await userStore.RemoveLoginAsync(user, userLoginInfo);

            var logins  = await userStore.GetLoginsAsync(user);

            logins.Should().HaveCount(2);
        }

        [TestFixtureTearDown]
        public void TearDown()
        {
            Database.TruncateAllTables();
        }
    }
}
