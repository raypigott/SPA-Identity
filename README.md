SPA-Identity
============

Implementation of SPA Template App with Identity using Dapper for SQL Server.

Changes in regards to the default template
------------------------------------------
IdentityConfig.cs
1. The ApplicationManager has been changed to use a UserManager with an int PK
2. Added claims identity

I found the following useful:

1. http://stack247.wordpress.com/2013/02/22/antiforgerytoken-a-claim-of-type-nameidentifier-or-identityprovider-was-not-present-on-provided-claimsidentity/
2. http://brockallen.com/2012/07/08/mvc-4-antiforgerytoken-and-claims/
3. http://stackoverflow.com/questions/19977833/anti-forgery-token-issue-mvc-5
                  

Integration Tests
-----------------
Please note that the tests wipe the tables they have run against after a test has completed.

Database Set Up
---------------

If using Visual Studio, use the dacpac created when the project is built (Identity\Identity.SqlServer\bin\Debug\Identity.SqlServer.dacpac) Instructions are here:http://msdn.microsoft.com/en-us/library/ee210569.aspx Othewise you can run the scripts in the database project. The database needs to be called Identity.SqlServer to run the integration tests out of the box.

The connection string now uses (localdb)\ProjectsV12. Initially it was just (localdb)\Projects

Model Changes
-------------

The boolean properties use an Is prefix EmailConfirmed is IsEmailConfirmed. This is also reflected in the database fields.

User Deletion
-------------

I decided to not delete users. Instead there is a flag that hides them.
