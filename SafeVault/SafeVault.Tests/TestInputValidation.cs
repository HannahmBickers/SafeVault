using NUnit.Framework;
using Utils;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestInputValidation
    {
        [Test]
        public void Should_Remove_Simple_SQL_Injection()
        {
            string input = "'; DROP TABLE Users;--";
            string result = InputSanitizer.SanitizeInput(input);

            Assert.That(result.Contains("'"), Is.False);
            Assert.That(result.Contains("--"), Is.False);
            Assert.That(result.Contains("DROP"), Is.True); // Words are okay, characters aren't
        }

        [Test]
        public void Should_Remove_Simple_XSS()
        {
            string input = "<script>alert('XSS')</script>";
            string result = InputSanitizer.SanitizeInput(input);

            Assert.That(result.Contains("<"), Is.False);
            Assert.That(result.Contains(">"), Is.False);
        }

        [Test]
        public void Should_Trim_Whitespace()
        {
            string input = "   username@example.com   ";
            string result = InputSanitizer.SanitizeInput(input);

            Assert.That(result, Is.EqualTo("username@example.com"));
        }
    }
}
