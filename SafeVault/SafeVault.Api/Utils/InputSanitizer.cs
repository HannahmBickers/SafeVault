using System.Text.RegularExpressions;

namespace Utils
{
    public static class InputSanitizer
    {
        // SanitizeInput removes HTML tags and common SQL injection characters.
        // Always use parameterized queries in addition to input sanitization.
        public static string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input)) 
                return string.Empty;

            // Remove HTML tags (basic XSS defense)
            string sanitized = Regex.Replace(input, @"<.*?>", string.Empty);

            // Remove common SQL injection characters
            sanitized = Regex.Replace(input, @"['"";]", string.Empty); // removes ', ", ;
            sanitized = Regex.Replace(sanitized, @"--", string.Empty);     // removes --

            // Trim any extra whitespace
            return sanitized.Trim();
        }
    }
}