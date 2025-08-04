using System.Text.RegularExpressions;

namespace Utils
{
    public static class InputSanitizer
    {
        public static string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input)) 
                return string.Empty;

            // Remove HTML tags (basic XSS defense)
            string sanitized = Regex.Replace(input, @"<.*?>", string.Empty);

            // Remove common SQL injection characters
            sanitized = Regex.Replace(input, @"['"";]", string.Empty); // removes ', ", ;
            sanitized = Regex.Replace(sanitized, @"--", string.Empty);     // removes --

            
            return sanitized.Trim();
        }
    }
}
