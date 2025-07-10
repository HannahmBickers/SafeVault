using System.Data;
using MySql.Data.MySqlClient;
using BCrypt.Net;

namespace SafeVault.Api.Services
{
    public class DbService
    {
        private readonly IConfiguration _configuration;

        public DbService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        private MySqlConnection GetConnection()
        {
            // Always use connection strings from configuration, never hardcode credentials
            return new MySqlConnection(_configuration.GetConnectionString("DefaultConnection"));
        }

        public void AddUser(string username, string email)
        {
            using var conn = GetConnection();
            conn.Open();
            // Use parameterized queries to prevent SQL injection
            string query = "INSERT INTO Users (Username, Email, HashedPassword, Role) VALUES (@Username, @Email, '', 'user')"; // Default role: user
            using var cmd = new MySqlCommand(query, conn);
            cmd.Parameters.AddWithValue("@Username", username);
            cmd.Parameters.AddWithValue("@Email", email);
            cmd.ExecuteNonQuery();
        }

        public bool RegisterUser(string username, string email, string password, string role = "user")
        {
            // Always hash passwords before storing them
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

            using var conn = GetConnection();
            conn.Open();
            // Use parameterized queries to prevent SQL injection
            string query = "INSERT INTO Users (Username, Email, HashedPassword, Role) VALUES (@Username, @Email, @HashedPassword, @Role)";
            using var cmd = new MySqlCommand(query, conn);
            cmd.Parameters.AddWithValue("@Username", username);
            cmd.Parameters.AddWithValue("@Email", email);
            cmd.Parameters.AddWithValue("@HashedPassword", hashedPassword);
            cmd.Parameters.AddWithValue("@Role", role);

            int result = cmd.ExecuteNonQuery();
            return result > 0;
        }

        public bool AuthenticateUser(string username, string password)
        {
            using var conn = GetConnection();
            conn.Open();
            // Use parameterized queries to prevent SQL injection
            string query = "SELECT HashedPassword FROM Users WHERE Username = @Username";
            using var cmd = new MySqlCommand(query, conn);
            cmd.Parameters.AddWithValue("@Username", username);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                string storedHash = reader.GetString("HashedPassword");
                // Always verify password hashes securely
                return BCrypt.Net.BCrypt.Verify(password, storedHash);
            }

            return false;
        }

        public string? GetUserRole(string username)
        {
            using var conn = GetConnection();
            conn.Open();
            // Use parameterized queries to prevent SQL injection
            string query = "SELECT Role FROM Users WHERE Username = @Username";
            using var cmd = new MySqlCommand(query, conn);
            cmd.Parameters.AddWithValue("@Username", username);

            using var reader = cmd.ExecuteReader();
            return reader.Read() ? reader.GetString("Role") : null;
        }
        public bool IsUserInRole(string username, string role)
        {
            using var connection = GetConnection();
            // Use parameterized queries to prevent SQL injection
            string query = "SELECT COUNT(*) FROM Users WHERE Username = @Username AND Role = @Role";

            using var cmd = new MySqlCommand(query, connection);
            cmd.Parameters.AddWithValue("@Username", username);
            cmd.Parameters.AddWithValue("@Role", role);

            connection.Open();
            long count = (long)cmd.ExecuteScalar();
            return count > 0;
        }

    }
}