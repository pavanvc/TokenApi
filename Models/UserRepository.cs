using Microsoft.Data.SqlClient;

namespace TokenApi.Models
{
    public class UserRepository
    {
        private IConfiguration config;

        public UserRepository(IConfiguration config)
        {
            this.config = config;
        }

        public string GetUserRoleIfValid(string username, string password, string _connectionString)
        {
            // 🚨 REMINDER: Use secure password hashing (like BCrypt) in a real application.
            // This example uses a placeholder WHERE clause for demonstration.
            string sqlQuery = "SELECT Role FROM Users WHERE Username = @Username AND Password = @Password";
            string userRole = null;

            using (var connection = new SqlConnection(_connectionString))
            {
                using (var command = new SqlCommand(sqlQuery, connection))
                {
                    // Use parameterized queries to prevent SQL Injection
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@Password", password);

                    try
                    {
                        connection.Open();
                        object result = command.ExecuteScalar();

                        if (result != null)
                        {
                            userRole = result.ToString();
                        }
                    }
                    catch (SqlException ex)
                    {
                        // Log the exception (e.g., to a logging service like Serilog or NLog)
                        Console.WriteLine($"Database Error in UserRepository: {ex.Message}");
                        // It's often best to let the controller handle unauthorized/internal errors.
                    }
                }
            }
            return userRole;
        }
    }
}
