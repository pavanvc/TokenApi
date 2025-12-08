using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using TokenApi.Models;

namespace TokenApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly string _connectionString; // Store the connection string
        private readonly UserRepository _userRepository;

        public AuthController(IConfiguration config)
        {
            _config = config;
            _connectionString = _config.GetConnectionString("DefaultConnection");
            _userRepository = new UserRepository(config);
        }
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            if (model is null) return BadRequest("Invalid client request");

            // TODO: Replace this with real user validation (DB, Identity, etc.)
            string userRole = _userRepository.GetUserRoleIfValid(model.Username, model.Password, _connectionString);

            if (userRole is null)
            {
                return Unauthorized("Invalid credentials");
            }
            var tokenString = GenerateJwtToken(model.Username, userRole);
            return Ok(new { token = tokenString });
             


           
        }

        private bool ValidateUser(string username, string password)
        {
            // Demo only — replace with real checks
            if (username == "user") {
                return username == "user" && password == "123"; }

            else if  (username == "admin") {
                return username == "admin" && password == "123";
            }
            else
            {
                return false;
            }

        }

        private string GenerateJwtToken(string username,string role)
        {
            var jwtSection = _config.GetSection("Jwt");
            var secret = jwtSection["Key"]!;
            var issuer = jwtSection["Issuer"];
            var audience = jwtSection["Audience"];
            var expiresMinutes = int.TryParse(jwtSection["ExpireMinutes"], out var m) ? m : 60;

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role, role)  // ROLE CLAIM
            // add roles: new Claim(ClaimTypes.Role, "Admin")
        };

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expiresMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("protected")]
        public IActionResult Protected()
        {
            return Ok(new { Message = "This is protected admin data", User = User.Identity?.Name, Role= User.Identity?.AuthenticationType });
        }


        [Authorize(Roles = "User")]
        [HttpGet("protected2")]
        public IActionResult Protected2()
        {
            return Ok(new { Message = "This is protected user data", User = User.Identity?.Name });
        }

        [Authorize(Roles = "Admin,User")]
        [HttpGet("protected3")]
        public IActionResult Protected3()
        {
            return Ok(new { Message = "This is protected Admin/User data", User = User.Identity?.Name, Role = User.Identity?.IsAuthenticated });
        }
    }
}
