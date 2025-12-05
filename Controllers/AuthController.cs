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

        public AuthController(IConfiguration config)
        {
            _config = config;
        }
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            if (model is null) return BadRequest("Invalid client request");

            // TODO: Replace this with real user validation (DB, Identity, etc.)
            if (!ValidateUser(model.Username, model.Password))
                return Unauthorized("Invalid credentials");

            var tokenString = GenerateJwtToken(model.Username);
            return Ok(new { token = tokenString });
        }

        private bool ValidateUser(string username, string password)
        {
            // Demo only — replace with real checks
            return username == "pavan" && password == "123";
        }

        private string GenerateJwtToken(string username)
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
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
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

        [Authorize]
        [HttpGet("protected")]
        public IActionResult Protected()
        {
            return Ok(new { Message = "This is protected data", User = User.Identity?.Name });
        }


        
        [HttpGet("protected2")]
        public IActionResult Protected2()
        {
            return Ok(new { Message = "This is protected data", User = User.Identity?.Name });
        }
    }
}
