using JwtInDotnetCore.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace JwtInDotnetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;
        private readonly List<User> _users;
        public LoginController(IConfiguration config)
        {
            _config = config;
            _users = new List<User>
        {
            new User("user1", HashPassword("password1"), "user1@example.com", new List<string> {"User"}),
            new User("user2", HashPassword("password2"), "user2@example.com", new List<string> {"Admin"})
        };
        }

        [HttpPost]
        public IActionResult Post([FromBody] LoginRequest loginRequest)
        {
            //your logic for login process
            // Validate the model
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Find the user by username
            var user = _users.FirstOrDefault(u => u.UserName == loginRequest.username);

            // Check if the user exists and the password is correct
            if (user == null || !VerifyPassword(loginRequest.password, user.Password))
            {
                return Unauthorized("Invalid username or password.");
            }
            
            //If login usrename and password are correct then proceed to generate token

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var Sectoken = new JwtSecurityToken(_config["Jwt:Issuer"],
              _config["Jwt:Issuer"],
              null,
              expires: DateTime.Now.AddMinutes(120),
              signingCredentials: credentials);

            var token =  new JwtSecurityTokenHandler().WriteToken(Sectoken);

            return Ok(token);
        }

        private bool VerifyPassword(string enteredPassword, string hashedPassword)
        {
            // In a production environment, use a secure password hashing library (e.g., BCrypt)
            // For simplicity, we'll use a basic hashing method here for demonstration purposes
            return hashedPassword == HashPassword(enteredPassword);
        }

        private string HashPassword(string password)
        {
            // In a production environment, use a secure password hashing library (e.g., BCrypt)
            // For simplicity, we'll use a basic hashing method here for demonstration purposes
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hashedBytes);
            }
        }
    }
}
