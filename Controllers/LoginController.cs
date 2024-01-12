using JwtInDotnetCore.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System;
using System.Collections.Generic;


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
            new User(1001,"user1", HashPassword("password1"), "user1@example.com", new List<string> {"User"}),
            new User(1002,"user2", HashPassword("password2"), "user2@example.com", new List<string> {"Admin"})
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
            var token = GenerateJwtToken(user);


            return Ok(token);
        }
        private string GenerateJwtToken(User user)
        {
            //If login usrename and password are correct then proceed to generate token

            var authClaims = new List<Claim>
            {
               new Claim(ClaimTypes.Name, user.UserName),
               new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),                             
            };

            foreach (var userRole in user.Roles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var Sectoken = new JwtSecurityToken(_config["Jwt:Issuer"],
              _config["Jwt:Audience"],
              authClaims,
              expires: DateTime.Now.AddMinutes(120),
              signingCredentials: credentials);

            var token = new JwtSecurityTokenHandler().WriteToken(Sectoken);

            return token;            
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
