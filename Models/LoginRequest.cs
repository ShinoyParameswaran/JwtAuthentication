using System.ComponentModel.DataAnnotations;

namespace JwtInDotnetCore.Models
{
    public class LoginRequest
    {      
        public string username { get; set; }
        public string password { get; set; }

    }
}
