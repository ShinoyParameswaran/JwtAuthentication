namespace JwtInDotnetCore.Models
{
    public class User
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
        public List<string> Roles { get; set; }

        // You can add additional properties as needed for your application

        // Example constructor for creating a user
        public User(string userName, string password, string email, List<string> roles)
        {
            UserName = userName;
            Password = password;
            Email = email;
            Roles = roles;
        }
    }
}
