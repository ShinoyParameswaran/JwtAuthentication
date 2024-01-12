using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtAuthentication.Controllers
{
    [Authorize("Admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminDashboardController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
           

            // Get the user's claims
            var claimsIdentity = User.Identity as ClaimsIdentity;


            // Find the NameIdentifier claim
            var nameIdentifierClaim = claimsIdentity?.FindFirst(ClaimTypes.NameIdentifier);


            // Find the NameIdentifier claim
            var nameClaim = claimsIdentity?.FindFirst(ClaimTypes.Name);

            // Find the NameIdentifier claim
            var roleClaim = claimsIdentity?.FindFirst(ClaimTypes.Role);

            

            return Ok($"Hello User, Welcome to Admin Dashboard -User ID: {nameIdentifierClaim?.Value} - Name:{nameClaim.Value} - Role:{roleClaim.Value}");           
        }
    }
}
