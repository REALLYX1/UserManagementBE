using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UserManagementBE.Data;

namespace UserManagementAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly UserManagementContext _context;

        public UsersController(UserManagementContext context)
        {
            _context = context;
        }

        private string GenerateJwtToken(User user)
        {
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("SPK123456789101112131415abcdefghtas"));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // POST: api/Users/Register
        [HttpPost("Register")]
        public async Task<ActionResult<User>> Register(User user)
        {
            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
            user.CreatedAt = DateTime.UtcNow;
            user.UpdatedAt = DateTime.UtcNow;

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return Ok(new { Message = "DANG KI THANH CONG", User = user });
        }

        // POST: api/Users/Login
        [HttpPost("Login")]
        public async Task<ActionResult<User>> Login([FromBody] LoginRequest loginRequest)
        {
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == loginRequest.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(loginRequest.Password, user.Password))
            {
                return Unauthorized(new { Message = "SAI TAI KHOAN HOAC MAT KHAU. VUI LONG KIEM TRA LAI" });
            }

            var token = GenerateJwtToken(user);

            return Ok(new
            {
                Message = "DANG NHAP THANH CONG",
                Token = token,
                User = user
            });
        }

        // PUT: api/Users/ChangePassword
        [HttpPut("ChangePassword")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            var user = await _context.Users.FindAsync(request.Id);
            if (user == null)
            {
                return NotFound(new { Message = "KHONG TIM THAY NGUOI DUNG" });
            }
            user.Password = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
            user.UpdatedAt = DateTime.UtcNow;
            _context.Entry(user).State = EntityState.Modified;
            await _context.SaveChangesAsync();
            return Ok(new { Message = "THAY DOI MAT KHAU THANH CONG" });
        }

        // GET: api/Users
        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<IEnumerable<User>>> GetUsers()
        {
            var users = await _context.Users.ToListAsync();
            return Ok(new { Message = "HIEN THI DANH SACH NGUOI DUNG", Users = users });
        }

        // PUT: api/Users/Edit/{id}
        [HttpPut("Edit/{id}")]
        [Authorize(Roles = "Admin")] 
        public async Task<IActionResult> EditUser(int id, [FromBody] User user)
        {
            var userToUpdate = await _context.Users.FindAsync(id);

            if (userToUpdate == null)
            {
                return BadRequest(new { Message = "KHONG TIM DUOC ID NGUOI DUNG" });
            }

            userToUpdate.Username = user.Username;
            userToUpdate.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
            userToUpdate.Email = user.Email;
            userToUpdate.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return Ok(new { Message = "THAY DOI NGUOI DUNG THANH CONG" });
        }

        // DELETE: api/Users/Delete/{id}
        [HttpDelete("Delete/{id}")]
        [Authorize(Roles = "Admin")] 
        public async Task<IActionResult> DeleteUser(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return NotFound(new { Message = "KHONG TIM THAY NGUOI DUNG" });
            }

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            return Ok(new { Message = "XOA THANH CONG" });
        }
    }

    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class ChangePasswordRequest
    {
        public int Id { get; set; }
        public string NewPassword { get; set; }
    }
}
