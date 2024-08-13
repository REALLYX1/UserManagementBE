using Microsoft.EntityFrameworkCore;

namespace UserManagementBE.Data
{
    public class UserManagementContext : DbContext
    {
        public UserManagementContext(DbContextOptions<UserManagementContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<UserLog> UserLogs { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UserLog>()
                .HasKey(ul => ul.LogId); // Cấu hình LogId là khóa chính

            // Các cấu hình khác
        }
    }

    public class User
    {
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }

    public class UserLog
    {
        public int LogId { get; set; }
        public int UserId { get; set; }
        public string Action { get; set; }
        public DateTime ActionTime { get; set; }
        public string Details { get; set; }

        public User User { get; set; }
    }

    public class Role
    {
        public int RoleId { get; set; }
        public string RoleName { get; set; }

        public ICollection<UserRole> UserRoles { get; set; }
    }

    public class UserRole
    {
        public int UserRoleId { get; set; }
        public int UserId { get; set; }
        public int RoleId { get; set; }

        public User User { get; set; }
        public Role Role { get; set; }
    }
}
