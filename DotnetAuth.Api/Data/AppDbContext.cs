using Microsoft.EntityFrameworkCore;
using DotnetAuth.Api.Models;

namespace DotnetAuth.Api.Data
{
    public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users => Set<User>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>(e =>
            {
                e.HasIndex(u => u.Username).IsUnique();
                e.Property(u => u.Username).HasMaxLength(32).IsRequired();
                e.HasIndex(u => u.Email).IsUnique();
                e.Property(u => u.Email).HasMaxLength(256).IsRequired();
                e.Property(u => u.PasswordHash).IsRequired();
            });
        }
    }
}