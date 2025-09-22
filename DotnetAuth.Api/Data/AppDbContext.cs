using Microsoft.EntityFrameworkCore;
using DotnetAuth.Api.Models;

namespace DotnetAuth.Api.Data
{
    public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users => Set<User>();
        public DbSet<ExternalLogin> ExternalLogins => Set<ExternalLogin>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // User
            modelBuilder.Entity<User>(e =>
            {
                e.HasIndex(u => u.Username).IsUnique();
                e.Property(u => u.Username).HasMaxLength(32).IsRequired();
                e.HasIndex(u => u.Email).IsUnique();
                e.Property(u => u.Email).HasMaxLength(256).IsRequired();
                e.Property(u => u.PasswordHash).IsRequired();
            });

            // ExternalLogins
            modelBuilder.Entity<ExternalLogin>(e =>
            {
                e.Property(x => x.Provider).HasMaxLength(32).IsRequired();
                e.Property(x => x.ProviderUserId).HasMaxLength(128).IsRequired();
                e.Property(x => x.Email).HasMaxLength(256);
                e.HasIndex(x => new { x.Provider, x.ProviderUserId }).IsUnique();
                e.HasOne(x => x.User)
                 .WithMany()
                 .HasForeignKey(x => x.UserId)
                 .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}