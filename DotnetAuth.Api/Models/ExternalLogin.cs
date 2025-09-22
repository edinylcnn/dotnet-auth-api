using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DotnetAuth.Api.Models
{
    public class ExternalLogin
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        // exp: "unity", "google", "apple"
        public string Provider { get; set; } = default!;
        public string ProviderUserId { get; set; } = default!;
        public string? Email { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastUsedAt { get; set; }
        public User User { get; set; } = default!;
    }
    public enum ExternalProviders
    {
        Unity,
        Google,
        Apple,
        Facebook
    }

}