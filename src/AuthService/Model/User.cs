using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthService.Model
{
    public class User
    {
        public string UserId { get; set; }
        public string Password { get; set; }
        public string token { get; set; }
    }
}
