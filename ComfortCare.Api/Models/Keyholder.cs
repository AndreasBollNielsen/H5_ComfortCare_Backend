using System.Security.Cryptography;

namespace ComfortCare.Api.Models
{
    public class Keyholder
    {
      public  RSAParameters RSAParameters { get; set; }
        public String key { get; set; }
        public String iv { get; set; }
    }
}
