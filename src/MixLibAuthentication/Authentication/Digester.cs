using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MixLibAuthentication.Authentication
{
    public class Digester
    {
        public static string HashString(string src)
        {
            var s = new SHA1Managed();
            return Convert.ToBase64String(s.ComputeHash(Encoding.Default.GetBytes(src)));
        }

        public static string HashFile(Stream file)
        {
            var s = new SHA1Managed();
            return Convert.ToBase64String(s.ComputeHash(file));
        }
    }
}
