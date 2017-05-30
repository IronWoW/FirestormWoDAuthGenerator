using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticationTest1
{
    public static class BigIntegerExtensions
    {
        public static BigInteger ToBigInteger(this byte[] src)
        {
            var dst = new byte[src.Length + 1];
            Array.Copy(src, dst, src.Length);
            return new BigInteger(dst);
        }

        public static byte[] ToArray(this BigInteger b)
        {
            var result = b.ToByteArray();
            if (result[result.Length - 1] == 0 && (result.Length % 0x10) != 0)
                Array.Resize(ref result, result.Length - 1);
            return result;
        }
    }

    public static class ArrayExtensions
    {
        public static string ToHexString(this byte[] byteArray)
        {
            return byteArray.Aggregate("", (current, b) => current + b.ToString("X2"));
        }

        public static byte[] ToByteArray(this string str)
        {
            str = str.Replace(" ", String.Empty);

            var res = new byte[str.Length / 2];
            for (int i = 0; i < res.Length; ++i)
            {
                string temp = String.Concat(str[i * 2], str[i * 2 + 1]);
                res[i] = Convert.ToByte(temp, 16);
            }
            return res;
        }
    }

    /// <summary>
    /// SRP6-a implementation.
    /// </summary>
    public class SRP6a
    {
        // The following is a description of SRP-6 and 6a, the latest versions of SRP:
        // ---------------------------------------------------------------------------
        //   N    A large safe prime (N = 2q+1, where q is prime)
        //        All arithmetic is done modulo N.
        //   g    A generator modulo N
        //   k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
        //   s    User's salt
        //   I    Username
        //   p    Cleartext Password
        //   H()  One-way hash function
        //   ^    (Modular) Exponentiation
        //   u    Random scrambling parameter
        //   a,b  Secret ephemeral values
        //   A,B  Public ephemeral values
        //   x    Private key (derived from p and s)
        //   v    Password verifier
        // ---------------------------------------------------------------------------
        // specification: http://srp.stanford.edu/design.html
        // article: http://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
        // contains code from tomrus88 (https://github.com/tomrus88/d3proto/blob/master/Core/SRP.cs

        private static readonly SHA256Managed H = new SHA256Managed(); // H() One-way hash function.

        /// <summary>
        /// Calculates password verifier for given email, password and salt.
        /// </summary>
        /// <param name="email">The account email.</param>
        /// <param name="password">The password.</param>
        /// <param name="salt">The generated salt.</param>
        /// <returns></returns>
        public static byte[] CalculatePasswordVerifierForAccount(string email, string password, byte[] salt)
        {
            // x = H(s, p) -> s: randomly choosen salt
            // v = g^x (computes password verifier)

            // TODO: it seems hashing identity-salt + password bugs for passwords with >11 chars or so.
            // we need to get rid of that identity-salt in pBytes /raist.

            var identitySalt = H.ComputeHash(Encoding.ASCII.GetBytes(email)).ToHexString(); // Identity salt that's hashed using account email.
            var pBytes = H.ComputeHash(Encoding.ASCII.GetBytes(identitySalt.ToUpper() + ":" + password.ToUpper())); // p (identitySalt + password)
            var x = H.ComputeHash(new byte[0].Concat(salt).Concat(pBytes).ToArray()).ToBigInteger(); // x = H(s, p)

            return BigInteger.ModPow(g, x, N).ToArray();
        }
        
        public static byte[] GetRandomBytes(int count)
        {
            var rnd = new Random();
            var result = new byte[count];
            rnd.NextBytes(result);
            return result;
        }
        
        /// <summary>
        /// A generator modulo N
        /// </summary>
        private static readonly BigInteger g = new byte[] { 0x02 }.ToBigInteger();

        /// <summary>
        /// A large safe prime (N = 2q+1, where q is prime)
        /// </summary>
        private static readonly BigInteger N = new byte[]
        {
            0xAB, 0x24, 0x43, 0x63, 0xA9, 0xC2, 0xA6, 0xC3, 0x3B, 0x37, 0xE4, 0x61, 0x84, 0x25, 0x9F, 0x8B,
            0x3F, 0xCB, 0x8A, 0x85, 0x27, 0xFC, 0x3D, 0x87, 0xBE, 0xA0, 0x54, 0xD2, 0x38, 0x5D, 0x12, 0xB7,
            0x61, 0x44, 0x2E, 0x83, 0xFA, 0xC2, 0x21, 0xD9, 0x10, 0x9F, 0xC1, 0x9F, 0xEA, 0x50, 0xE3, 0x09,
            0xA6, 0xE5, 0x5E, 0x23, 0xA7, 0x77, 0xEB, 0x00, 0xC7, 0xBA, 0xBF, 0xF8, 0x55, 0x8A, 0x0E, 0x80,
            0x2B, 0x14, 0x1A, 0xA2, 0xD4, 0x43, 0xA9, 0xD4, 0xAF, 0xAD, 0xB5, 0xE1, 0xF5, 0xAC, 0xA6, 0x13,
            0x1C, 0x69, 0x78, 0x64, 0x0B, 0x7B, 0xAF, 0x9C, 0xC5, 0x50, 0x31, 0x8A, 0x23, 0x08, 0x01, 0xA1,
            0xF5, 0xFE, 0x31, 0x32, 0x7F, 0xE2, 0x05, 0x82, 0xD6, 0x0B, 0xED, 0x4D, 0x55, 0x32, 0x41, 0x94,
            0x29, 0x6F, 0x55, 0x7D, 0xE3, 0x0F, 0x77, 0x19, 0xE5, 0x6C, 0x30, 0xEB, 0xDE, 0xF6, 0xA7, 0x86
        }.ToBigInteger();
    }
}
