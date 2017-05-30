using System;
using System.Collections.Generic;
using System.Linq;

namespace AuthenticationTest1
{
    public class Account
    {
        public string Email { get; private set; } // I - Username
        public byte[] Salt { get; private set; }  // s- User's salt.
        public byte[] PasswordVerifier { get; private set; } // v - password verifier.

        public Account(string email, string password) // Account with **newly generated** persistent ID
        {
            if (password.Length > 16) password = password.Substring(0, 16); // make sure the password does not exceed 16 chars.

            var salt = SRP6a.GetRandomBytes(32);
            var passwordVerifier = SRP6a.CalculatePasswordVerifierForAccount(email, password, salt);

            this.SetFields(email, salt, passwordVerifier);
        }

        public Account(string email, string password, string salt)
        {
            if (password.Length > 16) password = password.Substring(0, 16); // make sure the password does not exceed 16 chars.

            var passwordVerifier = SRP6a.CalculatePasswordVerifierForAccount(email, password, salt.ToByteArray());

            this.SetFields(email, salt.ToByteArray(), passwordVerifier);
        }

        private void SetFields(string email, byte[] salt, byte[] passwordVerifier)
        {
            this.Email = email;
            this.Salt = salt;
            this.PasswordVerifier = passwordVerifier;
        }
        
        public void UpdatePassword(string newPassword)
        {
            this.PasswordVerifier = SRP6a.CalculatePasswordVerifierForAccount(this.Email, newPassword, this.Salt);
        }
    }
}
