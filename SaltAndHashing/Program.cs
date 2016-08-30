using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
namespace SaltAndHashing
{

    class Program
    {

        static void Main(string[] args)
        {
            Console.WriteLine("*************************** SHA with SALT **********************************");

            // comparision with 

            var x = ComputeHash("Rajeev",Supported_HA.SHA512,null);
            var result = CompareHash("rajeev", x, Supported_HA.SHA512);
            Console.WriteLine(result);
            Console.ReadLine();
        }

    

        public static string ComputeHash(string PlainTxt, Supported_HA hash, byte[] salt)
        {
            int minsaltLength = 4;
            int maxsaltLength = 16;
            byte[] SalteByte = null;
            if (salt != null)
            {
                SalteByte = salt;
            }
            else
            {
                Random r = new Random();
                int saltLength = r.Next(minsaltLength, maxsaltLength);
                SalteByte = new byte[saltLength];
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                rng.GetNonZeroBytes(SalteByte);
                rng.Dispose();
            }

            byte[] Plaindate = ASCIIEncoding.UTF8.GetBytes(PlainTxt);
            byte[] PlainDateWithSalt = new byte[Plaindate.Length + SalteByte.Length];

            for (int i = 0; i < Plaindate.Length; i++)
            {
                PlainDateWithSalt[i] = Plaindate[i];

            }
            for (int n = 0; n < SalteByte.Length; n++)
            {
                PlainDateWithSalt[Plaindate.Length + n] = SalteByte[n];
            }
            byte[] HashValue = null;

            switch (hash)
            {
                case Supported_HA.SHA256:
                    SHA256Managed sha = new SHA256Managed();
                    HashValue = sha.ComputeHash(PlainDateWithSalt);
                    sha.Dispose();
                    break;
                case Supported_HA.SHA384:
                    SHA384Managed sha384 = new SHA384Managed();
                    HashValue = sha384.ComputeHash(PlainDateWithSalt);
                    sha384.Dispose();
                    break;
                case Supported_HA.SHA512:
                    SHA512Managed sha512 = new SHA512Managed();
                    HashValue = sha512.ComputeHash(PlainDateWithSalt);
                    sha512.Dispose();
                    break;
            }

            byte[] result = new byte[HashValue.Length + SalteByte.Length];
            for (int j = 0; j < HashValue.Length; j++)
            {
                result[j] = HashValue[j];
            }
            for (int m = 0; m < SalteByte.Length; m++)
            {
                result[HashValue.Length + m] = SalteByte[m];
            }
            return Convert.ToBase64String(result);
        }

        public static bool CompareHash(string attemptedPassword, String hashValue, Supported_HA hash)
        {
            byte[] hasByte = Convert.FromBase64String(hashValue);
            int hashSize = 0;
            switch (hash)
            {
                case Supported_HA.SHA256:
                    hashSize = 32;
                    break;
                case Supported_HA.SHA384:
                    hashSize = 48;
                    break;
                case Supported_HA.SHA512:
                    hashSize = 64;
                    break;
            }

            byte[] saltByte = new byte[hasByte.Length - hashSize];
            for (int i = 0; i < saltByte.Length; i++)
            {
                saltByte[i] = hasByte[hashSize + i];
            }
            string NewHash = ComputeHash(attemptedPassword, hash, saltByte);
            return (hashValue == NewHash);
        }

    }
    public enum Supported_HA
    {
        SHA256, SHA384, SHA512
    }
}
