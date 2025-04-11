using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EncryptionLibrary
{
    public static class Hashing
    {
        public static string Hash(string input)
        {
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                return Convert.ToBase64String(hashBytes);
            }
        }
    }
    public class RSA
    {
        private PrivateKey privateKey;
        private PublicKey publicKey;

        public RSA(int salt = 100)
        {
            GenerateKeys(salt);
        }
        public RSA(PublicKey publicKey, PrivateKey privateKey)
        {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public class PublicKey
        {
            public BigInteger e;
            public BigInteger n;
            public PublicKey(BigInteger e, BigInteger n)
            {
                this.e = e;
                this.n = n;
            }
        }

        public class PrivateKey
        {
            public BigInteger d;
            public BigInteger n;
            public PrivateKey(BigInteger d, BigInteger n)
            {
                this.d = d;
                this.n = n;
            }
        }

        public PrivateKey GetPrivateKey() => privateKey;
        public void SetPrivateKey(PrivateKey privateKey) => this.privateKey = privateKey;

        public PublicKey GetPublicKey() => publicKey;
        public void SetPublicKey(PublicKey publicKey) => this.publicKey = publicKey;

        public void GenerateKeys(int salt = 100)
        {
            int p = MathForEncryption.NextPrime(salt);
            int q = MathForEncryption.NextPrime(p);
            BigInteger n = p * q;
            BigInteger phi = (p - 1) * (q - 1);
            BigInteger e = MathForEncryption.NextPrime(q);

            if (MathForEncryption.GCD((int)e, (int)phi) != 1)
                e = 3;

            BigInteger d = MathForEncryption.ModInverse(e, phi);

            privateKey = new PrivateKey(d, n);
            publicKey = new PublicKey(e, n);
        }

        public List<BigInteger> EncryptString(string message)
        {
            var encrypted = new List<BigInteger>();
            foreach (char ch in message)
            {
                BigInteger m = ch;
                encrypted.Add(BigInteger.ModPow(m, publicKey.e, publicKey.n));
            }
            return encrypted;
        }

        public string DecryptString(List<BigInteger> encrypted)
        {
            var result = new StringBuilder();
            foreach (var c in encrypted)
            {
                BigInteger m = BigInteger.ModPow(c, privateKey.d, privateKey.n);
                result.Append((char)(int)m);
            }
            return result.ToString();
        }
    }

    public static class MathForEncryption
    {
        public static bool IsPrime(int n)
        {
            if (n <= 1) return false;
            if (n <= 3) return true;
            if (n % 2 == 0 || n % 3 == 0) return false;

            for (int i = 5; i * i <= n; i += 6)
            {
                if (n % i == 0 || n % (i + 2) == 0)
                    return false;
            }

            return true;
        }

        public static int NextPrime(int start)
        {
            int candidate = start + 1;
            while (true)
            {
                if (IsPrime(candidate))
                    return candidate;
                candidate++;
            }
        }

        public static int GCD(int a, int b)
        {
            while (b != 0)
            {
                int tmp = b;
                b = a % b;
                a = tmp;
            }
            return a;
        }

        public static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m, t, q;
            BigInteger x0 = 0, x1 = 1;

            if (m == 1) return 0;

            while (a > 1)
            {
                q = a / m;
                t = m;

                m = a % m;
                a = t;
                t = x0;

                x0 = x1 - q * x0;
                x1 = t;
            }

            return x1 < 0 ? x1 + m0 : x1;
        }
    }
}
