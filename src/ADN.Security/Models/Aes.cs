using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ADN.Security
{
    /// <summary>
    /// Represents a helper class to calculate Advanced Encryption Standard (AES).
    /// </summary>
    public class Aes
    {
        /// <summary>
        /// Encrypt the giving <see cref="Byte"> <see cref="Array"/>.
        /// </summary>
        /// <param name="plainText">The <see cref="Byte"> <see cref="Array"/> that contains data to encrypt.</param>
        /// <param name="Key">The <see cref="Byte"> <see cref="Array"/> that contains the key.</param>
        /// <param name="IV">The <see cref="Byte"> <see cref="Array"/> that contains the initialize vector.</param>
        /// <returns>The encrypted data.</returns>
        public static byte[] Encrypt(byte[] plainText, byte[] Key, byte[] IV)
        {
            // Check arguments
            if (ReferenceEquals(plainText, null) || plainText.Length <= 0)
            {
                throw (new ArgumentNullException("plainText"));
            }

            if (ReferenceEquals(Key, null) || Key.Length <= 0)
            {
                throw (new ArgumentNullException("Key"));
            }

            if (ReferenceEquals(IV, null) || IV.Length <= 0)
            {
                throw (new ArgumentNullException("IV"));
            }

            byte[] encrypted = null;

            // Create an Aes object with the specified key and IV
            using (System.Security.Cryptography.Aes aesAlg = AesManaged.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.Zeros;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainText, 0, plainText.Length);
                        csEncrypt.Flush();
                        csEncrypt.Close();
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }

            // Return the encrypted bytes from the memory stream
            return encrypted;
        }

        /// <summary>
        /// Decrypt the giving <see cref="Byte"> <see cref="Array"/>.
        /// </summary>
        /// <param name="cipherText">The <see cref="Byte"> <see cref="Array"/> that contains data to decrypt.</param>
        /// <param name="Key">The <see cref="Byte"> <see cref="Array"/> that contains the key.</param>
        /// <param name="IV">The <see cref="Byte"> <see cref="Array"/> that contains the initialize vector.</param>
        /// <returns>The decrypted data.</returns>
        public static byte[] Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments
            if (ReferenceEquals(cipherText, null) || cipherText.Length <= 0)
            {
                throw (new ArgumentNullException("cipherText"));
            }

            if (ReferenceEquals(Key, null) || Key.Length <= 0)
            {
                throw (new ArgumentNullException("Key"));
            }

            if (ReferenceEquals(IV, null) || IV.Length <= 0)
            {
                throw (new ArgumentNullException("IV"));
            }

            // Declare the string used to hold the decrypted text
            byte[] clearBytes = null;

            // Create an Aes object with the specified key and IV
            using (System.Security.Cryptography.Aes aesAlg = AesManaged.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.Zeros;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        csDecrypt.Write(cipherText, 0, cipherText.Length);
                        csDecrypt.Flush();
                        csDecrypt.Close();
                    }

                    clearBytes = msDecrypt.ToArray();
                }
            }

            return clearBytes;
        }
    }
}
