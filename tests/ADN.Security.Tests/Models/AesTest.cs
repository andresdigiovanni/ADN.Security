﻿using ADN.Security;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace ADN.Security.Tests
{
    public class AesTest
    {
        [Theory]
        [ClassData(typeof(AESTestData))]
        public void Encrypt_Valid(byte[] value, byte[] key, byte[] IV, byte[] encrypted)
        {
            var result = Aes.Encrypt(value, key, IV);

            Assert.True(result.SequenceEqual(encrypted));
        }

        [Fact]
        public void Encrypt_Exception_Value_Empty()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Encrypt(new byte[] { }, new byte[] { 0x00 }, new byte[] { 0x00 }));
        }

        [Fact]
        public void Encrypt_Exception_Value_Null()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Encrypt(null, new byte[] { 0x00 }, new byte[] { 0x00 }));
        }

        [Fact]
        public void Encrypt_Exception_Key_Empty()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Encrypt(new byte[] { 0x00 }, new byte[] { }, new byte[] { 0x00 }));
        }

        [Fact]
        public void Encrypt_Exception_Key_Null()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Encrypt(new byte[] { 0x00 }, null, new byte[] { 0x00 }));
        }

        [Fact]
        public void Encrypt_Exception_IV_Empty()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Encrypt(new byte[] { 0x00 }, new byte[] { 0x00 }, new byte[] { }));
        }

        [Fact]
        public void Encrypt_Exception_IV_Null()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Encrypt(new byte[] { 0x00 }, new byte[] { 0x00 }, null));
        }

        [Theory]
        [ClassData(typeof(AESTestData))]
        public void Decrypt_Valid(byte[] value, byte[] key, byte[] IV, byte[] encrypted)
        {
            var result = Aes.Decrypt(encrypted, key, IV);

            Assert.True(result.SequenceEqual(value));
        }

        [Fact]
        public void Decrypt_Exception_Value_Empty()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Decrypt(new byte[] { }, new byte[] { 0x00 }, new byte[] { 0x00 }));
        }

        [Fact]
        public void Decrypt_Exception_Value_Null()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Decrypt(null, new byte[] { 0x00 }, new byte[] { 0x00 }));
        }

        [Fact]
        public void Decrypt_Exception_Key_Empty()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Decrypt(new byte[] { 0x00 }, new byte[] { }, new byte[] { 0x00 }));
        }

        [Fact]
        public void Decrypt_Exception_Key_Null()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Decrypt(new byte[] { 0x00 }, null, new byte[] { 0x00 }));
        }

        [Fact]
        public void Decrypt_Exception_IV_Empty()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Decrypt(new byte[] { 0x00 }, new byte[] { 0x00 }, new byte[] { }));
        }

        [Fact]
        public void Decrypt_Exception_IV_Null()
        {
            Assert.Throws<ArgumentNullException>(() => Aes.Decrypt(new byte[] { 0x00 }, new byte[] { 0x00 }, null));
        }

        public class AESTestData : IEnumerable<object[]>
        {
            public IEnumerator<object[]> GetEnumerator()
            {
                // Key length: 16, 24 or 32 bytes
                // IV length: 16 bytes
                yield return new object[] { new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                            new byte[] { 0x8e, 0x0d, 0x99, 0xd1, 0x0a, 0xe9, 0xfa, 0xcb, 0x3d, 0x89, 0x0a, 0xbb, 0xa1, 0x28, 0xfa, 0x98 },
                                            new byte[] { 0x1a, 0x4f, 0x15, 0x9c, 0x34, 0x85, 0xac, 0xb1, 0x15, 0x12, 0xff, 0x9a, 0x05, 0xb6, 0x2d, 0xbb },
                                            new byte[] { 0x61, 0xa4, 0x14, 0x21, 0x88, 0x84, 0x51, 0x72, 0x1e, 0xa5, 0xf2, 0x3a, 0x57, 0x00, 0xf4, 0xce } };
            }

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }
    }
}
