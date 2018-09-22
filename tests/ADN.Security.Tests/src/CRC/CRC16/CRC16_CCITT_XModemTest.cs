using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace ADN.Security.Tests
{
    public class CRC16_CCITT_XModemTest
    {
        [Theory]
        [ClassData(typeof(ComputeChecksum))]
        public void ComputeChecksum_Bytes_Valid(string value, ushort expected)
        {
            var bytes = Encoding.ASCII.GetBytes(value);
            var crcfactory = new CRC16Factory();
            var crc = crcfactory.GetCRC16(CRC16Factory.CRC16Type.CRC16_CCITT_XModem);
            var result = crc.ComputeChecksum(bytes);

            Assert.Equal(expected, result);
        }

        [Theory]
        [ClassData(typeof(ComputeChecksum))]
        public void ComputeChecksum_String_Valid(string value, ushort expected)
        {
            var crcfactory = new CRC16Factory();
            var crc = crcfactory.GetCRC16(CRC16Factory.CRC16Type.CRC16_CCITT_XModem);
            var result = crc.ComputeChecksum(value);

            Assert.Equal(expected, result);
        }

        [Fact]
        public void ComputeChecksum_Exception_Value_Empty()
        {
            var crcfactory = new CRC16Factory();
            var crc = crcfactory.GetCRC16(CRC16Factory.CRC16Type.CRC16_CCITT_XModem);
            Assert.Throws<ArgumentNullException>(() => crc.ComputeChecksum(new byte[] { }));
        }

        [Fact]
        public void ComputeChecksum_Exception_Value_Null()
        {
            var crcfactory = new CRC16Factory();
            var crc = crcfactory.GetCRC16(CRC16Factory.CRC16Type.CRC16_CCITT_XModem);
            byte[] bytes = null;
            Assert.Throws<ArgumentNullException>(() => crc.ComputeChecksum(bytes));
        }

        public class ComputeChecksum : IEnumerable<object[]>
        {
            public IEnumerator<object[]> GetEnumerator()
            {
                yield return new object[] { "0123456789", 0x9C58 };
                yield return new object[] { "ABCDEF", 0x944D };
                yield return new object[] { "abcdef", 0x3AFD };
                yield return new object[] { "this_is_a_test", 0xFA23 };
                yield return new object[] { " !$%'()*-./", 0x70D1 };
                yield return new object[] { ":;<=>?@", 0x578C };
                yield return new object[] { "[\\]^_`{|}~", 0x5D34 };
            }

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }
    }
}
