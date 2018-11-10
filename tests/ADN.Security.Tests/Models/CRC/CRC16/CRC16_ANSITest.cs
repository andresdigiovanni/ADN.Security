using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace ADN.Security.Tests
{
    public class CRC16_ANSITest
    {
        [Theory]
        [ClassData(typeof(ComputeChecksum))]
        public void ComputeChecksum_Bytes_Valid(string value, ushort expected)
        {
            var bytes = Encoding.ASCII.GetBytes(value);
            var crcfactory = new CRC16Factory();
            var crc = crcfactory.GetCRC16(CRC16Factory.CRC16Type.CRC16_ANSI);
            var result = crc.ComputeChecksum(bytes);

            Assert.Equal(expected, result);
        }

        [Theory]
        [ClassData(typeof(ComputeChecksum))]
        public void ComputeChecksum_String_Valid(string value, ushort expected)
        {
            var crcfactory = new CRC16Factory();
            var crc = crcfactory.GetCRC16(CRC16Factory.CRC16Type.CRC16_ANSI);
            var result = crc.ComputeChecksum(value);

            Assert.Equal(expected, result);
        }

        [Fact]
        public void ComputeChecksum_Exception_Value_Empty()
        {
            var crcfactory = new CRC16Factory();
            var crc = crcfactory.GetCRC16(CRC16Factory.CRC16Type.CRC16_ANSI);
            Assert.Throws<ArgumentNullException>(() => crc.ComputeChecksum(new byte[] { }));
        }

        [Fact]
        public void ComputeChecksum_Exception_Value_Null()
        {
            var crcfactory = new CRC16Factory();
            var crc = crcfactory.GetCRC16(CRC16Factory.CRC16Type.CRC16_ANSI);
            byte[] bytes = null;
            Assert.Throws<ArgumentNullException>(() => crc.ComputeChecksum(bytes));
        }

        public class ComputeChecksum : IEnumerable<object[]>
        {
            public IEnumerator<object[]> GetEnumerator()
            {
                yield return new object[] { "0123456789", 0x443D };
                yield return new object[] { "ABCDEF", 0xED91 };
                yield return new object[] { "abcdef", 0x5805 };
                yield return new object[] { "this_is_a_test", 0x1678 };
                yield return new object[] { " !$%'()*-./", 0xC85A };
                yield return new object[] { ":;<=>?@", 0xEDB2 };
                yield return new object[] { "[\\]^_`{|}~", 0x2C54 };
            }

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }
    }
}
