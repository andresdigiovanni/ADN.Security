using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace ADN.Security.Tests
{
    public class CRC16_ANSITest
    {
        [Theory]
        [InlineData("0123456789", 0x443D)]
        [InlineData("ABCDEF", 0xED91)]
        [InlineData("abcdef", 0x5805)]
        [InlineData("this_is_a_test", 0x1678)]
        [InlineData(" !$%'()*-./", 0xC85A)]
        [InlineData(":;<=>?@", 0xEDB2)]
        [InlineData("[\\]^_`{|}~", 0x2C54)]
        public void ComputeChecksum_Valid(string value, ushort expected)
        {
            var bytes = Encoding.ASCII.GetBytes(value);
            var crcfactory = new CRC16Factory();
            var crc = crcfactory.GetCRC16(CRC16Factory.CRC16Type.CRC16_ANSI);
            var result = crc.ComputeChecksum(bytes);

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
            Assert.Throws<ArgumentNullException>(() => crc.ComputeChecksum(null));
        }
    }
}
