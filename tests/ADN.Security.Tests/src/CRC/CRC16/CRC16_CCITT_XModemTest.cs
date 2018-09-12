using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace ADN.Security.Tests
{
    public class CRC16_CCITT_XModemTest
    {
        [Theory]
        [InlineData("0123456789", 0x9C58)]
        [InlineData("ABCDEF", 0x944D)]
        [InlineData("abcdef", 0x3AFD)]
        [InlineData("this_is_a_test", 0xFA23)]
        [InlineData(" !$%'()*-./", 0x70D1)]
        [InlineData(":;<=>?@", 0x578C)]
        [InlineData("[\\]^_`{|}~", 0x5D34)]
        public void ComputeChecksum_Valid(string value, ushort expected)
        {
            var bytes = Encoding.ASCII.GetBytes(value);
            var crcfactory = new CRC16Factory();
            var crc = crcfactory.GetCRC16(CRC16Factory.CRC16Type.CRC16_CCITT_XModem);
            var result = crc.ComputeChecksum(bytes);

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
            Assert.Throws<ArgumentNullException>(() => crc.ComputeChecksum(null));
        }
    }
}
