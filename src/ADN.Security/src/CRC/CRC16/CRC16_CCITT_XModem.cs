using System;
using System.Collections.Generic;
using System.Text;

namespace ADN.Security
{
    /// <summary>
    /// Class CRC16_CCITT_XModem (Polynomial: 0x1021).
    /// </summary>
    public class CRC16_CCITT_XModem : CRC16
    {
        private const ushort POLYNOMIAL = 0x1021;
        private static readonly ushort[] _table = new ushort[256];

        public CRC16_CCITT_XModem()
        {
            ushort value;
            ushort temp;

            for (ushort i = 0; i < _table.Length; ++i)
            {
                value = 0;
                temp = (ushort)(i << 8);

                for (byte j = 0; j < 8; ++j)
                {
                    if (((value ^ temp) & 0x8000) != 0)
                    {
                        value = (ushort)((value << 1) ^ POLYNOMIAL);
                    }
                    else
                    {
                        value <<= 1;
                    }

                    temp <<= 1;
                }
                _table[i] = value;
            }
        }

        public override ushort ComputeChecksum(byte[] bytes)
        {
            if (ReferenceEquals(bytes, null) || bytes.Length <= 0)
            {
                throw (new ArgumentNullException("bytes"));
            }

            ushort crc = 0;

            for (int i = 0; i < bytes.Length; ++i)
            {
                byte index = (byte)((crc >> 8) ^ (0xff & bytes[i]));
                crc = (ushort)((crc << 8) ^ _table[index]);
            }

            return crc;
        }
    }
}
