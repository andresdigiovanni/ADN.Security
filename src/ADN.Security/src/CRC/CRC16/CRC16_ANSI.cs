using System;
using System.Collections.Generic;
using System.Text;

namespace ADN.Security
{
    /// <summary>
    /// Class CRC16 (Polynomial: 0xA001).
    /// </summary>
    public class CRC16_ANSI : CRC16
    {
        private const ushort POLYNOMIAL = 0xA001;
        private static readonly ushort[] _table = new ushort[256];

        public CRC16_ANSI()
        {
            ushort value;
            ushort temp;

            for (ushort i = 0; i < _table.Length; ++i)
            {
                value = 0;
                temp = i;

                for (byte j = 0; j < 8; ++j)
                {
                    if (((value ^ temp) & 0x0001) != 0)
                    {
                        value = (ushort)((value >> 1) ^ POLYNOMIAL);
                    }
                    else
                    {
                        value >>= 1;
                    }

                    temp >>= 1;
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
                byte index = (byte)(crc ^ bytes[i]);
                crc = (ushort)((crc >> 8) ^ _table[index]);
            }

            return crc;
        }
    }
}
