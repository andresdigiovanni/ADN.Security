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

        /// <summary>
        /// Class constructor.
        /// </summary>
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

        /// <summary>
        /// Compute the checksum for a giving <see cref="Byte"> <see cref="Array"/>.
        /// </summary>
        /// <param name="value">The <see cref="Byte"> <see cref="Array"/> that contains data to compute checksum.</param>
        /// <returns>Computed checksum</returns>
        public override ushort ComputeChecksum(byte[] value)
        {
            if (ReferenceEquals(value, null) || value.Length <= 0)
            {
                throw (new ArgumentNullException("value"));
            }

            ushort crc = 0;

            for (int i = 0; i < value.Length; ++i)
            {
                byte index = (byte)(crc ^ value[i]);
                crc = (ushort)((crc >> 8) ^ _table[index]);
            }

            return crc;
        }

        /// <summary>
        /// Compute the checksum for a giving <see cref="string">.
        /// </summary>
        /// <param name="value">The <see cref="string"> that contains data to compute checksum.</param>
        /// <returns>Computed checksum</returns>
        public override ushort ComputeChecksum(string value)
        {
            return ComputeChecksum(Encoding.UTF8.GetBytes(value));
        }
    }
}
