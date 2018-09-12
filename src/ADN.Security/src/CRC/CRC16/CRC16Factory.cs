using System;
using System.Collections.Generic;
using System.Text;

namespace ADN.Security
{
    public class CRC16Factory
    {
        public enum CRC16Type
        {
            CRC16_ANSI,
            CRC16_CCITT_XModem
        }

        public CRC16 GetCRC16(CRC16Type type)
        {
            switch (type)
            {
                case CRC16Type.CRC16_ANSI:
                    return new CRC16_ANSI();

                case CRC16Type.CRC16_CCITT_XModem:
                    return new CRC16_CCITT_XModem();
            }

            return null;
        }
    }
}
