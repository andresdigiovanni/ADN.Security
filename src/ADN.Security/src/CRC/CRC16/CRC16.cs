using System;
using System.Collections.Generic;
using System.Text;

namespace ADN.Security
{
    public abstract class CRC16
    {
        public abstract ushort ComputeChecksum(byte[] bytes);
    }
}
