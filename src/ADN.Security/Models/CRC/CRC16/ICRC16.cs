using System;
using System.Collections.Generic;
using System.Text;

namespace ADN.Security
{
    public interface ICRC16
    {
        ushort ComputeChecksum(byte[] value);
        ushort ComputeChecksum(string value);
    }
}
