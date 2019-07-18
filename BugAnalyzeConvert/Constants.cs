using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BugAnalyzeConvert
{
    //each int belongs to its respective IP header and TCP header as an offset unless otherwise specified
    class HeaderByteLocations
    {
        public readonly int LeadingByteCount; //14 bytes are always first; version/header len byte follows immediately after
        public readonly int TotalLengthByte; //size of the entire packet starting from IP header, ommits padding (2 bytes)
        public readonly int ProtocolByte; //what protocol, should always be TCP (06)
        public readonly int TcpLengthByte; //length of the TCP header (.5 byte)
        public readonly int IpSource;
        public readonly int TcpSource;
        public readonly int IpDestination;
        public readonly int TcpDestination;

        public HeaderByteLocations()
        {
            LeadingByteCount = 14;
            TotalLengthByte = 2;
            ProtocolByte = 9;
            TcpLengthByte = 12;
            IpSource = 12;
            IpDestination = 16;
            TcpSource = 0;
            TcpDestination = 2;
        }
    }
}
