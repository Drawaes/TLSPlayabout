using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Channels.Networking.Windows.Tls.Internal;

namespace Channels.Networking.Windows.Tls
{
    public static class ReadableBufferExtensions
    {
        public static TlsFrameType CheckForFrameType(this ReadableBuffer buffer, out ReadCursor endOfMessage)
        {
            endOfMessage = buffer.Start;
            //Need at least 5 bytes to be useful
            if (buffer.Length < 5)
                return TlsFrameType.Incomplete;

            var messageType = (TlsFrameType)buffer.ReadBigEndian<byte>();
            buffer = buffer.Slice(1);

            //Check it's a valid frametype for what we are expecting
            if (messageType != TlsFrameType.AppData && messageType != TlsFrameType.Alert && messageType != TlsFrameType.ChangeCipherSpec && messageType != TlsFrameType.Handshake)
                return TlsFrameType.Invalid;

            //now we get the version

            var version = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);

            if (version < 0x300 || version >= 0x500)
            {
                return TlsFrameType.Invalid;
            }

            var length = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);

            if (buffer.Length >= length)
            {
                endOfMessage = buffer.Slice(0, length).End;
                return messageType;
            }

            return TlsFrameType.Incomplete;
        }
    }
}
