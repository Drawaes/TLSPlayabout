using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Channels.Networking.Windows.Tls.Internal;

namespace Channels.Networking.Windows.Tls
{
    public interface ISecureContext
    {
        byte[] ProcessContextMessage(ReadableBuffer messageBuffer);

        void EncryptInPlace(WritableBuffer outBuffer, ReadableBuffer buffer);
        void EncryptWithCopy(WritableBuffer outBuffer, ReadableBuffer buffer);
    }
}
