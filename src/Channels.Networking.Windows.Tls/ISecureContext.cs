using System;
using Channels.Networking.Windows.Tls.Internal;

namespace Channels.Networking.Windows.Tls
{
    internal interface ISecureContext: IDisposable
    {
        int TrailerSize { get; }
        int HeaderSize { get; }
        SSPIHandle ContextHandle { get; }
        bool ReadyToSend { get; }
        byte[] ProcessContextMessage(ReadableBuffer messageBuffer);

    }
}
