﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Channels.Networking.Windows.Tls.Internal;

namespace Channels.Networking.Windows.Tls
{
    internal interface ISecureContext: IDisposable
    {
        int TrailerSize { get;}
        int HeaderSize { get;}

        SSPIHandle ContextHandle { get;}
        bool ReadyToSend { get;}
        byte[] ProcessContextMessage(ReadableBuffer messageBuffer);
        
    }
}
