using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Channels.Networking.Windows.Tls.Internal
{

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecPkgInfo
    {
        public int fCapabilities;
        public ushort wVersion;
        public ushort wRPCID;
        public int cbMaxToken;
        public IntPtr Name;
        public IntPtr Comment;
    }
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct SSPIHandle
    {
        public IntPtr handleHi;
        public IntPtr handleLo;

        public bool IsValid => handleHi != IntPtr.Zero && handleLo != IntPtr.Zero;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    internal struct SecureCredential
    {
        public const int CurrentVersion = 0x4;

        public int version;
        public int cCreds;
        public IntPtr certContextArray;
        public IntPtr rootStore;              
        public int cMappers;
        public IntPtr phMappers;               
        public int cSupportedAlgs;
        public IntPtr palgSupportedAlgs;       
        public int grbitEnabledProtocols;
        public int dwMinimumCipherStrength;
        public int dwMaximumCipherStrength;
        public int dwSessionLifespan;
        public CredentialFlags dwFlags;
        public int reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct SecurityBuffer
    {
        public int size;
        public SecurityBufferType type;
        public void* tokenPointer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct SecurityBufferDescriptor
    {
        public int Version;
        public int Count;
        public void* UnmanagedPointer;

        public SecurityBufferDescriptor(int count)
        {
            Version = 0;
            Count = count;
            UnmanagedPointer = null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ContextStreamSizes
    {
        public int header;
        public int trailer;
        public int maximumMessage;
        public int buffersCount;
        public int blockSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct ContextApplicationProtocol
    {
        public SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS ProtoNegoStatus; // Application  protocol negotiation status
        public SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT ProtoNegoExt;       // Protocol negotiation extension type corresponding to this protocol ID
        public byte ProtocolIdSize;                                // Size in bytes of the application protocol ID
        public fixed byte ProtocolId[255];              // Byte string representing the negotiated application protocol ID
    }
}
