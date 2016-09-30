using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static Channels.Networking.Windows.Tls.Internal.InteropEnums;

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
    public struct SSPIHandle
    {
        public IntPtr handleHi;
        public IntPtr handleLo;

        public bool IsValid()
        {
            return handleHi != IntPtr.Zero && handleLo != IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecureCredential
    {
        public const int CurrentVersion = 0x4;

        public int version;
        public int cCreds;
        public IntPtr certContextArray;
        public IntPtr rootStore;               // == always null, OTHERWISE NOT RELIABLE
        public int cMappers;
        public IntPtr phMappers;               // == always null, OTHERWISE NOT RELIABLE
        public int cSupportedAlgs;
        public IntPtr palgSupportedAlgs;       // == always null, OTHERWISE NOT RELIABLE
        public int grbitEnabledProtocols;
        public int dwMinimumCipherStrength;
        public int dwMaximumCipherStrength;
        public int dwSessionLifespan;
        public CredentialFlags dwFlags;
        public int reserved;


    } // SecureCredential

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
        public readonly int Version;
        public readonly int Count;
        public void* UnmanagedPointer;

        public SecurityBufferDescriptor(int count)
        {
            Version = 0;
            Count = count;
            UnmanagedPointer = null;
        }
    } // SecurityBufferDescriptor

    [StructLayout(LayoutKind.Sequential)]
    internal struct StreamSizes
    {
        public int header;
        public int trailer;
        public int maximumMessage;
        public int buffersCount;
        public int blockSize;
    }
}
