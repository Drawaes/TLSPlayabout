using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static Channels.Networking.Windows.Tls.Internal.InteropEnums;

namespace Channels.Networking.Windows.Tls.Internal
{
    public unsafe static class InteropSspi
    {
        internal const string Dll = "sspicli.dll";

        [DllImport(Dll, ExactSpelling = true, SetLastError = true)]
        internal static extern int EnumerateSecurityPackagesW([Out] out int pkgnum, [Out] out SecPkgInfo* info);

        [DllImport(Dll, ExactSpelling = true, SetLastError = true)]
        internal static extern int FreeContextBuffer([In] IntPtr contextBuffer);

        [DllImport(Dll, ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        internal unsafe static extern int AcquireCredentialsHandleW([In] string principal, [In] string moduleName, [In] int usage, [In] void* logonID, [In] ref SecureCredential authdata, [In] void* keyCallback, [In] void* keyArgument, ref SSPIHandle handlePtr, [Out] out long timeStamp);

        [DllImport(Dll, ExactSpelling = true, SetLastError = true)]
        internal static extern int FreeCredentialsHandle(ref SSPIHandle handlePtr);

        [DllImport(Dll, ExactSpelling = true, SetLastError = true)]
        internal unsafe static extern int AcceptSecurityContext(ref SSPIHandle credentialHandle, [In] void* inContextPtr, [In] SecurityBufferDescriptor inputBuffer, [In] ContextFlags inFlags, [In] Endianness endianness, ref SSPIHandle contextPtr, [In, Out] SecurityBufferDescriptor outputBuffer, [In, Out] ref ContextFlags attributes, out long timeStamp);

        [DllImport(Dll, ExactSpelling = true, SetLastError = true)]
        internal static unsafe extern int DecryptMessage([In] ref SSPIHandle contextHandle, [In, Out] SecurityBufferDescriptor inputOutput, [In] uint sequenceNumber, uint* qualityOfProtection);

        [DllImport(Dll, ExactSpelling = true, SetLastError = true)]
        internal static extern int EncryptMessage(ref SSPIHandle contextHandle, [In] uint qualityOfProtection, [In, Out] SecurityBufferDescriptor inputOutput, [In] uint sequenceNumber);

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern int QueryContextAttributesW(ref SSPIHandle phContext, [In] InteropEnums.ContextAttribute contextFlag,  [Out] out StreamSizes sizes);

        [DllImport(Dll, ExactSpelling = true, SetLastError = true)]
        internal unsafe static extern int InitializeSecurityContextW(ref SSPIHandle credentialHandle, [In] void* inContextPtr, [In] string targetName, [In] ContextFlags inFlags, [In] int reservedI, [In] Endianness endianness, SecurityBufferDescriptor* inputBuffer, [In] int reservedII, [In,Out] void* newContextPtr, [In,Out] SecurityBufferDescriptor outputBuffer, [In, Out] ref ContextFlags attributes, out long timeStamp);

        public const int SP_PROT_SSL2_SERVER = 0x00000004;
        public const int SP_PROT_SSL2_CLIENT = 0x00000008;
        public const int SP_PROT_SSL2 = (SP_PROT_SSL2_SERVER | SP_PROT_SSL2_CLIENT);

        public const int SP_PROT_SSL3_SERVER = 0x00000010;
        public const int SP_PROT_SSL3_CLIENT = 0x00000020;
        public const int SP_PROT_SSL3 = (SP_PROT_SSL3_SERVER | SP_PROT_SSL3_CLIENT);

        public const int SP_PROT_TLS1_0_SERVER = 0x00000040;
        public const int SP_PROT_TLS1_0_CLIENT = 0x00000080;
        public const int SP_PROT_TLS1_0 = (SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_0_CLIENT);

        public const int SP_PROT_TLS1_1_SERVER = 0x00000100;
        public const int SP_PROT_TLS1_1_CLIENT = 0x00000200;
        public const int SP_PROT_TLS1_1 = (SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_1_CLIENT);

        public const int SP_PROT_TLS1_2_SERVER = 0x00000400;
        public const int SP_PROT_TLS1_2_CLIENT = 0x00000800;
        public const int SP_PROT_TLS1_2 = (SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_2_CLIENT);

        public const int SP_PROT_NONE = 0;

        // These two constants are not taken from schannel.h. 
        public const int ClientProtocolMask = (SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT);
        public const int ServerProtocolMask = (SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_2_SERVER);
    }
}
