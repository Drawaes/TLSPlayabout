using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading.Tasks;
using Channels.Networking.Windows.Tls.Internal;
using Microsoft.Win32.SafeHandles;

namespace Channels.Networking.Windows.Tls
{
    public class SecurityContext: IDisposable
    {
        internal const ContextFlags RequiredFlags = ContextFlags.ReplayDetect | ContextFlags.SequenceDetect | ContextFlags.Confidentiality | ContextFlags.AllocateMemory;
        internal const ContextFlags ServerRequiredFlags = RequiredFlags | ContextFlags.AcceptStream;
        private const string SecurityPackage = "Microsoft Unified Security Protocol Provider";
        private bool _initOkay = false;
        private int _maxTokenSize;
        private bool _isServer;
        X509Certificate _serverCertificate;
        SslProtocols _supportedProtocols = SslProtocols.Tls;
        SSPIHandle _credsHandle;
        string _hostName;
        byte[] _alpnSupportedProtocols;
        GCHandle _alpnHandle;
        internal SSPIHandle CredentialsHandle => _credsHandle;
        internal IntPtr AlpnSupportedProtocols => _alpnHandle.IsAllocated ? _alpnHandle.AddrOfPinnedObject() : IntPtr.Zero;
        internal int LengthOfSupportedProtocols => _alpnSupportedProtocols?.Length ?? 0;
        private ChannelFactory _channelFactory;
        internal string HostName => _hostName;

        public SecurityContext(ChannelFactory factory,string hostName, bool isServer, X509Certificate serverCert)
            :this(factory, hostName, isServer, serverCert, 0)
        {
        }

        public SecurityContext(ChannelFactory factory,string hostName, bool isServer, X509Certificate serverCert, ApplicationProtocols.ProtocolIds alpnSupportedProtocols)
        {
            _hostName = hostName;
            _channelFactory = factory;
            _serverCertificate = serverCert;
            _isServer = isServer;
            CreateAuthentication(alpnSupportedProtocols);
        }

        private unsafe void CreateAuthentication(ApplicationProtocols.ProtocolIds alpnSupportedProtocols)
        {
            int numberOfPackages;
            SecPkgInfo* secPointer = null;
            if (alpnSupportedProtocols > 0)
            {
                _alpnSupportedProtocols = ApplicationProtocols.GetBufferForProtocolId(alpnSupportedProtocols);
                _alpnHandle = GCHandle.Alloc(_alpnSupportedProtocols, GCHandleType.Pinned);
            }
            try
            {
                if (InteropSspi.EnumerateSecurityPackagesW(out numberOfPackages, out secPointer) != 0)
                {
                    throw new InvalidOperationException("Unable to enumerate security packages");
                }
                var size = sizeof(SecPkgInfo);

                for (int i = 0; i < numberOfPackages; i++)
                {
                    var package = secPointer[i];
                    var name = Marshal.PtrToStringUni(package.Name);
                    if (name == SecurityPackage)
                    {
                        _maxTokenSize = package.cbMaxToken;

                        //The correct security package is available
                        _initOkay = true;
                        GetCredentials();
                        return;
                    }
                }
                throw new InvalidOperationException($"Unable to find the security package named {SecurityPackage}");
            }
            finally
            {
                if (secPointer != null)
                {
                    InteropSspi.FreeContextBuffer((IntPtr)secPointer);
                }
            }
        }

        private unsafe void GetCredentials()
        {
            CredentialUse direction;
            CredentialFlags flags;
            if (_isServer)
            {
                direction = CredentialUse.Inbound;
                flags = CredentialFlags.UseStrongCrypto | CredentialFlags.SendAuxRecord;
            }
            else
            {
                direction = CredentialUse.Outbound;
                flags = CredentialFlags.ValidateManual | CredentialFlags.NoDefaultCred | CredentialFlags.SendAuxRecord | CredentialFlags.UseStrongCrypto;
            }
            
            var creds = new SecureCredential()
            {
                rootStore = IntPtr.Zero,
                phMappers = IntPtr.Zero,
                palgSupportedAlgs = IntPtr.Zero,
                cMappers = 0,
                cSupportedAlgs = 0,
                dwSessionLifespan = 0,
                reserved = 0,
                dwMinimumCipherStrength = 0, //this is required to force encryption
                dwMaximumCipherStrength = 0,
                version = SecureCredential.CurrentVersion,
                dwFlags = flags,
                certContextArray = IntPtr.Zero,
                cCreds = 0
            };
            IntPtr certPointer;

            if (_isServer)
            {
                creds.grbitEnabledProtocols = InteropSspi.ServerProtocolMask;
                certPointer = _serverCertificate.Handle;
                //pointer to the pointer
                IntPtr certPointerPointer = new IntPtr(&certPointer);
                creds.certContextArray = certPointerPointer;
                creds.cCreds = 1;
            }
            else
            {
                creds.grbitEnabledProtocols = InteropSspi.ClientProtocolMask;
            }

            long timestamp = 0;
            SecurityStatus code =(SecurityStatus) InteropSspi.AcquireCredentialsHandleW(null, SecurityPackage, (int)direction, null, ref creds, null, null, ref _credsHandle, out timestamp);
            
            if(code != 0)
            {
                throw new InvalidOperationException("Could not acquire the credentials");
            }
        }

        public SecureChannel CreateSecureChannel(IChannel channel)
        {
            var chan = new SecureChannel(channel, _channelFactory);
            if(_isServer)
            {
                chan.StartReading(new SecureServerContext(this, _hostName));
            }
            else
            {
                chan.StartReading(new SecureClientContext(this, _hostName));
            }
            return chan;
        }

        public void Dispose()
        {
            InteropSspi.FreeCredentialsHandle(ref _credsHandle);
            if(_alpnHandle.IsAllocated) { _alpnHandle.Free();} 
        }
    }
}
