using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static Channels.Networking.Windows.Tls.Internal.InteropEnums;

namespace Channels.Networking.Windows.Tls.Internal
{
    public class SspiGlobal: IDisposable
    {
        public const ContextFlags RequiredFlags = ContextFlags.ReplayDetect | ContextFlags.SequenceDetect | ContextFlags.Confidentiality | ContextFlags.AllocateMemory;
        public const ContextFlags ServerRequiredFlags = RequiredFlags | ContextFlags.AcceptStream;
        private const string SecurityPackage = "Microsoft Unified Security Protocol Provider";
        private bool _initOkay = false;
        private int _maxTokenSize;
        private bool _isServer;
        X509Certificate _serverCertificate;
        SslProtocols _supportedProtocols = SslProtocols.Tls;
        SSPIHandle _CredsHandle;

        public unsafe SspiGlobal(bool isServer,X509Certificate serverCert)
        {
            _serverCertificate = serverCert;
            _isServer = isServer;
            int numberOfPackages;
            SecPkgInfo* secPointer = null;
            try
            {
                if(InteropSspi.EnumerateSecurityPackagesW(out numberOfPackages, out secPointer) != 0)
                {
                    throw new InvalidOperationException("Unable to enumerate security packages");
                }
                var size = sizeof(SecPkgInfo);

                for (int i = 0; i < numberOfPackages; i++)
                {
                    var package = secPointer[i];
                    var name = Marshal.PtrToStringUni(package.Name);
                    if(name == SecurityPackage)
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
            SecurityStatus code =(SecurityStatus) InteropSspi.AcquireCredentialsHandleW(null, SecurityPackage, (int)direction, null, ref creds, null, null, ref _CredsHandle, out timestamp);
            
            if(code != 0)
            {
                throw new InvalidOperationException("Could not acquire the credentials");
            }
        }

        public void Dispose()
        {
            InteropSspi.FreeCredentialsHandle(ref _CredsHandle);
        }

        public SSPIHandle CredsHandle => _CredsHandle;
    }
}
