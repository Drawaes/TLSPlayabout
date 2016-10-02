﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Channels.Networking.Windows.Tls.Internal;

namespace Channels.Networking.Windows.Tls
{
    internal unsafe class SecureServerContext: ISecureContext
    {
        string _hostName;
        EncryptionPolicy _encryptionPolicy = EncryptionPolicy.RequireEncryption;
        SecurityContext _securityContext;
        SSPIHandle _contextPointer;
        private int _headerSize = 5; //5 is the minimum (1 for frame type, 2 for version, 2 for frame size)
        private int _trailerSize = 16;
        private int _maxDataSize = 16354;
        private bool _readyToSend;
        public bool ReadyToSend => _readyToSend;
        private ApplicationProtocols.ProtocolIds _negotiatedProtocol;
        public ApplicationProtocols.ProtocolIds NegotiatedProtocol => _negotiatedProtocol;
        public int HeaderSize => _headerSize;
        public int TrailerSize => _trailerSize;
        public SSPIHandle ContextHandle => _contextPointer;

        public SecureServerContext(SecurityContext securityContext, string hostName)
        {
            _securityContext = securityContext;
            
            if (hostName == null)
            {
                throw new ArgumentNullException(nameof(hostName));
            }
            _hostName = hostName;
        }

        public void Dispose()
        {
            if (_contextPointer.IsValid) { InteropSspi.DeleteSecurityContext(ref _contextPointer); }
        }

        public byte[] ProcessContextMessage(ReadableBuffer messageBuffer)
        {
            if(messageBuffer.Length == 0)
                return null;
            SecurityBufferDescriptor input = new SecurityBufferDescriptor(3);
            SecurityBuffer* inputBuff = stackalloc SecurityBuffer[3];

            void* arrayPointer;
            messageBuffer.First.TryGetPointer(out arrayPointer);

            inputBuff[0] = new SecurityBuffer()
            {
                tokenPointer = arrayPointer,
                type = SecurityBufferType.Token,
                size = messageBuffer.Length
            };

            inputBuff[1] = new SecurityBuffer()
            {
                size = 0,
                tokenPointer = null,
                type = SecurityBufferType.Empty
            };
            
            if (_securityContext.LengthOfSupportedProtocols > 0)
            {
                inputBuff[2].size = _securityContext.LengthOfSupportedProtocols;
                inputBuff[2].tokenPointer = (void*)_securityContext.AlpnSupportedProtocols;
                inputBuff[2].type = SecurityBufferType.ApplicationProtocols;
            }
            else
            {
                inputBuff[2].size = 0;
                inputBuff[2].tokenPointer = null;
                inputBuff[2].type = SecurityBufferType.Empty;
            }

            input.UnmanagedPointer = inputBuff;

            SecurityBufferDescriptor output = new SecurityBufferDescriptor(3);
            SecurityBuffer* outputBuff = stackalloc SecurityBuffer[3];
            outputBuff[0].size = 0;
            outputBuff[0].tokenPointer = null;
            outputBuff[0].type = SecurityBufferType.Token;
            outputBuff[1].size = 0;
            outputBuff[1].tokenPointer = null;
            outputBuff[1].type = SecurityBufferType.Alert;
            outputBuff[2].size = 0;
            outputBuff[2].tokenPointer = null;
            outputBuff[2].type = SecurityBufferType.Empty;


            output.UnmanagedPointer = outputBuff;


            ContextFlags flags = default(ContextFlags);
            long timestamp;
            var handle = _securityContext.CredentialsHandle;
            void* contextptr;
            if (_contextPointer.handleHi == IntPtr.Zero && _contextPointer.handleLo == IntPtr.Zero)
            {
                contextptr = null;
            }
            else
            {
                contextptr = Unsafe.AsPointer(ref _contextPointer);
            }
            var result = InteropSspi.AcceptSecurityContext(ref handle, contextptr, input, SecurityContext.ServerRequiredFlags, Endianness.Native, ref _contextPointer, output, ref flags, out timestamp);


            var errorCode = (SecurityStatus)result;

            if (errorCode == SecurityStatus.ContinueNeeded || errorCode == SecurityStatus.OK)
            {
                byte[] outArray = null;
                if (outputBuff[0].size > 0)
                {
                    outArray = new byte[outputBuff[0].size];
                    Marshal.Copy((IntPtr)outputBuff[0].tokenPointer, outArray, 0, outputBuff[0].size);
                    InteropSspi.FreeContextBuffer((IntPtr)outputBuff[0].tokenPointer);
                }
                if (errorCode == SecurityStatus.OK)
                {
                    StreamSizes ss;
                    //We have a valid context so lets query it for info
                    InteropSspi.QueryContextAttributesW(ref _contextPointer, ContextAttribute.StreamSizes, out ss);
                    _headerSize = ss.header;
                    _trailerSize = ss.trailer;

                    if (_securityContext.LengthOfSupportedProtocols > 0)
                    {
                        SecPkgContext_ApplicationProtocol protoInfo;

                        InteropSspi.QueryContextAttributesW(ref _contextPointer, ContextAttribute.ApplicationProtocol, out protoInfo);

                        if (protoInfo.ProtoNegoStatus != SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS.SecApplicationProtocolNegotiationStatus_Success)
                        {
                            throw new InvalidOperationException("Could not negotiate a mutal application protocol");
                        }
                        _negotiatedProtocol = ApplicationProtocols.GetNegotiatedProtocol(protoInfo.ProtocolId, protoInfo.ProtocolIdSize);
                    }
                    _readyToSend = true;
                }
                return outArray;
            }
            throw new NotImplementedException();
        }
    }
}
