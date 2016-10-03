using System;
using System.Runtime.InteropServices;
using Channels.Networking.Windows.Tls.Internal;
using static Channels.Networking.Windows.Tls.ApplicationProtocols;

namespace Channels.Networking.Windows.Tls
{
    internal unsafe class SecureServerContext: ISecureContext
    {
        private SecurityContext _securityContext;
        private SSPIHandle _contextPointer;
        private int _headerSize = 5; //5 is the minimum (1 for frame type, 2 for version, 2 for frame size)
        private int _trailerSize = 16;
        private int _maxDataSize = 16354;
        private bool _readyToSend;
        private ApplicationProtocols.ProtocolIds _negotiatedProtocol;

        public bool ReadyToSend => _readyToSend;
        public ApplicationProtocols.ProtocolIds NegotiatedProtocol => _negotiatedProtocol;
        public int HeaderSize => _headerSize;
        public int TrailerSize => _trailerSize;
        public SSPIHandle ContextHandle => _contextPointer;

        public SecureServerContext(SecurityContext securityContext)
        {
            _securityContext = securityContext;
        }

        public void Dispose()
        {
            if (_contextPointer.IsValid) { InteropSspi.DeleteSecurityContext(ref _contextPointer); }
        }

        public byte[] ProcessContextMessage(ReadableBuffer messageBuffer)
        {
            if (messageBuffer.Length == 0)
                return null;
            SecurityBufferDescriptor input = new SecurityBufferDescriptor(3);
            SecurityBuffer* inputBuff = stackalloc SecurityBuffer[3];

            void* arrayPointer;
            if (messageBuffer.IsSingleSpan)
            {
                messageBuffer.First.TryGetPointer(out arrayPointer);
            }
            else
            {
                if (messageBuffer.Length > SecurityContext.MaxStackAllocSize)
                {
                    throw new OverflowException($"We need to create a buffer on the stack of size {messageBuffer.Length} but the max is {SecurityContext.MaxStackAllocSize}");
                }
                byte* tempBytes = stackalloc byte[messageBuffer.Length];
                messageBuffer.CopyTo(new Span<byte>(tempBytes, messageBuffer.Length));
                arrayPointer = tempBytes;
            }

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
            var localPointer = _contextPointer;
            if (_contextPointer.handleHi == IntPtr.Zero && _contextPointer.handleLo == IntPtr.Zero)
            {
                contextptr = null;
            }
            else
            {
                contextptr = &localPointer;
            }
            var errorCode = (SecurityStatus)InteropSspi.AcceptSecurityContext(ref handle, contextptr, input, SecurityContext.ServerRequiredFlags, Endianness.Native, ref _contextPointer, output, ref flags, out timestamp);

            _contextPointer = localPointer;

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
                    ContextStreamSizes ss;
                    //We have a valid context so lets query it for info
                    InteropSspi.QueryContextAttributesW(ref _contextPointer, ContextAttribute.StreamSizes, out ss);
                    _headerSize = ss.header;
                    _trailerSize = ss.trailer;

                    if (_securityContext.LengthOfSupportedProtocols > 0)
                    {
                        _negotiatedProtocol = ApplicationProtocols.FindNegotiatedProtocol(_contextPointer);
                    }
                    _readyToSend = true;
                }
                return outArray;
            }
            throw new InvalidOperationException($"We failed to build a server context {errorCode}");
        }
    }
}
