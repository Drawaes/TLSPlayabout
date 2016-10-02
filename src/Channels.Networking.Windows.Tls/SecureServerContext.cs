using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Channels.Networking.Windows.Tls.Internal;
using static Channels.Networking.Windows.Tls.Internal.InteropEnums;

namespace Channels.Networking.Windows.Tls
{
    public unsafe class SecureServerContext: IDisposable
    {
        EncryptionPolicy _encryptPolicy;
        string _hostName;
        bool _remoteCertRequired = false;
        bool _checkCertName = false;
        bool _checkCertRevocationStatus = false;
        EncryptionPolicy _encryptionPolicy = EncryptionPolicy.RequireEncryption;
        SspiGlobal _securityContext;
        SSPIHandle _contextPointer;
        private int _headerSize = 5; //5 is the minimum (1 for frame type, 2 for version, 2 for frame size)
        private int _trailerSize = 16;
        private int _maxDataSize = 16354;
        private bool _readerToSend;
        public bool ReaderToSend => _readerToSend;
        private ApplicationProtocols.ProtocolIds _negotiatedProtocol;
        public ApplicationProtocols.ProtocolIds NegotiatedProtocol => _negotiatedProtocol;


        public SecureServerContext(SspiGlobal securityContext, string hostName)
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
            throw new NotImplementedException();
        }

        public TlsFrameType CheckForFrameType(ReadableBuffer buffer, out ReadCursor endOfMessage)
        {
            endOfMessage = buffer.Start;
            //Need at least 5 bytes to be useful
            if (buffer.Length < 5)
                return TlsFrameType.Incomplete;

            var messageType = (TlsFrameType)buffer.ReadBigEndian<byte>();
            buffer = buffer.Slice(1);

            //Check it's a valid frametype for what we are expecting
            if (messageType != TlsFrameType.AppData && messageType != TlsFrameType.Alert && messageType != TlsFrameType.ChangeCipherSpec && messageType != TlsFrameType.Handshake)
                return TlsFrameType.Invalid;

            //now we get the version

            var version = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);

            if (version < 0x300 || version >= 0x500)
            {
                return TlsFrameType.Invalid;
            }

            var length = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);

            if (buffer.Length >= length)
            {
                endOfMessage = buffer.Slice(0, length).End;
                return messageType;
            }

            return TlsFrameType.Incomplete;
        }

        public byte[] ProcessContextMessage(ReadableBuffer messageBuffer)
        {
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
            var result = InteropSspi.AcceptSecurityContext(ref handle, contextptr, input, SspiGlobal.ServerRequiredFlags, Endianness.Native, ref _contextPointer, output, ref flags, out timestamp);


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
                    _readerToSend = true;
                }
                return outArray;
            }
            throw new NotImplementedException();
        }



        public void Encrypt(WritableBuffer outBuffer, ReadableBuffer buffer)
        {
            outBuffer.Ensure(_trailerSize + _headerSize + buffer.Length);
            void* outBufferPointer;
            outBuffer.Memory.TryGetPointer(out outBufferPointer);

            buffer.CopyTo(outBuffer.Memory.Slice(_headerSize, buffer.Length));

            var securityBuff = stackalloc SecurityBuffer[4];
            SecurityBufferDescriptor sdcInOut = new SecurityBufferDescriptor(4);
            securityBuff[0].size = _headerSize;
            securityBuff[0].type = SecurityBufferType.Header;
            securityBuff[0].tokenPointer = outBufferPointer;

            securityBuff[1].size = buffer.Length;
            securityBuff[1].type = SecurityBufferType.Data;
            securityBuff[1].tokenPointer = (byte*)outBufferPointer + _headerSize;

            securityBuff[2].size = _trailerSize;
            securityBuff[2].type = SecurityBufferType.Trailer;
            securityBuff[2].tokenPointer = (byte*)outBufferPointer + _headerSize + buffer.Length;

            securityBuff[3].size = 0;
            securityBuff[3].tokenPointer = null;
            securityBuff[3].type = SecurityBufferType.Empty;

            sdcInOut.UnmanagedPointer = securityBuff;

            var result = (SecurityStatus)InteropSspi.EncryptMessage(ref _contextPointer, 0, sdcInOut, 0);
            if (result == 0)
            {
                outBuffer.Advance(_headerSize + _trailerSize + buffer.Length);
            }
            else
            {
                throw new InvalidOperationException("BlaBla");
            }

        }


        public unsafe SecurityStatus Decrypt(ReadableBuffer buffer, out ReadableBuffer decryptedData)
        {
            void* pointer;

            if (buffer.IsSingleSpan)
            {
                buffer.First.TryGetPointer(out pointer);
            }
            else
            {
                byte* tmpBuffer = stackalloc byte[buffer.Length];
                Span<byte> span = new Span<byte>(tmpBuffer, buffer.Length);
                buffer.CopyTo(span);
                pointer = tmpBuffer;
            }

            decryptedData = buffer;
            int offset = 0;
            int count = buffer.Length;

            var secStatus = DecryptMessage(pointer, ref offset, ref count);
            decryptedData = buffer.Slice(offset, count);
            //if (needsToWriteBack)
            //{
            //    var actualData = memory.Slice().Slice(offset,count);
            //    decryptedData.FirstSpan.Write(actualData);
            //}
            return secStatus;
        }

        private unsafe SecurityStatus DecryptMessage(void* buffer, ref int offset, ref int count)
        {
            var securityBuff = stackalloc SecurityBuffer[4];
            SecurityBufferDescriptor sdcInOut = new SecurityBufferDescriptor(4);
            securityBuff[0].size = count;
            securityBuff[0].tokenPointer = buffer;
            securityBuff[0].type = SecurityBufferType.Data;
            securityBuff[1].size = 0;
            securityBuff[1].tokenPointer = null;
            securityBuff[1].type = SecurityBufferType.Empty;
            securityBuff[2].size = 0;
            securityBuff[2].tokenPointer = null;
            securityBuff[2].type = SecurityBufferType.Empty;
            securityBuff[3].size = 0;
            securityBuff[3].tokenPointer = null;
            securityBuff[3].type = SecurityBufferType.Empty;

            sdcInOut.UnmanagedPointer = securityBuff;

            var errorCode = (SecurityStatus)InteropSspi.DecryptMessage(ref _contextPointer, sdcInOut, 0, null);

            if (errorCode == 0)
            {
                for (int i = 0; i < 4; i++)
                {
                    if (securityBuff[i].type == SecurityBufferType.Data)
                    {
                        //we have found the data lets find the offset
                        offset = (int)((byte*)securityBuff[i].tokenPointer - (byte*)buffer);
                        if (offset > (count - 1))
                            throw new OverflowException();
                        count = securityBuff[i].size;
                        return errorCode;
                    }
                }
            }
            throw new NotImplementedException();
        }
    }
}
