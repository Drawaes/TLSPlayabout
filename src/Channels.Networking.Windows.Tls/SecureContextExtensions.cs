using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Channels.Networking.Windows.Tls.Internal;

namespace Channels.Networking.Windows.Tls
{
    internal static class SecureContextExtensions
    {
        internal static unsafe void Encrypt<T>(this T context, WritableBuffer outBuffer, ReadableBuffer buffer) where T :ISecureContext
        {
            outBuffer.Ensure( context.TrailerSize + context.HeaderSize + buffer.Length);
            void* outBufferPointer;
            outBuffer.Memory.TryGetPointer(out outBufferPointer);

            buffer.CopyTo(outBuffer.Memory.Slice(context.HeaderSize, buffer.Length));

            var securityBuff = stackalloc SecurityBuffer[4];
            SecurityBufferDescriptor sdcInOut = new SecurityBufferDescriptor(4);
            securityBuff[0].size = context.HeaderSize;
            securityBuff[0].type = SecurityBufferType.Header;
            securityBuff[0].tokenPointer = outBufferPointer;

            securityBuff[1].size = buffer.Length;
            securityBuff[1].type = SecurityBufferType.Data;
            securityBuff[1].tokenPointer = (byte*)outBufferPointer + context.HeaderSize;

            securityBuff[2].size = context.TrailerSize;
            securityBuff[2].type = SecurityBufferType.Trailer;
            securityBuff[2].tokenPointer = (byte*)outBufferPointer + context.HeaderSize + buffer.Length;

            securityBuff[3].size = 0;
            securityBuff[3].tokenPointer = null;
            securityBuff[3].type = SecurityBufferType.Empty;

            sdcInOut.UnmanagedPointer = securityBuff;

            var handle = context.ContextHandle;
            var result = (SecurityStatus)InteropSspi.EncryptMessage(ref handle, 0, sdcInOut, 0);
            if (result == 0)
            {
                outBuffer.Advance(context.HeaderSize + context.TrailerSize + buffer.Length);
            }
            else
            {
                //Zero out the output buffer before throwing the exception to stop any data being sent in the clear
                //By a misbehaving underlying channel
                Span<byte> memoryToClear = new Span<byte>(outBufferPointer, context.HeaderSize + context.TrailerSize + buffer.Length);
                byte* empty = stackalloc byte[context.HeaderSize + context.TrailerSize + buffer.Length];
                memoryToClear.Set(empty, context.HeaderSize + context.TrailerSize + buffer.Length);
                throw new InvalidOperationException($"There was an issue encrypting the data {result}");
            }

        }

        internal static unsafe SecurityStatus Decrypt<T>(this T context, ReadableBuffer buffer, WritableBuffer decryptedData) where T : ISecureContext
        {
            void* pointer;
            if (buffer.IsSingleSpan)
            {
                buffer.First.TryGetPointer(out pointer);
            }
            else
            {
                if (buffer.Length > SecurityContext.MaxStackAllocSize)
                {
                    throw new OverflowException($"We need to create a buffer on the stack of size {buffer.Length} but the max is {SecurityContext.MaxStackAllocSize}");
                }
                byte* tmpBuffer = stackalloc byte[buffer.Length];
                Span<byte> span = new Span<byte>(tmpBuffer, buffer.Length);
                buffer.CopyTo(span);
                pointer = tmpBuffer;
            }
            
            int offset = 0;
            int count = buffer.Length;

            var secStatus = DecryptMessage(pointer, ref offset, ref count, context.ContextHandle);
            if (buffer.IsSingleSpan)
            {
                buffer = buffer.Slice(offset, count);
                decryptedData.Append(ref buffer);
            }
            else
            {
                decryptedData.Ensure(buffer.Length);
                decryptedData.Write(new Span<byte>(pointer, buffer.Length));
            }
            return secStatus;
        }

        private static unsafe SecurityStatus DecryptMessage(void* buffer, ref int offset, ref int count, SSPIHandle context)
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

            var errorCode = (SecurityStatus)InteropSspi.DecryptMessage(ref context, sdcInOut, 0, null);

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
            throw new InvalidOperationException($"There was an error ncrypting the data {errorCode}");
        }
        internal static TlsFrameType CheckForFrameType(this ReadableBuffer buffer, out ReadCursor endOfMessage)
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
    }
}
