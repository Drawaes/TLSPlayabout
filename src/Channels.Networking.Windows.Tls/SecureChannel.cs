using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Channels.Networking.Windows.Tls.Internal;

namespace Channels.Networking.Windows.Tls
{
    public class SecureChannel: IChannel
    {
        IChannel _lowerChannel;
        Channel _outputChannel;
        Channel _inputChannel;

        public IReadableChannel Input => _outputChannel;
        public IWritableChannel Output => _inputChannel;

        public SecureChannel(IChannel inChannel, ChannelFactory channelFactory)
        {
            _lowerChannel = inChannel;
            _inputChannel = channelFactory.CreateChannel();
            _outputChannel = channelFactory.CreateChannel();
        }

        internal async void StartReading<T>(T securityContext) where T : ISecureContext
        {
            while (true)
            {
                var buffer = await _lowerChannel.Input.ReadAsync();

                ReadCursor pointToSliceMessage;
                var f = buffer.CheckForFrameType(out pointToSliceMessage);
                while (f != TlsFrameType.Incomplete)
                {
                    if (f == TlsFrameType.Handshake || f == TlsFrameType.ChangeCipherSpec)
                    {
                        var messageBuffer = buffer.Slice(0, pointToSliceMessage);
                        buffer = buffer.Slice(pointToSliceMessage);
                        var buff = securityContext.ProcessContextMessage(messageBuffer);
                        if (buff != null && buff.Length > 0)
                        {
                            var output = _lowerChannel.Output.Alloc(buff.Length);
                            output.Write(buff);
                            await output.FlushAsync();
                        }
                        if (securityContext.ReadyToSend)
                        {
                            StartWriting(securityContext);
                        }
                    }
                    else if (f == TlsFrameType.Invalid)
                    {
                        throw new InvalidOperationException("We have recieved an invalid tls frame");
                    }
                    else if (f == TlsFrameType.AppData)
                    {
                        var messageBuffer = buffer.Slice(0, pointToSliceMessage);
                        buffer = buffer.Slice(pointToSliceMessage);
                        var decryptedData = _outputChannel.Alloc();

                        securityContext.Decrypt(messageBuffer, decryptedData);

                        await decryptedData.FlushAsync();
                    }
                    f = buffer.CheckForFrameType(out pointToSliceMessage);
                }
                _lowerChannel.Input.Advance(buffer.Start, buffer.End);
            }
        }

        private async void StartWriting<T>(T securityContext) where T : ISecureContext
        {
            while (true)
            {
                var buffer = await _inputChannel.ReadAsync();
                var outputBuffer = _lowerChannel.Output.Alloc();
                securityContext.Encrypt(outputBuffer, buffer);
                await outputBuffer.FlushAsync();
            }
        }

        public void Dispose()
        {

        }
    }
}
