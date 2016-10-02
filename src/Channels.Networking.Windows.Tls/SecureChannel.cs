using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Channels.Networking.Windows.Tls.Internal;

namespace Channels.Networking.Windows.Tls
{
    public class SecureChannel<T> :IChannel where T : ISecureContext
    {
        IChannel _lowerChannel;
        Channel _outputChannel;
        Channel _inputChannel;
        T _securityContext;

        public IReadableChannel Input
        {
            get
            {
                return _outputChannel;
            }
        }

        public IWritableChannel Output
        {
            get
            {
                return _inputChannel;
            }
        }

        public SecureChannel(IChannel inChannel, ChannelFactory channelFactory, T securityContext)
        {
            _lowerChannel = inChannel;
            _inputChannel = channelFactory.CreateChannel();
            _outputChannel = channelFactory.CreateChannel();
            _securityContext = securityContext;
            StartReading();
        }

        private async void StartReading()
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
                        var buff = _securityContext.ProcessContextMessage(messageBuffer);
                        if (buff != null && buff.Length > 0)
                        {
                            var output = _lowerChannel.Output.Alloc(buff.Length);
                            output.Write(buff);
                            await output.FlushAsync();
                        }
                        if (_securityContext.ReadyToSend)
                        {
                            StartWriting();
                        }
                    }
                    else if (f == TlsFrameType.Invalid)
                    {
                        throw new InvalidOperationException();
                    }
                    else if (f == TlsFrameType.AppData)
                    {
                        var messageBuffer = buffer.Slice(0, pointToSliceMessage);
                        buffer = buffer.Slice(pointToSliceMessage);
                        var decryptedData = _outputChannel.Alloc();

                        _securityContext.Decrypt(messageBuffer, decryptedData);

                        await decryptedData.FlushAsync();


                    }
                    f = buffer.CheckForFrameType(out pointToSliceMessage);
                }
                _lowerChannel.Input.Advance(buffer.Start,buffer.End);
            }
        }

        private async void StartWriting()
        {
            while (true)
            {
                var buffer = await _inputChannel.ReadAsync();
                var outputBuffer = _lowerChannel.Output.Alloc();
                _securityContext.Encrypt(outputBuffer, buffer);
                await outputBuffer.FlushAsync();
            }
        }

        public void Dispose()
        {

        }
    }
}
