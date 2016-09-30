using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Channels;
using Channels.Networking.Windows.Tls;
using Channels.Networking.Windows.Tls.Internal;

namespace BenchMarks
{
    public class TLSTest
    {
        static X509Certificate _serverCertificate;
        Channel _clientChannel;
        Channel _serverChannel;
        SecureClientContext _clientContext;
        SecureServerContext _serverContext;
        byte[] _MessageToPass;

        [Setup]
        public void Setup()
        {
            _MessageToPass = System.Text.Encoding.UTF8.GetBytes("The quick brown fox");
            ChannelFactory fact = new ChannelFactory();
            _clientChannel = fact.CreateChannel();
            _serverChannel = fact.CreateChannel();

            _serverCertificate = new X509Certificate("C:\\code\\CARoot.pfx", "Test123t");
            var serverGlobalContext = new SspiGlobal(true, _serverCertificate);

            var clientGlobalContext = new SspiGlobal(false, null);

            _clientContext = new SecureClientContext(clientGlobalContext, "timslaptop");
            _serverContext = new SecureServerContext(serverGlobalContext, "timslaptop", null);


            Task[] tasks = new Task[2];
            tasks[0] = new Task(async () => await SetupServer());
            tasks[1] = new Task(async () => await SetupClient());

            tasks[0].Start();
            tasks[1].Start();
            Task.WaitAll(tasks);
        }

        private async Task SetupServer()
        {
            while (true)
            {
                var buffer = await _clientChannel.ReadAsync();
                ReadCursor pointToSliceMessage;
                var f = _serverContext.CheckForFrameType(buffer, out pointToSliceMessage);
                while (f != TlsFrameType.Incomplete)
                {
                    if (f == TlsFrameType.Handshake || f == TlsFrameType.ChangeCipherSpec)
                    {
                        var messageBuffer = buffer.Slice(0, pointToSliceMessage);
                        buffer = buffer.Slice(pointToSliceMessage);
                        var buff = _serverContext.ProcessContextMessage(messageBuffer);
                        if (buff != null && buff.Length > 0)
                        {
                            var output = _serverChannel.Alloc(buff.Length);
                            output.Write(buff);
                            await output.FlushAsync();
                        }
                        if (_serverContext.ReaderToSend)
                            return;
                    }
                    else if (f == TlsFrameType.Invalid)
                    {
                        throw new InvalidOperationException();
                    }
                    f = _serverContext.CheckForFrameType(buffer, out pointToSliceMessage);
                }
                _clientChannel.AdvanceReader(buffer.Start, buffer.End);
            }
        }

        private async Task SetupClient()
        {
            var token = _clientContext.ProcessContextMessage(default(ReadableBuffer));
            var writebuffer = _clientChannel.Alloc(token.Length);
            writebuffer.Ensure(token.Length);
            writebuffer.Write(token);
            await writebuffer.FlushAsync();

            while (true)
            {
                var buffer = await _serverChannel.ReadAsync();
                ReadCursor pointToSliceMessage;
                var f = _clientContext.CheckForFrameType(buffer, out pointToSliceMessage);
                while (f != TlsFrameType.Incomplete)
                {
                    if (f == TlsFrameType.Handshake || f == TlsFrameType.ChangeCipherSpec)
                    {
                        var messageBuffer = buffer.Slice(0, pointToSliceMessage);
                        buffer = buffer.Slice(pointToSliceMessage);
                        var buff = _clientContext.ProcessContextMessage(messageBuffer);
                        if (buff != null && buff.Length > 0)
                        {
                            var output = _clientChannel.Alloc(buff.Length);
                            output.Ensure(buff.Length);
                            output.Write(buff);
                            await output.FlushAsync();
                        }
                        if (_clientContext.ReaderToSend)
                            return;
                    }
                    else if (f == TlsFrameType.Invalid)
                    {
                        throw new InvalidOperationException();
                    }
                    f = _clientContext.CheckForFrameType(buffer, out pointToSliceMessage);
                }
                _serverChannel.AdvanceReader(buffer.Start, buffer.End);
            }
        }

        public void RunTest()
        {
            var cBuffer = _clientChannel.Alloc(_MessageToPass.Length);
            cBuffer.Write(_MessageToPass);
            cBuffer.FlushAsync();


        }
    }
}
