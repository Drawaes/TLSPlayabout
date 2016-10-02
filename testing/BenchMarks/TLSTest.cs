using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Channels;
using Channels.Networking.Windows.Tls;
using Channels.Networking.Windows.Tls.Internal;
using static Channels.Networking.Windows.Tls.ApplicationProtocols;

namespace BenchMarks
{
    [Config(typeof(BenchConfig))]
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
            _MessageToPass = System.Text.Encoding.UTF8.GetBytes("tvCn6uYhKPjzauuXPOYU2xPTJuLDZqcOzJBt3xyxngr8yEh1303Am4H9tsMAl8AJDPrHK8BY5iZAcKBDO7L8AwX0NsZU7BEAk7L5f9BZqZjF06Q8vz4cWAMuGyfwXJQ9av0DcSUNz0bCuhU5jHi1sDGQHlGc0SeX8XP1KMppfXGEcGh3ZYNfepXWXvG99lKMWVHAMIu4c0gCDaOUsADSJnMwtub7yoLD0WiVO4k7XMAX9QAOuLQRcoMOYfKzGF5Ze6lAkMtYiYx2xBYUf2BTDNkvhhFjJlusIcK3fYV37592yO1ocq7RiIOQX4NrfSXev5w4EXw5Pms2AEfq3Hi1Ufpj4gJXAxkApo2qmF3EljuhxgkbBsnbW5gpfMsLqvUukkJrIEflvisiC8ZeHnOyavG7rnVxhIVenaLbKesYcJQLi6lbTcv7XDP1QcM1rGOEsTI3FSLYVPUSuOayzl7mA5e3UCK387o2cEblDrIy1VTH4kQtKx3g421brahnqGYtVyJLH4nyqBxseXC1kE6zVzkiGxE6CiZr3pH1kzntrLE5IXo7PtT2cGJIaZaErOrRWKifvSMTeTukkKIRLOIhc8jTzP58oHmtjUZc1yi9Ig8f8MVh15Fz4wZuD1LXhHElNuLV3N4pewDOv9S72wQal2U8b2kCPsvZBINVP9LrmPopKy8h3IxfyAOIG9GhBYWcs71ksOv1kDljzQptq5qEDiTTSeh9aTOZH1bXHowipJWHhkrxW1obFIokNWZ2N0r6J03lxfFs1VwpK0eMbGOtugN6slHH6XczJXnqYoJWUDqnOVANNM1U9xWJRnokKzGL8QCSLyNtzcFwl4Dbmy7QC98ZDpBsut9rXyhnDih9gNI1LsZH8J0y2A1OCTWW6DlENTwUtHs1Gyi3Gr51UF1zO1zy8bD7FRM4Yk77Yc3lQ9sTEPgJHWSx58iXY5PnqgJVftZSvkpbhg6yePDs8rCFyxo9berIFSKKJ9L7pnLM");
            ChannelFactory fact = new ChannelFactory();
            _clientChannel = fact.CreateChannel();
            _serverChannel = fact.CreateChannel();

            _serverCertificate = new X509Certificate("C:\\code\\CARoot.pfx", "Test123t");
            var serverGlobalContext = new SspiGlobal(true, _serverCertificate,ProtocolIds.Http11);

            var clientGlobalContext = new SspiGlobal(false, null, ProtocolIds.Http11);

            _clientContext = new SecureClientContext(clientGlobalContext, "timslaptop");
            _serverContext = new SecureServerContext(serverGlobalContext, "timslaptop");


            Task[] tasks = new Task[2];
            tasks[0] = new Task(async () => await SetupServer());
            tasks[1] = new Task(async () => await SetupClient());

            tasks[0].Start();
            tasks[1].Start();
            Task.WaitAll(tasks);

            var cBuffer = _clientChannel.Alloc(_MessageToPass.Length);
            cBuffer.Write(_MessageToPass);
            cBuffer.FlushAsync().Wait();
        }

        private async Task SetupServer()
        {
            ReadableBuffer buffer = default(ReadableBuffer);
            try
            {
                while (true)
                {
                    buffer = await _clientChannel.ReadAsync();
                    ReadCursor pointToSliceMessage;
                    var f = buffer.CheckForFrameType( out pointToSliceMessage);
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
                            if (_serverContext.ReadyToSend)
                                return;
                        }
                        else if (f == TlsFrameType.Invalid)
                        {
                            throw new InvalidOperationException();
                        }
                        f = buffer.CheckForFrameType( out pointToSliceMessage);
                    }
                    _clientChannel.AdvanceReader(buffer.Start, buffer.End);
                }
            }
            finally
            {
                _clientChannel.AdvanceReader(buffer.End,buffer.End);
            }
        }

        private async Task SetupClient()
        {
            ReadableBuffer buffer = default(ReadableBuffer);
            var token = _clientContext.ProcessContextMessage(default(ReadableBuffer));
            var writebuffer = _clientChannel.Alloc(token.Length);
            writebuffer.Ensure(token.Length);
            writebuffer.Write(token);
            await writebuffer.FlushAsync();
            try
            {
                while (true)
                {
                    buffer = await _serverChannel.ReadAsync();
                    ReadCursor pointToSliceMessage;
                    var f = buffer.CheckForFrameType(out pointToSliceMessage);
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
                            if (_clientContext.ReadyToSend)
                                return;
                        }
                        else if (f == TlsFrameType.Invalid)
                        {
                            throw new InvalidOperationException();
                        }
                        f = buffer.CheckForFrameType(out pointToSliceMessage);
                    }
                    _serverChannel.AdvanceReader(buffer.Start, buffer.End);
                }
            }
            finally
            {
                _serverChannel.AdvanceReader(buffer.End,buffer.End);
            }
        }

        [Benchmark]
        public void RunTest()
        {
            

            var inputBuffer = _clientChannel.ReadAsync().GetResult();
            var serverWriter = _serverChannel.Alloc(10);
            _serverContext.Encrypt(serverWriter, inputBuffer);
            serverWriter.FlushAsync().Wait();
            _clientChannel.AdvanceReader(inputBuffer.End,inputBuffer.End);

            var fromServer = _serverChannel.ReadAsync().GetResult();
            ReadableBuffer decryptedData;
            _clientContext.Decrypt(fromServer,out decryptedData );
            _serverChannel.AdvanceReader(fromServer.End,fromServer.End);

            var cBuffer = _clientChannel.Alloc();
            cBuffer.Append(ref decryptedData);
            cBuffer.Commit();
            cBuffer.FlushAsync().Wait();

        }
    }
}
