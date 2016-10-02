using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Channels;
using Channels.Networking.Sockets;
using Channels.Networking.Windows.Tls;
using Channels.Networking.Windows.Tls.Internal;
using Channels.Text.Primitives;

namespace SSLServer
{
    public class Program
    {
        static X509Certificate serverCertificate = null;
        static SocketListener server;
        static SspiGlobal _global;

        public static void Main(string[] args)
        {
            serverCertificate = new X509Certificate("C:\\code\\CARoot.pfx", "Test123t");

            _global = new SspiGlobal(true, serverCertificate,ApplicationProtocols.ProtocolIds.Http2overTLS);

            
            var endpoint = new IPEndPoint(IPAddress.Any , 17777);

            server = new SocketListener();
            server.OnConnection(UserConnected);
            server.Start(endpoint);

            Console.WriteLine("Waiting");
            Console.ReadLine();
        }

        private static async void UserConnected(IChannel channel)
        {
            SecureServerContext context = new SecureServerContext(_global,"test");
            try
            {
                while (true)
                {
                   var buffer = await channel.Input.ReadAsync();


                    ReadCursor pointToSliceMessage;
                    var f = buffer.CheckForFrameType(out pointToSliceMessage);
                    while (f != TlsFrameType.Incomplete)
                    {
                        if (f == TlsFrameType.Handshake || f == TlsFrameType.ChangeCipherSpec)
                        {
                            var messageBuffer = buffer.Slice(0, pointToSliceMessage);
                            buffer = buffer.Slice(pointToSliceMessage);
                            var buff = context.ProcessContextMessage(messageBuffer);
                            if (buff != null && buff.Length > 0)
                            {
                                var output = channel.Output.Alloc(buff.Length);
                                output.Write(buff);
                                await output.FlushAsync();
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
                            ReadableBuffer decryptedData;
                            context.Decrypt(messageBuffer, out decryptedData);
                            if(decryptedData.Length >= 24);
                            {
                                //check for http/2 preface
                            }                            
                            

                        }
                        f = buffer.CheckForFrameType(out pointToSliceMessage);
                    }




                    channel.Input.Advance(buffer.Start, buffer.End);
                }


            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                context?.Dispose();
                channel?.Dispose();
            }
        }
    }
}
