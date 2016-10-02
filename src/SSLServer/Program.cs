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
        static ChannelFactory _factory;

        public static void Main(string[] args)
        {
            serverCertificate = new X509Certificate("C:\\code\\CARoot.pfx", "Test123t");
            _factory = new ChannelFactory();
            _global = new SspiGlobal(true, serverCertificate);


            var endpoint = new IPEndPoint(IPAddress.Any, 17777);

            server = new SocketListener();
            server.OnConnection(UserConnected);
            server.Start(endpoint);

            Console.WriteLine("Waiting");
            Console.ReadLine();
        }

        private static async void UserConnected(IChannel channel)
        {
            SecureServerContext context = null;
            try
            {
                context = new SecureServerContext(_global, "test");

                var secChannel = new SecureChannel<SecureServerContext>(channel, _factory, context);

                while(true)
                {
                    var buffer = await secChannel.Input.ReadAsync();
                    Console.WriteLine(buffer.GetAsciiString());
                    secChannel.Input.Advance(buffer.End);
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
