using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Channels;
using Channels.Networking.Sockets;
using Channels.Networking.Windows.Tls;
using Channels.Text.Primitives;

namespace SSLServer
{
    public class Program
    {
        static X509Certificate serverCertificate = null;
        static SocketListener server;
        static SecurityContext _global;
        static ChannelFactory _factory;

        public static void Main(string[] args)
        {
            serverCertificate = new X509Certificate("C:\\code\\CARoot.pfx", "Test123t");
            _factory = new ChannelFactory();
            _global = new SecurityContext(_factory,"timslaptop", true, serverCertificate);


            var endpoint = new IPEndPoint(IPAddress.Any, 17777);

            server = new SocketListener();
            server.OnConnection(UserConnected);
            server.Start(endpoint);

            Console.WriteLine("Waiting");
            Console.ReadLine();
        }

        private static async void UserConnected(IChannel channel)
        {
            Channels.Networking.Windows.Tls.

            SecureChannel sChannel = null;
            try
            {
                sChannel = _global.CreateSecureChannel(channel);

                while (true)
                {
                    var buffer = await sChannel.Input.ReadAsync();
                    Console.WriteLine(buffer.GetAsciiString());
                    sChannel.Input.Advance(buffer.End);
                }


            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                sChannel?.Dispose();
                channel?.Dispose();
            }
        }
    }
}
