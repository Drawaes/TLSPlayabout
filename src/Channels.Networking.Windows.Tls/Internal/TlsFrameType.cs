namespace Channels.Networking.Windows.Tls.Internal
{
    internal enum TlsFrameType
    {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        AppData = 23,
        Invalid = -1,
        Incomplete = 0
    }
}
