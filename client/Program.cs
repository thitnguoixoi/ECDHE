using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

class Client
{
    private byte[] publicKey;

    public Client()
    {
    }

    public void Connect(string ipAddress)
    {
        TcpClient client = new TcpClient(ipAddress, 1234);

        using (NetworkStream stream = client.GetStream())
        {
            byte[] publicKey = new byte[1024];
            int bytesRead = stream.Read(publicKey, 0, publicKey.Length);

            ECDiffieHellmanCng ecDh = new ECDiffieHellmanCng();
            ecDh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            ecDh.HashAlgorithm = CngAlgorithm.Sha256;
            byte[] clientPublicKey = ecDh.PublicKey.ToByteArray();
            stream.Write(clientPublicKey, 0, clientPublicKey.Length);

            byte[] sharedSecret = ecDh.DeriveKeyMaterial(CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob));

            Console.WriteLine($"Shared key with server: {BitConverter.ToString(sharedSecret).Replace("-", "")}");
        }

        client.Close();
    }
}

class Program
{
    static void Main(string[] args)
    {
        Client client = new Client();
        client.Connect("127.0.0.1");
    }
}