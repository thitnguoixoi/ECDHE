using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;  // Sử dụng namespace có sẵn của .NET framework

class Client
{
    private byte[] publicKey;

    public Client()
    {
    }

    public void Connect(string ipAddress)
    {
        TcpClient client = new TcpClient(ipAddress, 8888); // Sử dụng port 8888 để kết nối

        using (NetworkStream stream = client.GetStream())
        {
            // Nhận và in public key ra màn hình
            byte[] publicKey = new byte[1024];
            int bytesRead = stream.Read(publicKey, 0, publicKey.Length);
            Console.WriteLine($"Server public key: {BitConverter.ToString(publicKey, 0, bytesRead).Replace("-", "")}\n");
            // Sử dụng curve384
            ECDiffieHellmanCng ecDh = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP384);  
            ecDh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            ecDh.HashAlgorithm = CngAlgorithm.Sha256;
/*            byte[] privateKey = ecDh.Key.Export(CngKeyBlobFormat.EccPrivateBlob);
            Console.WriteLine("Private key: " + BitConverter.ToString(privateKey).Replace("-", "") + "\n");*/
            // Public key của Client
            byte[] clientPublicKey = ecDh.PublicKey.ToByteArray();
            stream.Write(clientPublicKey, 0, clientPublicKey.Length);
            Console.WriteLine($"client public key: {BitConverter.ToString(clientPublicKey).Replace("-", "")}\n");
            // Private key 
            byte[] sharedSecret = ecDh.DeriveKeyMaterial(CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob));
            Console.WriteLine($"Shared key with server: {BitConverter.ToString(sharedSecret).Replace("-", "")}\n");
        }

        client.Close();
    }
}

class Program
{
    static void Main(string[] args)
    {
        Console.Write("Enter IP address: ");
        string ipAddress = Console.ReadLine();

        Client client = new Client();
        client.Connect(ipAddress);  //khởi tạo kết nối đến server
    }
}