﻿using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

class Server
{
    private TcpListener listener;
    private ECDiffieHellmanCng ecDh;
    private byte[] publicKey;

    public Server()
    {
        ecDh = new ECDiffieHellmanCng();
        ecDh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
        ecDh.HashAlgorithm = CngAlgorithm.Sha256;
        publicKey = ecDh.PublicKey.ToByteArray();
    }

    public void Start()
    {
        listener = new TcpListener(IPAddress.Any, 8888);
        listener.Start();

        Console.WriteLine("Server started. Waiting for connections...");

        while (true)
        {
            TcpClient client = listener.AcceptTcpClient();
            Console.WriteLine($"Client {((IPEndPoint)client.Client.RemoteEndPoint).Address} connected.");

            using (NetworkStream stream = client.GetStream())
            {
                stream.Write(publicKey, 0, publicKey.Length);
                Console.WriteLine($"server public key: {BitConverter.ToString(publicKey).Replace("-", "")}");
                byte[] clientPublicKey = new byte[ecDh.PublicKey.ToByteArray().Length];
                stream.Read(clientPublicKey, 0, clientPublicKey.Length);
                Console.WriteLine($"client public key: {BitConverter.ToString(clientPublicKey).Replace("-", "")}");
                byte[] sharedSecret = ecDh.DeriveKeyMaterial(CngKey.Import(clientPublicKey, CngKeyBlobFormat.EccPublicBlob));
                Console.WriteLine($"Shared key with client {((IPEndPoint)client.Client.RemoteEndPoint).Address}: {BitConverter.ToString(sharedSecret).Replace("-", "")}");

            }
            client.Close();
            Console.WriteLine($"Connection with client {((IPEndPoint)client.Client.RemoteEndPoint).Address} closed.");
        }
    }
}

class Program
{
    static void Main(string[] args)
    {
        try
        {

            Server server = new Server();
            server.Start();
        }
        catch (Exception e) { }
    }
}