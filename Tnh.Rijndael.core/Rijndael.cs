using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Tnh.Rijndael.core;


public class Rijndael
{
    private readonly (byte[], byte[]) _privateKey;

    public Rijndael(byte[] rgbKey, byte[] rgbIv)
    {
        _privateKey = (rgbKey, rgbIv);
    }

    public Rijndael()
    {
        _privateKey = (GenerateRandomKey(), GenerateRandomKey());
    }

    public (byte[], byte[]) GetKey() => _privateKey;

    private BufferedBlockCipher GetBlockCipher(bool forEncryption)
    {
        var rijndaelEngine = new RijndaelEngine(256);
        var cbcBlockCipher = new CbcBlockCipher(rijndaelEngine);
        var cipher = new BufferedBlockCipher(cbcBlockCipher);
        var keyParameter = new KeyParameter(_privateKey.Item1);
        var parametersWithIv = new ParametersWithIV(keyParameter, _privateKey.Item2);
        cipher.Init(forEncryption, parametersWithIv);
        return cipher;
    }

    public byte[] Encrypt(MemoryStream dataStream)
    {
        var cipher = GetBlockCipher(true);
        dataStream.Seek(0, SeekOrigin.Begin);
       
        var desStream = new MemoryStream();
        var buffer = new byte[cipher.GetBlockSize()];
        int bytesRead;
        while ((bytesRead = dataStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            var processedBlock = new byte[cipher.GetOutputSize(bytesRead)];
            var length = cipher.ProcessBytes(buffer, 0, bytesRead, processedBlock, 0);
            desStream.Write(processedBlock, 0, length);
            if (bytesRead >= cipher.GetBlockSize())
                continue;

            var fillFinal = FixedLengthBytes(cipher.GetBlockSize() - bytesRead).ToArray();
            var finalBlock = cipher.DoFinal(fillFinal);
            
            desStream.Write(finalBlock, 0, finalBlock.Length);
        }

        desStream.Seek(0L, SeekOrigin.Begin);
        return desStream.ToArray();
    }

   
    public MemoryStream Decrypt(Stream fileStream, int offset)
    {
        var cipher = GetBlockCipher(false);
        var memoryStream1 = new MemoryStream();
        fileStream.Seek(offset, SeekOrigin.Begin);
        memoryStream1.Seek(0, SeekOrigin.Begin);

        var buffer = new byte[cipher.GetBlockSize()];
        int bytesRead;

        while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            var processedBlock = new byte[cipher.GetOutputSize(bytesRead)];
            cipher.ProcessBytes(buffer, 0, bytesRead, processedBlock, 0);
            memoryStream1.Write(processedBlock, 0, processedBlock.Length);
            if (bytesRead >= cipher.GetBlockSize())
                continue;

            var finalBlock = cipher.DoFinal();
            memoryStream1.Write(finalBlock, 0, finalBlock.Length);
        }

        return memoryStream1;
    }
    private static byte[] FixedLengthBytes(int fixedLength)
    {
        var result = new StringBuilder();
        for (var i = 0; i < fixedLength; i++)
        {
            result.Append(' ');
        }
        return Encoding.UTF8.GetBytes(result.ToString());
    }

    private static byte[] GenerateRandomKey()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return randomNumber;
    }
}