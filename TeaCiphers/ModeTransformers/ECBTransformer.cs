using System.Security.Cryptography;

using TeaCiphers.Encoders;


namespace TeaCiphers.ModeTransformers;

public class ECBTransformer: IModeTransformer
{
    public ECBTransformer(ICipher cipher, byte[] key, byte[] iv, int inputBlockSize, int outputBlockSize) : base(cipher, key, iv, inputBlockSize, outputBlockSize)
    {
    }

    public override int Encrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        var numBytes = Cipher.Encode(Key,inputBuffer, outputBuffer);

        return numBytes;
    }

    public override int Decrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        var numBytes = Cipher.Decode(Key,inputBuffer, outputBuffer);

        return numBytes;
    }
}
