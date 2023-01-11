using System.Security.Cryptography;

using TeaCiphers.Encoders;


namespace TeaCiphers.ModeTransformers;

public class OFBTransformer: IModeTransformer
{
    private bool isFirst = true;
    private byte[] tempArray;
    public OFBTransformer(ICipher cipher, byte[] key, byte[] iv, int inputBlockSize, int outputBlockSize) : base(cipher, key, iv, inputBlockSize, outputBlockSize)
    {
        tempArray = new byte[inputBlockSize];
        IV.CopyTo(tempArray,0);
        CanTransformMultipleBlocks = false;
    }

    public override int Encrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        var decoded = new byte[outputBuffer.Length];
        var numBytes = Cipher.Decode(Key,tempArray, decoded);
        decoded.CopyTo(tempArray,0);
        var gamma =TransfromHelper.XOR(inputBuffer, tempArray.AsSpan());
        gamma.CopyTo(outputBuffer);
        
        return numBytes;
    }

    public override int Decrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        return Encrypt(inputBuffer, outputBuffer);
    }
}
