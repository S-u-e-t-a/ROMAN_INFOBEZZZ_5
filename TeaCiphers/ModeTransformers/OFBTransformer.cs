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
        CanTransformMultipleBlocks = false;
    }

    public override int Encrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        var vec = isFirst ? IV : tempArray;
        var numBytes = Cipher.Decode(Key,vec, tempArray);
        var decoded =TransfromHelper.XOR(inputBuffer, tempArray.AsSpan());
        decoded.CopyTo(outputBuffer);
        
        return numBytes;
    }

    public override int Decrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        return Encrypt(inputBuffer, outputBuffer);
    }
}
