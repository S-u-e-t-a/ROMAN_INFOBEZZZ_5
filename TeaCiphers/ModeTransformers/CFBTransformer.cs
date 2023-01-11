using System.Security.Cryptography;

using TeaCiphers.Encoders;


namespace TeaCiphers.ModeTransformers;

public class CFBTransformer: IModeTransformer
{
    private bool isFirst = true;
    private byte[] tempArray;
    public CFBTransformer(ICipher cipher, byte[] key, byte[] iv, int inputBlockSize, int outputBlockSize) : base(cipher, key, iv, inputBlockSize, outputBlockSize)
    {
        tempArray = new byte[inputBlockSize];
        IV.CopyTo(tempArray,0);
        CanTransformMultipleBlocks = false;
    }

    public override int Encrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        var tempSpan = new Span<byte>(tempArray);
        var numBytes = Cipher.Encode(Key, tempSpan,tempSpan);

        var gamma = TransfromHelper.XOR(inputBuffer, tempSpan);
        gamma.CopyTo(outputBuffer);
        tempArray = gamma.ToArray();
        return numBytes;
    }

    public override int Decrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        var tempSpan = new Span<byte>(tempArray);
        var numBytes = Cipher.Decode(Key,tempSpan, tempSpan);
        var gamma = TransfromHelper.XOR(inputBuffer, tempSpan);
        gamma.CopyTo(outputBuffer);
        tempArray = inputBuffer.ToArray();
        return numBytes;
    }
}
