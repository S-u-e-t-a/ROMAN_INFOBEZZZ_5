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
        //var tempSpan = new Span<byte>(tempArray);
        var temp2 = new byte[tempArray.Length];
        var numBytes = Cipher.Encode(Key, tempArray,temp2);

        var gamma = TransfromHelper.XOR(inputBuffer, temp2);
        gamma.CopyTo(outputBuffer);
        gamma.CopyTo(tempArray);
        return numBytes;
    }

    public override int Decrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        var temp2 = new byte[tempArray.Length];
        var numBytes = Cipher.Decode(Key,tempArray, temp2);
        var gamma = TransfromHelper.XOR(inputBuffer, temp2);
        gamma.CopyTo(outputBuffer);
        inputBuffer.CopyTo(tempArray);
        return numBytes;
    }
}
