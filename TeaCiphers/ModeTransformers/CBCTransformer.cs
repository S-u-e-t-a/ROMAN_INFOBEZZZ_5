using TeaCiphers.Encoders;
using TeaCiphers.Padders;


namespace TeaCiphers.ModeTransformers;

public class CBCTransformer : IModeTransformer
{
    private bool isFirst = true;
    private byte[] tempArray;

    public override int Encrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        var tempSpan = new Span<byte>(tempArray);
        var gamma = TransfromHelper.XOR(inputBuffer, tempSpan);
        //todo finish 
        var numBytes = Cipher.Encode(Key, gamma,tempSpan);
        
        tempSpan.CopyTo(outputBuffer);
        tempArray = tempSpan.ToArray();
        return numBytes;
    }

    public override int Decrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        var decoded = new byte[outputBuffer.Length];
        var numBytes = Cipher.Decode(Key,inputBuffer, decoded);
        TransfromHelper.XOR(decoded, tempArray).AsSpan().CopyTo(outputBuffer);
        tempArray = inputBuffer.ToArray();
        
        return numBytes;
    }
    
    public CBCTransformer(ICipher cipher, byte[] key, byte[] iv, int inputBlockSize, int outputBlockSize) : base(cipher, key, iv, inputBlockSize, outputBlockSize)
    {
        tempArray = new byte[inputBlockSize];
        IV.CopyTo(tempArray,0);
        CanTransformMultipleBlocks = false;
    }
}

