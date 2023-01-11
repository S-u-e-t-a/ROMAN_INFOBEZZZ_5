using TeaCiphers.Encoders;
using TeaCiphers.Padders;


namespace TeaCiphers.ModeTransformers;

public class CBCTransformer : IModeTransformer
{
    private bool isFirst = true;
    private byte[] tempArray;

    public override int Encrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        tempArray = isFirst ? IV : tempArray;
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
        var vec = isFirst ? IV : tempArray;
        var numBytes = Cipher.Decode(Key,inputBuffer, tempArray);
        var decoded = new Span<byte>(TransfromHelper.XOR(vec, tempArray));
        tempArray = inputBuffer.ToArray();
        
        decoded.CopyTo(outputBuffer);
        return numBytes;
    }
    
    public CBCTransformer(ICipher cipher, byte[] key, byte[] iv, int inputBlockSize, int outputBlockSize) : base(cipher, key, iv, inputBlockSize, outputBlockSize)
    {
        tempArray = new byte[inputBlockSize];
        CanTransformMultipleBlocks = false;
    }
}

