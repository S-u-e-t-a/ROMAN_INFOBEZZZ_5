using System.Security.Cryptography;

using TeaCiphers.Encoders;


namespace TeaCiphers.ModeTransformers;

public class CFBTransformer<TCipher>: ICryptoTransform where TCipher: ICipher
{
    public void Dispose()
    {
        throw new NotImplementedException();
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        throw new NotImplementedException();
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        throw new NotImplementedException();
    }

    public bool CanReuseTransform { get; }
    public bool CanTransformMultipleBlocks { get; }
    public int InputBlockSize { get; }
    public int OutputBlockSize { get; }
}
