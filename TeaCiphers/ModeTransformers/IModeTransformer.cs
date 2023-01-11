using System.Security.Cryptography;

using TeaCiphers.Encoders;


namespace TeaCiphers.ModeTransformers;

public abstract class IModeTransformer
{
    public IModeTransformer(ICipher cipher, byte[] key, byte[] iv, int inputBlockSize, int outputBlockSize)
    {
        Cipher = cipher;
        Key = key;
        IV = iv;
        InputBlockSize = inputBlockSize;
        OutputBlockSize = outputBlockSize;
        
    }
    public byte[] Key { get; init; }
    public byte[] IV { get; init; }
    public ICipher Cipher { get; init; }

    public int InputBlockSize { get; init; }
    public int OutputBlockSize { get; init; }
    public bool CanTransformMultipleBlocks { get; protected set; }
    public abstract int Encrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer);
    public abstract int Decrypt(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer);


}
