namespace TeaCiphers.Encoders;

public interface ICipher
{
    public int Encode(byte[] key, ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer);
    public int Decode(byte[] key, ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer);
}
