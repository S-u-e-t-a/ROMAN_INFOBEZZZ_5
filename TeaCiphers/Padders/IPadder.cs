namespace TeaCiphers.Padders;

public interface IPadder
{
    public byte[] Pad(byte[] block, uint requiredSize);

    public int  GetPaddingLength(ReadOnlySpan<byte> block, int blockSize);
    public bool IsDepaddingRequired { get; }
}
