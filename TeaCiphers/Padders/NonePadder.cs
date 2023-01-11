namespace TeaCiphers.Padders;

public class NonePadder : IPadder
{
    public byte[] Pad(byte[] block, uint requiredSize)
    {
        var newBlock = new byte[block.Length];
        block.CopyTo(newBlock,0);

        return newBlock;
    }

    public int GetPaddingLength(ReadOnlySpan<byte> block, int blockSize)
    {
        return block.Length;
    }
    
    public bool IsDepaddingRequired => false;
}
