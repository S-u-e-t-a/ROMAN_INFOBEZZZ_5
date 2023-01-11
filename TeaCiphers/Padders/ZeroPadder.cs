namespace TeaCiphers.Padders;

public class ZeroPadder: IPadder
{
    public byte[] Pad(byte[] block, uint requiredSize)
    {
        if (block.Length > requiredSize)
        {
            throw new ArgumentException("wtf");
        }

        if (requiredSize>255)
        {
            throw new ArgumentException("wtf");
        }
        
        var paddedBlock = new byte[requiredSize];
        block.CopyTo(paddedBlock,0);
        
        return paddedBlock;
    }

    public int GetPaddingLength(ReadOnlySpan<byte> block, int blockSize)
    {
        return blockSize;
    }


    public bool IsDepaddingRequired => false;
}
