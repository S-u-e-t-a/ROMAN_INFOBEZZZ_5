using System.Security.Cryptography;


namespace TeaCiphers.Padders;

public class ISO10126Padder:IPadder
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

        uint paddedBlockSize;
        byte last;

        if (block.Length == requiredSize)
        {
            paddedBlockSize = requiredSize * 2;
            last = (byte) requiredSize;
        }
        else
        {
            paddedBlockSize = requiredSize ;
            last = (byte) (requiredSize- block.Length);
        }
        var paddedBlock = new byte[paddedBlockSize];
        block.CopyTo(paddedBlock,0);
        
        RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        rng.GetBytes(paddedBlock, block.Length,last-1);
        
        paddedBlock[^1] = last;

        return paddedBlock;
    }

    public int GetPaddingLength(ReadOnlySpan<byte> block, int blockSize)
    {
        int padBytes;
        padBytes = block[^1];

        // Verify the amount of padding is reasonable
        if (padBytes <= 0 || padBytes > blockSize)
        {
            throw new CryptographicException("Invalid padding");
        }

        return block.Length - padBytes;

    }


    public bool IsDepaddingRequired => true;
}
