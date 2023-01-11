﻿using System.Security.Cryptography;


namespace TeaCiphers.Padders;

public class PKCS7Padder : IPadder
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

        for (int i = 0; i < last; i++)
        {
            paddedBlock[i + block.Length] = last;
        }
        
        

        return paddedBlock;
    }

    public int GetPaddingLength(ReadOnlySpan<byte> block, int blockSize)
    {
        var padBytes = block[^1];

        // Verify the amount of padding is reasonable
        if (padBytes <= 0 || padBytes > blockSize)
            throw new CryptographicException("Invalid Padding");

        // Verify all the padding bytes match the amount of padding
        for (int i = block.Length - padBytes; i < block.Length - 1; i++)
        {
            if (block[i] != padBytes)
                throw new CryptographicException("Invalid Padding");
        }

        return block.Length - padBytes;
    }


    public bool IsDepaddingRequired => true;
}
