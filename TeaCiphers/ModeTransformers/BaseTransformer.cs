using System.Security.Cryptography;

using TeaCiphers.Padders;


namespace TeaCiphers.ModeTransformers;

public class Transformer: ICryptoTransform

{
    public Transformer(IModeTransformer transformer, IPadder padder, bool encryption, int inputBlockSize, int outputBlockSize)
    {
        ModeTransformer = transformer;
        Padder = padder;
        Encryption = encryption;
        InputBlockSize = inputBlockSize;
        OutputBlockSize = outputBlockSize;
    }
    public void Dispose()
    {
        throw new NotImplementedException();
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        if (Encryption)
        {
            return ModeTransformer.Encrypt(new ReadOnlySpan<byte>(inputBuffer, inputOffset, inputCount), outputBuffer);
        }
        else
        {
            return UncheckedTransformBlock(new ReadOnlySpan<byte>(inputBuffer, inputOffset, inputCount), outputBuffer);
        }
        
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        if (Encryption)
        {
            var paddedBlock = Padder.Pad(inputBuffer[new Range(inputOffset, inputOffset + inputCount)], (uint) InputBlockSize);
            var transformedBlock = new byte[paddedBlock.Length];

            if (transformedBlock.Length == InputBlockSize * 2)
            {
                // var part1 = paddedBlock[new Range(0, InputBlockSize)];
                // var part2 = paddedBlock[new Range(InputBlockSize, InputBlockSize * 2)];
                // ModeTransformer.Encrypt(part1, transformedBlock);
                // ModeTransformer.Encrypt(part2, transformedBlock);
                // Encrypt(part2, 0, InputBlockSize).CopyTo(transformedBlock,InputBlockSize);
            }
            else if (transformedBlock.Length == InputBlockSize)
            {
                var part1 = paddedBlock[new Range(0, InputBlockSize)];
                ModeTransformer.Encrypt(part1, transformedBlock);
            }
            else
            {
                throw new Exception("блок не того размера!");
            }

            return transformedBlock;
        }
        else
        {
            return UncheckedTransformFinalBlock(inputBuffer, inputOffset, inputCount);
        }
    }

    // взято с System.Security.Cryptography.UniversalCryptoDecryptor
    private int UncheckedTransformBlock(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
        {
            //
            // If we're decrypting, it's possible to be called with the last blocks of the data, and then
            // have TransformFinalBlock called with an empty array. Since we don't know if this is the case,
            // we won't decrypt the last block of the input until either TransformBlock or
            // TransformFinalBlock is next called.
            //
            // We don't need to do this for PaddingMode.None because there is no padding to strip, and
            // we also don't do this for PaddingMode.Zeros since there is no way for us to tell if the
            // zeros at the end of a block are part of the plaintext or the padding.
            //
            int decryptedBytes = 0;
            if (Padder.IsDepaddingRequired)
            {
                // If we have data saved from a previous call, decrypt that into the output first
                if (_heldoverCipher != null)
                {
                    int depadDecryptLength = ModeTransformer.Decrypt(_heldoverCipher, outputBuffer);
                    outputBuffer = outputBuffer.Slice(depadDecryptLength);
                    decryptedBytes += depadDecryptLength;
                }
                else
                {
                    _heldoverCipher = new byte[InputBlockSize];
                }

                // Postpone the last block to the next round.
                inputBuffer.Slice(inputBuffer.Length - _heldoverCipher.Length).CopyTo(_heldoverCipher);
                inputBuffer = inputBuffer.Slice(0, inputBuffer.Length - _heldoverCipher.Length);
            }

            if (inputBuffer.Length > 0)
            {
                decryptedBytes += ModeTransformer.Decrypt(inputBuffer, outputBuffer);
            }

            return decryptedBytes;
        }
    

    private unsafe int UncheckedTransformFinalBlock(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
        {
            // We can't complete decryption on a partial block
            if (inputBuffer.Length % InputBlockSize != 0)
                throw new CryptographicException("can't complete decryption on a partial block");

            //
            // If we have postponed cipher bits from the prior round, copy that into the decryption buffer followed by the input data.
            // Otherwise the decryption buffer is just the input data.
            //

            ReadOnlySpan<byte> inputCiphertext;
            Span<byte> ciphertext;
            byte[]? rentedCiphertext = null;
            int rentedCiphertextSize = 0;

            try
            {
                if (_heldoverCipher == null)
                {
                    rentedCiphertextSize = inputBuffer.Length;
                    rentedCiphertext = new byte[inputBuffer.Length];
                    //rentedCiphertext = CryptoPool.Rent(inputBuffer.Length);
                    ciphertext = rentedCiphertext.AsSpan(0, inputBuffer.Length);
                    inputCiphertext = inputBuffer;
                }
                else
                {
                    rentedCiphertextSize = _heldoverCipher.Length + inputBuffer.Length;
                    rentedCiphertext = new byte[rentedCiphertextSize];
                    //rentedCiphertext = CryptoPool.Rent(rentedCiphertextSize);
                    ciphertext = rentedCiphertext.AsSpan(0, rentedCiphertextSize);
                    _heldoverCipher.AsSpan().CopyTo(ciphertext);
                    inputBuffer.CopyTo(ciphertext.Slice(_heldoverCipher.Length));

                    // Decrypt in-place
                    inputCiphertext = ciphertext;
                }

                int unpaddedLength = 0;

                fixed (byte* pCiphertext = ciphertext)
                {
                    // Decrypt the data, then strip the padding to get the final decrypted data. Note that even if the cipherText length is 0, we must
                    // invoke TransformFinal() so that the cipher object knows to reset for the next cipher operation.
                    int decryptWritten = ModeTransformer.Decrypt(inputCiphertext, ciphertext);
                    Span<byte> decryptedBytes = ciphertext.Slice(0, decryptWritten);

                    if (decryptedBytes.Length > 0)
                    {
                        unpaddedLength = Padder.GetPaddingLength(decryptedBytes, InputBlockSize);
                        decryptedBytes.Slice(0, unpaddedLength).CopyTo(outputBuffer);
                    }
                }
                
                return unpaddedLength;
            }
            finally
            {
                // if (rentedCiphertext != null)
                // {
                //     CryptoPool.Return(rentedCiphertext, clearSize: rentedCiphertextSize);
                // }
            }
        }

        protected unsafe byte[] UncheckedTransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (Padder.IsDepaddingRequired)
            {
                byte[] rented = new byte[inputCount + InputBlockSize];
                int written = 0;

                fixed (byte* pRented = rented)
                {
                    try
                    {
                        written = UncheckedTransformFinalBlock(inputBuffer.AsSpan(inputOffset, inputCount), rented);
                        return rented.AsSpan(0, written).ToArray();
                    }
                    finally
                    {
                        //CryptoPool.Return(rented, clearSize: written);
                    }
                }
            }
            else
            {
                byte[] buffer = GC.AllocateUninitializedArray<byte>(inputCount);
                int written = UncheckedTransformFinalBlock(inputBuffer.AsSpan(inputOffset, inputCount), buffer);
                return buffer;
            }
        }
    
    public bool Encryption { get; init; }
    public IModeTransformer ModeTransformer { get; init; }
    public IPadder Padder { get; init; }
    public bool CanReuseTransform { get; }
    public bool CanTransformMultipleBlocks => ModeTransformer.CanTransformMultipleBlocks;
    public int InputBlockSize { get; init; }
    public int OutputBlockSize { get; init; }
    private byte[]? _heldoverCipher;

}
