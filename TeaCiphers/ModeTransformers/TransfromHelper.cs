using System.Security.Cryptography;

using TeaCiphers.Encoders;
using TeaCiphers.Padders;


namespace TeaCiphers.ModeTransformers;

public static class TransfromHelper
{
    
    public static byte[] XOR(byte[] arr1, byte[] arr2)
    {
        if (arr1.Length != arr2.Length)
            throw new ArgumentException("arr1 and arr2 are not the same length");

        byte[] result = new byte[arr1.Length];

        for (int i = 0; i < arr1.Length; ++i)
            result[i] = (byte) (arr1[i] ^ arr2[i]);

        return result;
    }

    public static Span<byte> XOR(ReadOnlySpan<byte> arr1, ReadOnlySpan<byte> arr2)
    {
        if (arr1.Length != arr2.Length)
            throw new ArgumentException("arr1 and arr2 are not the same length");
        Span<byte> result = new byte[arr1.Length];
        for (int i = 0; i < arr1.Length; ++i)
            result[i] = (byte) (arr1[i] ^ arr2[i]);

        return result;
    }

    public static IModeTransformer CreateModeTransformer(CipherMode mode, ICipher cipher, byte[] key, byte[] iv, int inputBlockSize,
                                                         int outputBlockSize)
    {
        IModeTransformer transformer;
        switch (mode)
        {
            case CipherMode.CBC:
                transformer = new CBCTransformer(cipher, key,iv,inputBlockSize, outputBlockSize);
                break;
            case CipherMode.ECB:
                transformer = new ECBTransformer(cipher, key,iv,inputBlockSize, outputBlockSize);
                break;
            case CipherMode.OFB:
                transformer = new OFBTransformer(cipher, key,iv,inputBlockSize, outputBlockSize);
                break;
            case CipherMode.CFB:
                transformer = new CFBTransformer(cipher, key,iv,inputBlockSize, outputBlockSize);
                break;
            case CipherMode.CTS:
                throw new NotImplementedException();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
        }
        
        return transformer;
    }

    public static IPadder CreatePadder(PaddingMode mode)
    {
        switch (mode)
        {
            case PaddingMode.None:
                return new NonePadder();
                break;
            case PaddingMode.PKCS7:
                return new PKCS7Padder();
                break;
            case PaddingMode.Zeros:
                return new ZeroPadder();
                break;
            case PaddingMode.ANSIX923:
                return new ANSIX923Padder();
                break;
            case PaddingMode.ISO10126:
                return new ISO10126Padder();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
        }
    }

    public static Transformer CreateTransformer(CipherMode cipherMode, PaddingMode paddingMode, ICipher cipher,
                                                byte[] key, byte[] iv, bool encryption,
                                                int inputBlockSize, int outputBlockSize)
    {
        var modeTransformer = CreateModeTransformer(cipherMode, cipher, key, iv, inputBlockSize, outputBlockSize);
        var padder = CreatePadder(paddingMode);
        var transformer = new Transformer(modeTransformer, padder, encryption, inputBlockSize, outputBlockSize);
        
        return transformer;
    }
}
