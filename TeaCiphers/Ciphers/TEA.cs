using System.Security.Cryptography;


namespace TeaCiphers;

public sealed class TEA: SymmetricAlgorithm
{
    public TEA()
    {
        BlockSize = 64;
        KeySize = 128;
        FeedbackSize = 64;
    }
    public override KeySizes[] LegalBlockSizes => new KeySizes[] {new KeySizes(64, 64, 0)};

    public override KeySizes[] LegalKeySizes => new KeySizes[] {new KeySizes(128, 128, 0)};
    
    public override CipherMode Mode { get; set; } = CipherMode.CBC;


    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        return new TeaCryptoTransform(rgbKey, rgbIV,false);
    }

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        return new TeaCryptoTransform(rgbKey, rgbIV,true);
    }

    public override void GenerateIV()
    {
        throw new NotImplementedException();
    }

    public override void GenerateKey()
    {
        throw new NotImplementedException();
    }
}
