using System.Security.Cryptography;

using TeaCiphers.Encoders;
using TeaCiphers.ModeTransformers;


namespace TeaCiphers;

public class Raiden:SymmetricAlgorithm
{
    public Raiden()
    {
        BlockSize = 64;
        KeySize = 128;
        FeedbackSize = 64;
    }
    public override CipherMode Mode { get; set; } = CipherMode.CBC;

    public override KeySizes[] LegalBlockSizes => new KeySizes[] {new KeySizes(64, 64, 0)};

    public override KeySizes[] LegalKeySizes => new KeySizes[] {new KeySizes(128, 128, 0)};

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        var cipher = new RaidenCipher();
        var transformer = TransfromHelper.CreateTransformer(Mode, Padding, cipher, rgbKey, rgbIV, false, 8,8);
        
        return transformer;
    }

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        var cipher = new RaidenCipher();
        var transformer = TransfromHelper.CreateTransformer(Mode, Padding, cipher, rgbKey, rgbIV, true, 8,8);
        return transformer;
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
