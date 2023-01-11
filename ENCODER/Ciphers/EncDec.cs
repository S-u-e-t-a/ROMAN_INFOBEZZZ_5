using System.Security.Cryptography;

namespace ENCODER.Ciphers;

public struct KeyAndIV
{
    public byte[] Key;
    public byte[] IV;
}
public static class EncDec
{
#region text

    public static byte[] EncryptText(SymmetricAlgorithm alg, string Text)
    {
        var encryptor = alg.CreateEncryptor();
        byte[] encrypted;
        using (MemoryStream ms = new MemoryStream())
        {
            using (CryptoStream cs = new CryptoStream(ms,encryptor, CryptoStreamMode.Write))
            {
                using (StreamWriter sw = new StreamWriter(cs))
                {
                    //todo возможная проблема
                    sw.Write(Text);
                    
                }
                encrypted = ms.ToArray();
            }
        }

        return encrypted;
    }

    public static string DecryptText(SymmetricAlgorithm alg, byte[] Text)
    {

        var decryptor = alg.CreateDecryptor();
        string result;
        using (MemoryStream ms = new MemoryStream(Text))
        {
            using (CryptoStream cs = new CryptoStream(ms,decryptor, CryptoStreamMode.Read))
            {
                using (StreamReader sw = new StreamReader(cs))
                {
                    result = sw.ReadToEnd();
                }
            }
        }
        return result;
    }

#endregion
    
#region file

    public static void EncryptFile(SymmetricAlgorithm alg, string inputFile)
    {
        var fsCrypt = new FileStream(inputFile + ".crypt", FileMode.Create);
        
    }

    public static void DecryptFile()
    {
        
    }

#endregion


    public static KeyAndIV GenerateKeyAndIVByPassword(string password, byte[] salt,int keyLen,int IVlen, int iterations = 50000)
    {
        var prf = new Rfc2898DeriveBytes(password, salt, iterations);
        var key = prf.GetBytes(keyLen / 8);
        var iv = prf.GetBytes(IVlen/8);

        return new KeyAndIV
        {
            Key = key,
            IV = iv
        };
    }
}
