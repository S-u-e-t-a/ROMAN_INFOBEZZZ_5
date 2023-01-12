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

    public static void EncryptFile(SymmetricAlgorithm alg, string inputFile, string outputFile)
    {
        using (FileStream fsCrypt = new FileStream(outputFile, FileMode.Create))
        {
            using (CryptoStream cs = new CryptoStream(fsCrypt, alg.CreateEncryptor(), CryptoStreamMode.Write))
            {
                using (FileStream fsIn = new FileStream(inputFile, FileMode.Open))
                {
                    byte[] buffer = new byte[1048576];
                    int read;
                    while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cs.Write(buffer, 0, read);
                    }
                }
            }
        }
    }
    public static void DecryptFile(SymmetricAlgorithm alg, string inputFile, string outputFile)
    {
        using (FileStream fsCrypt = new FileStream(inputFile, FileMode.Open))
        {
            using (CryptoStream cryptoStream = new CryptoStream(fsCrypt, alg.CreateDecryptor(), CryptoStreamMode.Read))
            {
                using (FileStream fsOut = new FileStream(outputFile, FileMode.Create))
                {
                    int read;
                    byte[] buffer = new byte[1048576];
                    while ((read = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        fsOut.Write(buffer, 0, read);
                    }
                }
            }
        }
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
