using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;


namespace ENCODER.Ciphers;

public class SymmetricAlgWithName
{
    public string Name { get; set; }
    public SymmetricAlgorithm Algorithm { get; set; }

    public List<int> keySizes
    {
        get
        {
            var sizes = new List<int>();
            var keySize = Algorithm.LegalKeySizes[0];
            if (keySize.SkipSize!=0)
            {
                for (int i = keySize.MinSize; i <= keySize.MaxSize; i+=keySize.SkipSize)
                {
                    sizes.Add(i);
                }
            }
            else
            {
                sizes.Add(keySize.MinSize);
            }

            return sizes;
        }
    }

    public List<int> blockSizes {
        get
    {
        var sizes = new List<int>();
        var keySize = Algorithm.LegalBlockSizes[0];

        if (keySize.SkipSize!=0)
        {
            for (int i = keySize.MinSize; i <= keySize.MaxSize; i+=keySize.SkipSize)
            {
                sizes.Add(i);
            }
        }
        else
        {
            sizes.Add(keySize.MinSize);
        }
        

        return sizes;
    } }
    
}


public class CipherModeExtended
{
    public CipherMode Mode { get; set; }
    public string Name { get; set; }
}
public class PaddingModeExtended
{
    public PaddingMode Mode { get; set; }
    public string Name { get; set; }
}
public class SymmetricAlgorithmsViewModel: BaseViewModel
{
    public SymmetricAlgorithmsViewModel()
    {
        AlgWithNames = new List<SymmetricAlgWithName>()
        {
            new()
            {
                Algorithm = Aes.Create(),
                Name = "AES",
                
            },
            new ()
            {
                Algorithm = DES.Create(),
                Name = "DES",
            },
            new()
            {
              Algorithm  = TripleDES.Create(),
              Name = "TripleDES",
            },
            new()
            {
             Algorithm = RC2.Create(),
             Name = "RC2",
            },
            new()
            {
                Algorithm = Rijndael.Create(),
                Name = "Rijndael",
            }
        };
        
        SelectedAlg = AlgWithNames[0];
        
        
        var fields = typeof(CipherMode).GetFields().Where(fi => fi.IsLiteral);
        AllCipherModes = new List<CipherModeExtended>();
        foreach (var field in fields)
        {
            var mode = new CipherModeExtended()
            {
                Mode = (CipherMode) field.GetRawConstantValue(),
                Name = field.Name
            };
            
            AllCipherModes.Add(mode);
        }
        fields = typeof(PaddingMode).GetFields().Where(fi => fi.IsLiteral);
        AllPaddingModes = new List<PaddingModeExtended>();
        foreach (var field in fields)
        {
            var mode = new PaddingModeExtended()
            {
                Mode = (PaddingMode) field.GetRawConstantValue(),
                Name = field.Name
            };
            
            AllPaddingModes.Add(mode);
        }

        SelectedPaddingMode = AllPaddingModes[0];
        SelectedCipherMode = AllCipherModes[0];
    }
    public List<SymmetricAlgWithName> AlgWithNames { get; set; }
    public SymmetricAlgWithName SelectedAlg { get; set; }
    public List<CipherModeExtended> AllCipherModes { get; set; }
    public List<PaddingModeExtended> AllPaddingModes { get; set; }


#region input

    public string Text { get; set; }
    public string Path { get; set; }
    public string Result { get; set; }
    public string Password { get; set; }
    public string Salt { get; set; }
    public int Iterations { get; set; }
    public string Key { get; set; }
    public string IV { get; set; }

    public bool IsText { get; set; }
    public bool IsFile
    {
        get => !IsText;
    }

    public bool IsPassword { get; set; }
    public bool IsKey
    {
        get => !IsPassword;
    }
    
    
    public CipherModeExtended SelectedCipherMode { get; set; } 
    public PaddingModeExtended SelectedPaddingMode { get; set; } 
    

#endregion
    
    
    
    private Command _encode;

    public Command Encode
    {
        get
        {
            return _encode ??= new Command(() =>
            {
                try
                {
                    var alg = SelectedAlg.Algorithm;
                    alg.Mode = SelectedCipherMode.Mode;
                    alg.Padding = SelectedPaddingMode.Mode;
                    var key = Convert.FromBase64String(Key);
                    var iv = Convert.FromBase64String(IV);
                    Debug.WriteLine(key.Length);
                    alg.Key = key;
                    alg.IV = iv;
                    var t = EncDec.EncryptText(alg, Text);
                    Result =Convert.ToBase64String(t);
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
            });
        }
    }

    private Command _decode;

    public Command Decode
    {
        get
        {
            return _decode ??= new Command(() =>
            {
                try
                {
                    var alg = SelectedAlg.Algorithm;
                    alg.Mode = SelectedCipherMode.Mode;
                    alg.Padding = SelectedPaddingMode.Mode;
                    var key = Convert.FromBase64String(Key);
                    var iv = Convert.FromBase64String(IV);
                    Debug.WriteLine(key.Length);
                    alg.Key = key;
                    alg.IV = iv;
                    var t = EncDec.DecryptText(alg, Convert.FromBase64String(Text));
                    Result = t;
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
                
                
            });
        }
    }
    
    
    
}
