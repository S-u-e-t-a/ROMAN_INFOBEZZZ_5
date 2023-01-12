using System.Diagnostics;
using System.Net.Mime;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

using PropertyChanged;

using TeaCiphers;


namespace ENCODER.Ciphers;

public class SymmetricAlgWithName : BaseViewModel
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

    public override string ToString()
    {
        return Name;
    }
}


public class CipherModeExtended: BaseViewModel
{
    public CipherMode Mode { get; set; }
    public string Name { get; set; }
    public override string ToString()
    {
        return Name;
    }
}

public class PaddingModeExtended: BaseViewModel
{
    public PaddingMode Mode { get; set; }
    public string Name { get; set; }
    public override string ToString()
    {
        return Name;
    }
}
public class SymmetricAlgorithmsViewModel: BaseViewModel
{
    public SymmetricAlgorithmsViewModel()
    {
        AlgWithNames = new List<SymmetricAlgWithName>()
        {
            new ()
            {
                Algorithm = new TEA(),
               Name  = "TEa",
            },
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
        IsText = true;
        IsPassword = true;
    }
    public List<SymmetricAlgWithName> AlgWithNames { get; set; }

    private SymmetricAlgWithName _selectedAlg;

    public SymmetricAlgWithName SelectedAlg
    {
        get
        {
            return _selectedAlg;
        }
        set
        {
            _selectedAlg = value;
            OnPropertyChanged(nameof(KeySize1));
            OnPropertyChanged(nameof(BlockSize1));
            
        }
    }

    public List<CipherModeExtended> AllCipherModes { get; set; }
    public List<PaddingModeExtended> AllPaddingModes { get; set; }


#region input

    public string Text { get; set; }= "ТЕКСТ";
    
    public string OutputPath { get; set; }

    public string InputPath { get; set; }= "";
    public string Result { get; set; }
    public string Password { get; set; } = "";
    public string Salt { get; set; }= "";
    public int Iterations { get; set; } = 50;
    private string key;
    private int _blockSize;

    public int BlockSize1 //если убрать 1 в названии то перестает работать. 
    {
        get
        {
            return SelectedAlg.Algorithm.BlockSize;
        }
        set
        {
            SelectedAlg.Algorithm.BlockSize = value;
            OnPropertyChanged(nameof(Key));
        }
    }

    private int _keySize;

    public int KeySize1 //если убрать 1 в названии то перестает работать. 
    {
        get
        {
            return SelectedAlg.Algorithm.KeySize;
        }
        set
        {
            SelectedAlg.Algorithm.KeySize = value;
            OnPropertyChanged(nameof(Key));

        }
    }
    
[DependsOn("KeySize", "BlockSize")]
    public string Key
    {
        get
        {
            if (IsPassword)
            {
                var bytes = Encoding.Unicode.GetBytes(Password);
                var keyIV = EncDec.GenerateKeyAndIVByPassword(Password, 
                                                              Encoding.Unicode.GetBytes(Salt), 
                                                              SelectedAlg.Algorithm.KeySize, 
                                                              SelectedAlg.Algorithm.BlockSize,
                                                              Iterations);

                key = Convert.ToBase64String(keyIV.Key);
                IV = Convert.ToBase64String(keyIV.IV);
            }

            return key;
        }
        set => key = value;
    }

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
            return _encode ??= new Command(async () =>
            {
                if (IsText)
                {
                    EncryptText();
                }
                else
                {
                    EncryptFile();
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

                if (IsText)
                {
                    DecryptText();
                }
                else
                {
                    DecryptFile();
                }
                
            });
        }
    }

    private Command _openInputFile;

    public Command OpenInputFile
    {
        get
        {
            return _openInputFile ??= new Command( async o =>
            {
                var result = await FilePicker.Default.PickAsync();
                if (result != null)
                {
                    InputPath = result.FullPath;
                }
            });
        }
    }

    private Command _openOutputPath;

    public Command OpenOutputPath
    {
        get
        {
            return _openOutputPath ??= new Command( async o =>
            {
                var result = await FilePicker.Default.PickAsync();
                if (result != null)
                {
                    OutputPath = result.FullPath;
                }
            });
        }
    }


    
    
    private void EncryptText()
    {
        try
        {
            var alg = SelectedAlg.Algorithm;
            var key = Convert.FromBase64String(Key);
            var iv = Convert.FromBase64String(IV);
            alg.Mode = SelectedCipherMode.Mode;
            alg.Padding = SelectedPaddingMode.Mode;
            Debug.WriteLine(key.Length);
            Debug.WriteLine($"Text size - {Encoding.UTF8.GetBytes(Text).Length}");
            alg.Key = key;
            alg.IV = iv;
            var t = EncDec.EncryptText(alg, Text);
            Result =Convert.ToBase64String(t);
        }
        catch (Exception e)
        {
            App.AlertSvc.ShowAlert("Ошибка",e.Message);
            Debug.WriteLine(e.Message);
        }
    }

    private void DecryptText()
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
            App.AlertSvc.ShowAlert("Ошибка",e.Message);
            Debug.WriteLine(e.Message);
        }
    }


    private void EncryptFile()
    {
        try
        {
            var alg = SelectedAlg.Algorithm;
            var key = Convert.FromBase64String(Key);
            var iv = Convert.FromBase64String(IV);
            alg.Mode = SelectedCipherMode.Mode;
            alg.Padding = SelectedPaddingMode.Mode;
            Debug.WriteLine(key.Length);
            Debug.WriteLine($"Text size - {Encoding.UTF8.GetBytes(Text).Length}");
            alg.Key = key;
            alg.IV = iv;
            EncDec.EncryptFile(alg, InputPath, OutputPath);
        }
        catch (Exception e)
        {
            App.AlertSvc.ShowAlert("Ошибка",e.Message);
            Debug.WriteLine(e.Message);
        }
    }

    private void DecryptFile()
    {
        try
        {
            var alg = SelectedAlg.Algorithm;
            var key = Convert.FromBase64String(Key);
            var iv = Convert.FromBase64String(IV);
            alg.Mode = SelectedCipherMode.Mode;
            alg.Padding = SelectedPaddingMode.Mode;
            Debug.WriteLine(key.Length);
            Debug.WriteLine($"Text size - {Encoding.UTF8.GetBytes(Text).Length}");
            alg.Key = key;
            alg.IV = iv;
            EncDec.DecryptFile(alg, InputPath, OutputPath);
        }
        catch (Exception e)
        {
            App.AlertSvc.ShowAlert("Ошибка",e.Message);
            Debug.WriteLine(e.Message);
        }
    }
    
}
