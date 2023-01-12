using System.Diagnostics;
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

            if (keySize.SkipSize != 0)
            {
                for (var i = keySize.MinSize; i <= keySize.MaxSize; i += keySize.SkipSize)
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

    public List<int> blockSizes
    {
        get
        {
            var sizes = new List<int>();
            var keySize = Algorithm.LegalBlockSizes[0];

            if (keySize.SkipSize != 0)
            {
                for (var i = keySize.MinSize; i <= keySize.MaxSize; i += keySize.SkipSize)
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

    public List<CipherMode> LegalMods { get; set; }

    public override string ToString()
    {
        return Name;
    }
}


public class PaddingModeExtended : BaseViewModel
{
    public PaddingMode Mode { get; set; }
    public string Name { get; set; }

    public override string ToString()
    {
        return Name;
    }
}


public class SymmetricAlgorithmsViewModel : BaseViewModel
{
    private SymmetricAlgWithName _selectedAlg;

    public SymmetricAlgorithmsViewModel()
    {
        AlgWithNames = new List<SymmetricAlgWithName>
        {
            new()
            {
                Algorithm = new Raiden(),
                Name = "Raiden",
                LegalMods = new List<CipherMode>
                {
                    CipherMode.CBC, CipherMode.ECB, CipherMode.OFB,
                },
            },
            new()
            {
                Algorithm = new XTEA(),
                Name = "XTEA",
                LegalMods = new List<CipherMode>
                {
                    CipherMode.CBC, CipherMode.ECB, CipherMode.OFB,
                },
            },
            new()
            {
                Algorithm = new TEA(),
                Name = "TEA",
                LegalMods = new List<CipherMode>
                {
                    CipherMode.CBC, CipherMode.ECB, CipherMode.OFB,
                },
            },
            new()
            {
                Algorithm = Aes.Create(),
                Name = "AES",
                LegalMods = new List<CipherMode>
                {
                    CipherMode.CBC, CipherMode.CFB, CipherMode.ECB,
                },
            },
            new()
            {
                Algorithm = DES.Create(),
                Name = "DES",
                LegalMods = new List<CipherMode>
                {
                    CipherMode.CBC, CipherMode.CFB, CipherMode.ECB,
                },
            },
            new()
            {
                Algorithm = TripleDES.Create(),
                Name = "TripleDES",
                LegalMods = new List<CipherMode>
                {
                    CipherMode.CBC, CipherMode.CFB, CipherMode.ECB,
                },
            },
            new()
            {
                Algorithm = RC2.Create(),
                Name = "RC2",
                LegalMods = new List<CipherMode>
                {
                    CipherMode.CBC, CipherMode.CFB, CipherMode.ECB,
                },
            },
            new()
            {
                Algorithm = Rijndael.Create(),
                Name = "Rijndael",
                LegalMods = new List<CipherMode>
                {
                    CipherMode.CBC, CipherMode.CFB, CipherMode.ECB,
                },
            },
        };

        SelectedAlg = AlgWithNames[0];


        var fields = typeof(CipherMode).GetFields().Where(fi => fi.IsLiteral);

        fields = typeof(PaddingMode).GetFields().Where(fi => fi.IsLiteral);
        AllPaddingModes = new List<PaddingModeExtended>();

        foreach (var field in fields)
        {
            var mode = new PaddingModeExtended
            {
                Mode = (PaddingMode) field.GetRawConstantValue(),
                Name = field.Name,
            };

            AllPaddingModes.Add(mode);
        }

        SelectedPaddingMode = AllPaddingModes.First(x => x.Mode == PaddingMode.PKCS7);
        SelectedCipherMode = AllCipherModes[0];
        IsText = true;
        IsPassword = true;
    }

    public List<SymmetricAlgWithName> AlgWithNames { get; set; }

    public SymmetricAlgWithName SelectedAlg
    {
        get => _selectedAlg;
        set
        {
            _selectedAlg = value;

            if (value.LegalMods.Contains(SelectedCipherMode))
            {
                SelectedCipherMode = value.LegalMods.First(m => m == SelectedCipherMode);
            }
            else
            {
                SelectedCipherMode = value.LegalMods.First();
            }

            OnPropertyChanged(nameof(SelectedCipherMode));
            OnPropertyChanged(nameof(KeySize1));
            OnPropertyChanged(nameof(BlockSize1));
        }
    }

    public List<CipherMode> AllCipherModes => SelectedAlg.LegalMods;

    public List<PaddingModeExtended> AllPaddingModes { get; set; }


#region input

    public string Text { get; set; } = "ТЕКСТ";

    public string OutputPath { get; set; }

    public string InputPath { get; set; } = "";
    public string Result { get; set; }
    public string Password { get; set; } = "";
    public string Salt { get; set; } = "";
    public int Iterations { get; set; } = 50;
    private string key;
    private int _blockSize;

    public int BlockSize1 //если убрать 1 в названии то перестает работать. 
    {
        get => SelectedAlg.Algorithm.BlockSize;
        set
        {
            SelectedAlg.Algorithm.BlockSize = value;
            OnPropertyChanged(nameof(Key));
        }
    }

    private int _keySize;

    public int KeySize1 //если убрать 1 в названии то перестает работать. 
    {
        get => SelectedAlg.Algorithm.KeySize;
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

    public bool IsFile => !IsText;

    public bool IsPassword { get; set; }

    public bool IsKey => !IsPassword;

    private CipherMode _selectedCipherMode;

    public CipherMode SelectedCipherMode
    {
        get => _selectedCipherMode;
        set
        {
            if (SelectedAlg is not null)
            {
                _selectedCipherMode = SelectedAlg.LegalMods.Contains(value) ? value : AllCipherModes.First();
            }
        }
    }


    public PaddingModeExtended SelectedPaddingMode { get; set; }

#endregion


#region Commands

    private Command _encode;

    public Command Encode
    {
        get
        {
            return _encode ??= new Command(async () =>
            {
                try
                {
                    if (IsText)
                    {
                        EncryptText();
                    }
                    else
                    {
                        EncryptFile();
                    }
                }

                catch (FormatException e)
                {
                    App.AlertSvc.ShowAlert("Ошибка", "Введенное значение не яляется строкой в формате Base64");
                    Debug.WriteLine(e.Message);
                }
                catch (CryptographicException e) when (e.Message == "Specified key is not a valid size for this algorithm.")
                {
                    App.AlertSvc.ShowAlert("Ошибка", "Размер ключа не соответствует нужному");
                    Debug.WriteLine(e.Message);
                }
                catch (CryptographicException e) when (e.Message ==
                                                       "Specified initialization vector (IV) does not match the block size for this algorithm.")
                {
                    App.AlertSvc.ShowAlert("Ошибка", "Размер вектор инициализации не соответствует нужному");
                    Debug.WriteLine(e.Message);
                }
                catch (Exception e)
                {
                    App.AlertSvc.ShowAlert("Ошибка", e.Message);
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
                    if (IsText)
                    {
                        DecryptText();
                    }
                    else
                    {
                        DecryptFile();
                    }
                }
                catch (FormatException e)
                {
                    App.AlertSvc.ShowAlert("Ошибка", "Введенное значение не яляется строкой в формате Base64");
                    Debug.WriteLine(e.Message);
                }
                catch (CryptographicException e)
                    when (e.Message == "Specified key is not a valid size for this algorithm.")
                {
                    App.AlertSvc.ShowAlert("Ошибка", "Размер ключа не соответствует нужному");
                    Debug.WriteLine(e.Message);
                }
                catch (CryptographicException e)
                    when (e.Message == "Specified initialization vector (IV) does not match the block size for this algorithm.")
                {
                    App.AlertSvc.ShowAlert("Ошибка", "Размер вектор инициализации не соответствует нужному");
                    Debug.WriteLine(e.Message);
                }
                catch (Exception e)
                {
                    App.AlertSvc.ShowAlert("Ошибка", e.Message);
                    Debug.WriteLine(e.Message);
                }
            });
        }
    }

    private Command _openInputFile;

    public Command OpenInputFile
    {
        get
        {
            return _openInputFile ??= new Command(async o =>
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
            return _openOutputPath ??= new Command(async o =>
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
        var alg = SelectedAlg.Algorithm;
        var key = Convert.FromBase64String(Key);
        var iv = Convert.FromBase64String(IV);
        alg.Mode = SelectedCipherMode;
        alg.Padding = SelectedPaddingMode.Mode;
        Debug.WriteLine(key.Length);
        Debug.WriteLine($"Text size - {Encoding.UTF8.GetBytes(Text).Length}");
        alg.Key = key;
        alg.IV = iv;
        var t = EncDec.EncryptText(alg, Text);
        Result = Convert.ToBase64String(t);
    }

    private void DecryptText()
    {
        var alg = SelectedAlg.Algorithm;
        alg.Mode = SelectedCipherMode;
        alg.Padding = SelectedPaddingMode.Mode;
        var key = Convert.FromBase64String(Key);
        var iv = Convert.FromBase64String(IV);
        Debug.WriteLine(key.Length);
        alg.Key = key;
        alg.IV = iv;
        var t = EncDec.DecryptText(alg, Convert.FromBase64String(Text));
        Result = t;
    }


    private void EncryptFile()
    {
        var alg = SelectedAlg.Algorithm;
        var key = Convert.FromBase64String(Key);
        var iv = Convert.FromBase64String(IV);
        alg.Mode = SelectedCipherMode;
        alg.Padding = SelectedPaddingMode.Mode;
        Debug.WriteLine(key.Length);
        Debug.WriteLine($"Text size - {Encoding.UTF8.GetBytes(Text).Length}");
        alg.Key = key;
        alg.IV = iv;
        EncDec.EncryptFile(alg, InputPath, OutputPath);
    }

    private void DecryptFile()
    {
        var alg = SelectedAlg.Algorithm;
        var key = Convert.FromBase64String(Key);
        var iv = Convert.FromBase64String(IV);
        alg.Mode = SelectedCipherMode;
        alg.Padding = SelectedPaddingMode.Mode;
        Debug.WriteLine(key.Length);
        Debug.WriteLine($"Text size - {Encoding.UTF8.GetBytes(Text).Length}");
        alg.Key = key;
        alg.IV = iv;
        EncDec.DecryptFile(alg, InputPath, OutputPath);
    }

#endregion
}

