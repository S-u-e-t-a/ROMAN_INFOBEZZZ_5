using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace ENCODER.Ciphers;

public partial class sha256ViewModel : BaseViewModel
{
    public string text { get; set; } = "ТЕКСТ";

    public string hash { get; set; } = "Значение хэша";


    private Command _calcHash;

    public Command calcHash
    {
        get
        {
            return _calcHash ?? (_calcHash = new Command(() =>
                {
                    var crypt = new SHA256Managed();
                    string tempHash = String.Empty;
                    byte[] crypto = crypt.ComputeHash(Encoding.ASCII.GetBytes(text));
                    foreach (byte theByte in crypto)
                    {
                        tempHash += theByte.ToString("x2");
                    }

                    hash = tempHash;
                }));
        }
    }

}
