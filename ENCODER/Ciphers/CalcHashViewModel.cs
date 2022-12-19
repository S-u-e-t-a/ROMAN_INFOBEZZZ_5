using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace ENCODER.Ciphers;

public class AlgWithName
{
    public string Name { get; set; }
    public HashAlgorithm Algorithm { get; set; }
}

public class CalcHashViewModel : BaseViewModel
{
    public CalcHashViewModel()
    {
        AlgWithNames = new List<AlgWithName>()
        {
            new ()
            {
                Name = "SHA1",
                Algorithm = SHA1.Create()
            },
            new ()
            {
                Name = "SHA256",
                Algorithm = SHA256.Create()
            },
            new ()
            {
                Name = "SHA384",
                Algorithm = SHA384.Create()
            },
            new ()
            {
                Name = "SHA512",
                Algorithm = SHA512.Create()
            },
            new ()
            {
                Name = "MD5",
                Algorithm = MD5.Create()
            },
        };

        SelectedAlg = AlgWithNames[0];
    }
    public string text { get; set; } = "ТЕКСТ";
    public FileResult file { get; set; }
    public string hash { get; set; } = "Значение хэша";
    public List<AlgWithName> AlgWithNames { get; set; }
    public AlgWithName SelectedAlg { get; set; }

    private Command _calcHash;

    public Command calcHash
    {
        get
        {
            return _calcHash ??= new Command( async () =>
            {
                //var file = await FilePicker.PickAsync();
                string tempHash = String.Empty;
                byte[] crypto = SelectedAlg.Algorithm.ComputeHash(Encoding.UTF8.GetBytes(text));
                foreach (byte theByte in crypto)
                {
                    tempHash += theByte.ToString("x2");
                }

                hash = tempHash;
            });
        }
    }

}
