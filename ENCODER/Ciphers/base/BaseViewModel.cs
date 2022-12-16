using System.ComponentModel;
using System.Runtime.CompilerServices;

using PropertyChanged;


namespace ENCODER.Ciphers;

[AddINotifyPropertyChangedInterface]
public abstract class BaseViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler PropertyChanged;
    
    public virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
