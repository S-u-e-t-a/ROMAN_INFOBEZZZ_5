using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace ENCODER.Ciphers;

public partial class AsymmetricAlgorithmsPage : ContentPage
{
    public AsymmetricAlgorithmsPage()
    {
        InitializeComponent();
        BindingContext = new AsymmetricAlgorithmsPageViewModel();
    }
}

