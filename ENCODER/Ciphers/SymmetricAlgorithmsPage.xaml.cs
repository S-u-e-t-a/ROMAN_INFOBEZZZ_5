using System.Diagnostics;

using UraniumUI.Material.Controls;


namespace ENCODER.Ciphers;

public partial class SymmetricAlgorithmsPage : ContentPage
{
    public SymmetricAlgorithmsPage()
    {
        InitializeComponent();
        BindingContext = new SymmetricAlgorithmsViewModel();
    }
    

    private async void Button_OnClicked(object sender, EventArgs e)
    {
        Debug.WriteLine("tapped");
        await Clipboard.Default.SetTextAsync(ResultField.Text);
        // Frame frame = new Frame
        // {
        //     BorderColor = Colors.Gray,
        //     CornerRadius = 10,
        //     Content = new Label { Text = "Frame wrapped around a Label" },
        //     ZIndex = 5,
        //     Opacity = 0,
        //     Padding = 15,
        // };
        //
        // MainLayout.Add(frame);
        //
        // var turnOn = new Animation((value) =>
        // {
        //     frame.Opacity = value;
        // },0,1);
        // var turnOff= new Animation((value) =>
        // {
        //     frame.Opacity = value;
        // },1,0);
        // frame.Animate("Opacity",turnOn, length:300);
        // await Task.Delay(1200);
        // frame.Animate("Opacity",turnOff, length:300);
        // await Task.Delay(300);
        // MainLayout.Remove(frame);
    }
}


