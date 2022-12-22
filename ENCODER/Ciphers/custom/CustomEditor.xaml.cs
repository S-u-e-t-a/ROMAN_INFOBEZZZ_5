using System.Diagnostics;

using UraniumUI.Material.Controls;


namespace ENCODER.Ciphers.custom;

public partial class CustomEditor : InputField
{
  public static readonly BindableProperty TextProperty =
        BindableProperty.Create(
                       nameof(Text),
                       typeof(string),
                       typeof(TextField),
                       string.Empty,
                       BindingMode.TwoWay,
                       // propertyChanging: (bindable, oldValue, newValue) =>
                       // {
                       //     var textField = (TextField)bindable;
                       //     textField.UpdateClearIconState();
                       // },
                       propertyChanged: (bindable, oldValue, newValue) =>
                       {
                           (bindable as CustomEditor).InternalEditor.Text = (string)newValue;
                           (bindable as CustomEditor).OnPropertyChanged(nameof(Text));
                       }
                           );

    public CustomEditor()
    {
        InitializeComponent();
        InternalEditor = (Editor) Content;
        InternalEditor.TextChanged += (sender, args) =>
        {
            Text = args.NewTextValue;
            InvalidateMeasure();
        };
    }

    
    
    public string Text
    {
        get => (string)GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }
    public Editor InternalEditor
    {
        get;
        set;
    }

    public override View Content { get; set; } = new Editor(){AutoSize = EditorAutoSizeOption.TextChanges};

    public override bool HasValue => !string.IsNullOrEmpty(InternalEditor.Text);
}


