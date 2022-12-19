using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace ENCODER.Ciphers;

public partial class CalcHashPage 
{
 public CalcHashPage()
 {
  InitializeComponent();
  BindingContext = new CalcHashViewModel();
 }
}

