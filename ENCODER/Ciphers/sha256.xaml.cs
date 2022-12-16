using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace ENCODER.Ciphers;

public partial class sha256 
{
 public sha256()
 {
  InitializeComponent();
  BindingContext = new sha256ViewModel();
 }
}

