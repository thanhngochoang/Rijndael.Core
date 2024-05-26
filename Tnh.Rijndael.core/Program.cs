using System.Text;
using Tnh.Rijndael.core;

var rijndael = new Rijndael();
const string test = "Hello World!";

var encrypted = rijndael.Encrypt(new MemoryStream(Encoding.UTF8.GetBytes(test)));
Console.WriteLine(Encoding.UTF8.GetString(encrypted));

var decrypted = rijndael.Decrypt(new MemoryStream(encrypted),0);


Console.WriteLine(Encoding.UTF8.GetString(decrypted.ToArray()));