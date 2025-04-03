// See https://aka.ms/new-console-template for more information
using EncryptionLibrary;

EncryptionLibrary.RSA rsa = new EncryptionLibrary.RSA();
rsa.GenerateKeys();

Console.Write("Введите строку для шифрования: ");
string input = Console.ReadLine();

var encrypted = rsa.EncryptString(input);
Console.WriteLine("\nЗашифрованная строка (в виде чисел):");
Console.WriteLine(string.Join(" ", encrypted));

string decrypted = rsa.DecryptString(encrypted);
Console.WriteLine("\nРасшифрованная строка:");
Console.WriteLine(decrypted);