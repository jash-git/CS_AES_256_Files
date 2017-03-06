using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace CS_Console_AES
{
    class Program
    {
        //解密資料
        public static string DecryptStringAES(string cipherText)
        {
            var keybytes = Encoding.UTF8.GetBytes("8080808080808080");   //自行設定，但要與JavaScript端 一致
            var iv = Encoding.UTF8.GetBytes("8080808080808080"); // 自行設定，但要與JavaScript端 一致
            var encrypted = Convert.FromBase64String(cipherText);
            var decriptedFromJavascript = DecryptStringFromBytes(encrypted, keybytes, iv);
            return string.Format(decriptedFromJavascript);
        }
        private static string DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] iv)
        {
            if (cipherText == null || cipherText.Length <= 0)
            {
                throw new ArgumentNullException("cipherText");
            }
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }
            if (iv == null || iv.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }
            string plaintext = null;
            using (var rijAlg = new RijndaelManaged())
            {
                rijAlg.Mode = CipherMode.ECB;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.FeedbackSize = 128;
                rijAlg.Key = key;
                rijAlg.IV = iv;
                var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
                try
                {
                    using (var msDecrypt = new MemoryStream(cipherText))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
                catch
                {
                    plaintext = "keyError";
                }
            }
            return plaintext;
        }
        //加密資料
        public static string EncryptStringAES(string cipherText)
        {
            var keybytes = Encoding.UTF8.GetBytes("8080808080808080");   //自行設定
            var iv = Encoding.UTF8.GetBytes("8080808080808080");         //自行設定
            var EncryptString = EncryptStringToBytes(cipherText, keybytes, iv);

            var str = BitConverter.ToString(EncryptString).Replace("-", string.Empty).ToLower();
            Console.WriteLine("Hex=" + str+"\n");

            return Convert.ToBase64String(EncryptString);
        }
        private static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
        {
            if (plainText == null || plainText.Length <= 0)
            {
                throw new ArgumentNullException("plainText");
            }
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }
            if (iv == null || iv.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }
            byte[] encrypted;
            using (var rijAlg = new RijndaelManaged())
            {
                rijAlg.Mode = CipherMode.ECB;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.FeedbackSize = 128;
                rijAlg.Key = key;
                rijAlg.IV = iv;
                var encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }
        static void Pause()
        {
            Console.Write("Press any key to continue . . . ");
            Console.ReadKey(true);
        }
        public static String RandomString(int count)
        {
            Random R = new Random();//亂數種子
            String StrBuf = "";
            String StrArray = "QAZXSWEDCVFRTGBNHYUJMKIOLP";
            for (int i = 0; i < count; i++)
            {

                int j = R.Next(0, 25);//0~25

                StrBuf += StrArray.Substring(j, 1);

            }
            return StrBuf;
        }
        static void Main(string[] args)
        {
            String StrSource = RandomString(16);
            //String StrSource = "HELLOHELLOHELLOHELLOHELLOHELLOHELLOHELLO";
            Console.WriteLine("原始資料:"+StrSource + "\n");
            Console.WriteLine("原始資料hex:" + BitConverter.ToString(Encoding.UTF8.GetBytes(StrSource)).Replace("-", string.Empty).ToLower() + "\n");
            String Data = EncryptStringAES(StrSource);

            Console.WriteLine(Data+"\n");
            Console.WriteLine(DecryptStringAES(Data)+"\n");
            //驗證比對網頁：http://www.seacha.com/tools/aes.html
            Pause();
        }
    }
}
