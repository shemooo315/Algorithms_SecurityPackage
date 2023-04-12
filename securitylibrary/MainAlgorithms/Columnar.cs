using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            //to remove repeat and calculate lenght of key
            var unique1 = new HashSet<char>(plainText);
            var unique2 = new HashSet<char>(cipherText);
            string pt_removeRepeat = plainText, cp_removeRepeat = cipherText;
            int index1, index2 = 0;
            int lenghtOfKey;

            if (cipherText[0] == cipherText[1])
            {
                pt_removeRepeat = "";
                cp_removeRepeat = "";
                foreach (char c in unique1)
                    pt_removeRepeat += c;
                foreach (char c in unique2)
                    cp_removeRepeat += c;
                index1 = pt_removeRepeat.IndexOf(cp_removeRepeat[0]);
                index2 = pt_removeRepeat.IndexOf(cp_removeRepeat[1]);
                lenghtOfKey = Math.Abs(index2 - index1) + 1;
                Console.WriteLine(lenghtOfKey);
            }
            else
            {
                index1 = pt_removeRepeat.IndexOf(cp_removeRepeat[0]);
                index2 = pt_removeRepeat.IndexOf(cp_removeRepeat[1]);
                lenghtOfKey = Math.Abs(index2 - index1);
                Console.WriteLine(lenghtOfKey);
            }



            float num = (float)plainText.Length / lenghtOfKey;
            int rowCount = (int)Math.Ceiling(num);
            int counttt = plainText.Length;
            if ((plainText.Length % lenghtOfKey) != 0)
            {

                while (counttt % lenghtOfKey != 0)
                {
                    counttt++;
                }
                counttt = counttt - plainText.Length;
                for (int i = 0; i < counttt; i++)
                    plainText += "x";


            }
            char[,] arr = new char[rowCount, lenghtOfKey];
            int index = 0;

            for (int i = 0; i < rowCount; i++)
            {
                for (int j = 0; j < lenghtOfKey; j++)
                {
                    arr[i, j] = plainText[index];
                    index++;
                }
            }
            string word = "";
            if (!cipherText.Contains("x"))
            {
                for (int i = 0; i < lenghtOfKey; i++)
                {
                    for (int j = 0; j < rowCount; j++)
                    {
                        word += arr[j, i];
                    }

                    if (word.Contains("x"))
                    {
                        word = word.Substring(0, rowCount - 1);
                        int c = cipherText.IndexOf(word);
                        cipherText = cipherText.Insert(c + (int)num, "x");

                    }
                    word = "";
                }
            }
            string wordOfcipher = "";
            string wordOfarr = "";
            List<int> key = new List<int>();
            int count = 0;
            for (int j = 0; j < lenghtOfKey; j++)
            {
                for (int n = 0; n < rowCount; n++)
                {
                    wordOfarr += arr[n, j];
                }

                for (int i = 0; i < lenghtOfKey; i++)
                {
                    wordOfcipher += cipherText.Substring(count, rowCount);
                    count += rowCount;
                    if (wordOfcipher == wordOfarr)
                    {
                        key.Add(i + 1);
                        wordOfcipher = "";

                    }
                    else
                        wordOfcipher = "";
                }
                count = 0;
                wordOfarr = "";

            }

            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int rowCount = cipherText.Length / key.Count;
            string PT = "";
            char[,] arr = new char[rowCount, key.Count];
            int indexcipher = 0;
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if (i + 1 == key[j])
                    {
                        for (int row = 0; row < rowCount; row++)
                        {
                            arr[row, j] = cipherText[indexcipher];
                            indexcipher++;
                        }
                        break;
                    }
                }


            }
            for (int i = 0; i < rowCount; i++)
            {
                for (int j = 0; j < key.Count; j++)
                    PT += arr[i, j];
            }
            return PT;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int cols = key.Count;
            string CT = "";
            int rows = (int)Math.Ceiling((double)plainText.Length / cols);
            char[,] arr = new char[rows, cols];
            int counter = 0;
            if (plainText.Length != rows * cols)
            {
                int x = plainText.Length % cols;
                string dontcare = new string('x', x);
                plainText += dontcare;
            }
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    arr[i, j] = plainText[counter];
                    counter++;
                }
            }
            for (int i = 1; i <= cols; i++)
            {
                int index = key.IndexOf(i);
                for (int j = 0; j < rows; j++)
                {
                    CT += arr[j, index];
                }
            }
            return CT.ToUpper();
        }

    }
}