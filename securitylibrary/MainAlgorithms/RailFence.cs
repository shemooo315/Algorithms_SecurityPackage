using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;
            for (int i = 1; i < 4; i++)
            {
                string text = Encrypt(plainText, i);
                string res = "";
                for (int j = 0; j < text.Length - 1; j++)
                {
                    if (text[j] != '\0')
                    {
                        res = res + text[j];
                    }
                }
                text = res;
                if (text.Trim().ToLower() == cipherText.ToLower())
                {
                    key = i;
                    break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            string PT = "";
            int count = 0;
            int row = 0;
            int column = 0;
            int width = (int)Math.Ceiling((double)(cipherText.Length) / key);
            int height = key;
            char[,] railFence_matrix = new char[height, width];

            while (row < key)
            {
                for (int j = 0; j < width; j++)
                {
                    railFence_matrix[row, j] = cipherText[count];
                    count++;
                    if (count == cipherText.Length)
                    {
                        break;
                    }
                }
                row++;
            }

            while (column < (width))
            {
                for (int i = 0; i < height; i++)
                {
                    PT += railFence_matrix[i, column];
                }
                column++;
            }
            return PT.ToUpper();
        }

        public string Encrypt(string plainText, int key)
        {

            string CT = "";
            int row = 0;
            int count = 0;
            //getting rid of spaces
            int num = plainText.Length;
            //width and height of the matrix
            int width = (int)Math.Ceiling((double)(plainText.Length) / key) + 1;
            int height = key;
            char[,] railFence_matrix = new char[height, width];

            while (row < height)
            {

                for (int i = 0; i < width; i++)
                {
                    railFence_matrix[row, i] = plainText[count];
                    count += key;
                    if (count >= plainText.Length)
                    {
                        row++;
                        count = row;
                        break;
                    }
                    num--;
                    if (num == 0)
                    {
                        break;
                    }
                }
            }

            for (int i = 0; i < height; i++)
            {
                for (int j = 0; j < width; j++)
                {
                    CT += railFence_matrix[i, j];
                }
            }

            return CT.ToUpper();

        }
    }
}
