using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        string alphabets= "abcdefghiklmnopqrstuvwxyz";

      

        char[,] cipher_matrix=new char[5,5];

        public char[,] GenereatedKey(string key)
        {
            HashSet<char> Gkey = new HashSet<char>();
            int keyLength = key.Length;
            HashSet<char>.Enumerator em = Gkey.GetEnumerator();
            for (int i = 0; i < keyLength; i++)
            {
                if (key[i] == 'j')
                {
                    Gkey.Add('i');
                }
                else
                {
                    Gkey.Add(key[i]);
                }
            }

            for (int i = 0; i < 25; i++)
            {
                //without j
                Gkey.Add(alphabets[i]);
            }
            for (int i = 0; i < 25; i++)
            {
                Gkey.Add(alphabets[i]);
            }
            int row = 0, col = 0;
            foreach (var v in Gkey)
            {

                cipher_matrix[col, row] = v;
                //Console.WriteLine(cipher_matrix[row, col]);
                row = (row + 1) % 5;
                if (row == 0)
                {
                    col++;
                }

            }
            return cipher_matrix;
        }


        public string  Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string plain_text = "";
            char[,] cipher_matrix = GenereatedKey(key.ToLower());
            List<string> blocks = new List<string>();
            for (int i = 0; i < cipherText.Length - 1; i += 2)
            {
                blocks.Add(cipherText.Substring(i, 2));
            }

            Console.WriteLine(blocks.Count);

            for (int b = 0; b < blocks.Count; b++)
            {
                bool found1 = false, found2 = false;
                int row1 = 0, row2 = 0, col1 = 0, col2 = 0;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (blocks[b][0] == cipher_matrix[i, j])
                        {
                            col1 = i;
                            row1 = j;

                            found1 = true;
                        }
                        if (blocks[b][1] == cipher_matrix[i, j])
                        {
                            col2 = i;
                            row2 = j;

                            found2 = true;
                        }
                        if (found1 && found2)
                        {
                            //if same row
                            if (row1 == row2)
                            {
                                plain_text += cipher_matrix[(col1 + 4) % 5, row1];
                                plain_text += cipher_matrix[(col2 + 4) % 5, row2];
                            }
                            //if same col 
                            else if (col1 == col2)
                            {
                                plain_text += cipher_matrix[col1, (row1 + 4) % 5];
                                plain_text += cipher_matrix[col2, (row2 + 4) % 5];
                            }
                            // niether
                            else
                            {
                                plain_text += cipher_matrix[col1, row2];
                                plain_text += cipher_matrix[col2, row1];
                            }
                            break;
                        }
                    }
                    if (found1 && found2) break;
                }
            }
            blocks = new List<string>();
            for (int i = 0; i < plain_text.Length - 1; i += 2)
            {
                blocks.Add(plain_text.Substring(i, 2));
            }
            int changable_index = 0;
            for (int b = 0; b < blocks.Count - 1; b++)
            {
                Console.WriteLine(blocks[b]);
                if (blocks[b][1] == 'x' && blocks[b][0] == blocks[b + 1][0])
                {
                    plain_text = plain_text.Remove(b * 2 + 1+ changable_index, 1);
                    changable_index--;

                }
            }
            if (plain_text[plain_text.Length - 1] == 'x' )
            {
                plain_text = plain_text.Remove(plain_text.Length - 1);
            }
            Console.WriteLine(plain_text);
            Console.WriteLine(plain_text.Length);
            return plain_text.ToUpper();
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] cipher_matrix = GenereatedKey(key);
            string cipher_text  = "";
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "x");
                }
            }
            if (plainText.Length % 2 == 1)
            {
                plainText = plainText.Insert(plainText.Length, "x");
            }
            List<string> blocks = new List<string>();
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                blocks.Add(plainText.Substring(i, 2));
            }
            foreach (var v in blocks)
            {
                Console.WriteLine(v);
            }
            Console.WriteLine(blocks.Count);
            for (int b = 0; b < blocks.Count; b++)
            {
                bool found1 = false, found2 = false;
                int row1 = 0, row2 = 0, col1 = 0, col2 = 0;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (blocks[b][0] == cipher_matrix[i, j])
                        {
                            col1 = i;
                            row1 = j;

                            found1 = true;
                        }
                        if (blocks[b][1] == cipher_matrix[i, j])
                        {
                            col2 = i;
                            row2 = j;

                            found2 = true;
                        }
                        if (found1 && found2)
                        {
                            //if same row
                            if (row1 == row2)
                            {
                                cipher_text += cipher_matrix[(col1 + 1) % 5, row1];
                                cipher_text += cipher_matrix[(col2 + 1) % 5, row2];
                            }
                            //if same col 
                            else if (col1 == col2)
                            {
                                cipher_text += cipher_matrix[col1, (row1 + 1) % 5];
                                cipher_text += cipher_matrix[col2, (row2 + 1) % 5];
                            }
                            // niether 
                            else
                            {
                                cipher_text += cipher_matrix[col1, row2];
                                cipher_text += cipher_matrix[col2, row1];
                            }
                            break;
                        }
                    }
                    if (found1 && found2) break;
                }

            }
            Console.WriteLine(cipher_text);
            return cipher_text;
        }
    }
}
