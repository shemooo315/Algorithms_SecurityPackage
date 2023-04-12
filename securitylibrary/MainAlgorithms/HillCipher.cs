using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {


            List<int> key = new List<int>();
            bool flag = false;
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int m = 0; m < 26; m++)
                        {
                            key = Encrypt(plainText, new List<int> { m, k, j, i });

                            flag = Enumerable.SequenceEqual(key, cipherText);
                            if (flag)
                            {
                                return new List<int> { m, k, j, i };
                            }
                            else
                                continue; 
                        }
                    }
                }
            }
            if (!flag)
                throw new InvalidAnlysisException();
            else
                return key;
        }

        private List<int> MatToList(int[,] matrix)
        {

            List<int> LST = new List<int>();
            for (int i = 0; i < matrix.GetLength(0); i++)
                for (int j = 0; j < matrix.GetLength(1); j++)
                    LST.Add(matrix[i, j]);
            return LST;


        }

        //ListToMat function to conver List to matrix
        private int[,] ListToMat(List<int> key)
        {
            int[,] Matrix_Key;

            int count;
            if (key.Count % 2 == 0)
            {
                Matrix_Key = new int[2, 2];
                count = 0;
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        Matrix_Key[i, j] = key[count];

                        count++;
                    }
                }
            }

            else if (key.Count % 3 == 0)
            {
                Matrix_Key = new int[3, 3];
                count = 0;
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        Matrix_Key[i, j] = key[count];
                        count++;
                    }
                }
            }

            else
                Matrix_Key = new int[3, 2];

            return Matrix_Key;
        }


        //function to get determine of key matrix
        private int Det(int[,] keyMatrix)
        {
            int det = 0;

            if (keyMatrix.GetLength(0) == 2)
                det += (keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[0, 1] * keyMatrix[1, 0]);

            else
                for (int i = 0; i < 3; i++)
                {
                    det += (keyMatrix[0, i] * (keyMatrix[1, (i + 1) % 3] * keyMatrix[2, (i + 2) % 3] - keyMatrix[1, (i + 2) % 3] * keyMatrix[2, (i + 1) % 3]));
                }

            return det;
        }


        //minor matrix of key function
        private int[,] MinorMatrix(int[,] matrix, int r, int c)
        {
            int[,] minor = new int[matrix.GetLength(0) - 1, matrix.GetLength(1) - 1];
            int m = 0, n = 0;

            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                if (i == r)
                    continue;
                n = 0;
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    if (j == c)
                        continue;
                    minor[m, n] = matrix[i, j];
                    n++;
                }
                m++;
            }
            return minor;
        }

        private int Mod(int x1, int M)
        {
            if (x1 < 0)
                return ((x1 % M) + M) % M;
            return x1 % M;
        }
        private int find(int Det)
        {
            int result = 0;
            for (int i = 2; i < 26; i++)
            {
                if (((i * Det) % 26) == 1)
                {
                    result = i;
                    break;
                }
            }
            return result;
        }
        private int[,] flip2x2Matrix(int[,] matrix)
        {
            int[,] flip = new int[2, 2];
            flip[0, 0] = matrix[1, 1];
            flip[1, 1] = matrix[0, 0];
            flip[0, 1] = 0 - matrix[0, 1];
            flip[1, 0] = 0 - matrix[1, 0];
            return flip;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {

            List<int> ptext = new List<int>();
            //convert key list to matrix
            int[,] keyMatrix = ListToMat(key);

            int det = Mod(Det(keyMatrix), 26);
            //A × A-1 = I 
            List<int> keyInverseList = new List<int>();
            int[,] keyMatInverse = new int[keyMatrix.GetLength(0), keyMatrix.GetLength(1)];
            if (keyMatrix.GetLength(0) != keyMatrix.GetLength(1))
                throw new System.Exception();


            if (keyMatrix.GetLength(0) == 3)
            {
                int b = find(det);
                for (int i = 0; i < keyMatrix.GetLength(0); i++)
                {
                    for (int j = 0; j < keyMatrix.GetLength(1); j++)
                    {
                        int[,] minorMatrix = this.MinorMatrix(keyMatrix, j, i);
                        int subdet = this.Mod(this.Det(minorMatrix), 26);
                        keyMatInverse[i, j] = Convert.ToInt32(b * Math.Pow(-1, i + j) * subdet);
                        keyMatInverse[i, j] = this.Mod(keyMatInverse[i, j], 26);
                    }
                }
                keyInverseList = MatToList(keyMatInverse);
                for (int k = 0; k < cipherText.Count; k += 3)
                    for (int i = 0; i < keyInverseList.Count; i += 3)
                        ptext.Add(((keyInverseList[i] * cipherText[k]) + (keyInverseList[i + 1] * cipherText[k + 1]) + (keyInverseList[i + 2] * cipherText[k + 2])) % 26);
            }

            else if (keyMatrix.GetLength(0) == 2)
            {
                det = Det(keyMatrix);
                int[,] flipMatrix = this.flip2x2Matrix(keyMatrix);
                for (int i = 0; i < keyMatInverse.GetLength(0); i++)
                    for (int j = 0; j < keyMatInverse.GetLength(1); j++)
                        keyMatInverse[i, j] = this.Mod(((1 / det) * flipMatrix[i, j]), 26);
                keyInverseList = this.MatToList(keyMatInverse);
                for (int k = 0; k < cipherText.Count; k += 2)
                    for (int i = 0; i < keyInverseList.Count; i += 2)
                        ptext.Add(((keyInverseList[i] * cipherText[k]) + (keyInverseList[i + 1] * cipherText[k + 1])) % 26);
            }

            if (ptext.FindAll(s => s.Equals(0)).Count == ptext.Count)
                throw new System.Exception();
            return ptext;
        }





        public List<int> Encrypt(List<int> plainText, List<int> key)
        {

            List<int> ctext = new List<int>();
            if (key.Count % 2 == 0)
                for (int k = 0; k < plainText.Count; k += 2)
                    for (int i = 0; i < key.Count; i += 2)
                        ctext.Add(((key[i] * plainText[k]) + (key[i + 1] * plainText[k + 1])) % 26);

            else if (key.Count % 3 == 0)
                for (int k = 0; k < plainText.Count; k += 3)
                    for (int i = 0; i < key.Count; i += 3)
                        ctext.Add(((key[i] * plainText[k]) + (key[i + 1] * plainText[k + 1]) + (key[i + 2] * plainText[k + 2])) % 26);
            return ctext;
        }

       
        public int GCD(int num1, int num2)
        {
            int Remainder;

            while (num2 != 0)
            {
                Remainder = num1 % num2;
                num1 = num2;
                num2 = Remainder;
            }

            return num1;
        }
        public int det_matrix2x2(int a, int b, int c, int d, int sign)
        {

            if (sign == 1)
            {
                return (((((a * d) - (b * c)) % 26) + 26) % 26);
            }
            else
            {
                return (((((b * c) - (a * d)) % 26) + 26) % 26);

            }

        }
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<int> plaintext = new List<int>();
            int[,] matrixkey = new int[3, 3];
            int[,] matrixcipher = new int[3, 1];
            int count = 0;
            int det = 0;
            int b = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (plain3[count] < 0 || plain3[count] > 26)
                    {
                        throw new InvalidAnlysisException();
                    }
                    else
                    {
                        matrixkey[i, j] = plain3[count];
                        count++;
                    }
                }
            }
            count = 0;
            // calculating det for 2x2 or 3x3 matrices

            for (int i = 0; i < 3; i++)
                det = det + (matrixkey[0, i] * (matrixkey[1, (i + 1) % 3] * matrixkey[2, (i + 2) % 3] - matrixkey[1, (i + 2) % 3] * matrixkey[2, (i + 1) % 3]));



            det = ((det % 26) + 26) % 26;
            // calculating b
            for (int i = 0; i < 26; i++)
            {
                if ((((i * det) % 26) + 26) % 26 == 1)
                {
                    b = i;
                    break;
                }
            }

            if (det == 0 || GCD(26, det) != 1 || b == 0)
                throw new InvalidAnlysisException();

            int[,] inverse_key_matrix = new int[3, 3];
            int[,] transpose_matrix = new int[3, 3];
            // calculating transpose matrix for 2x2 or 3x3 matrices  
            int temp;
            int z;
            int[] signs = new int[] { 1, 0, 1, 0, 1, 0, 1, 0, 1 };
            int c = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    temp = b * Convert.ToInt32(Math.Pow(-1, i + j));
                    z = det_matrix2x2(matrixkey[(i + 1) % 3, (j + 1) % 3], matrixkey[(i + 1) % 3, (j + 2) % 3], matrixkey[(i + 2) % 3, (j + 1) % 3], matrixkey[(i + 2) % 3, (j + 2) % 3], signs[c]);
                    c++;
                    inverse_key_matrix[i, j] = (((temp * z) % 26) + 26) % 26;
                    transpose_matrix[j, i] = inverse_key_matrix[i, j];
                }
            }
            count = 0;
            int acc = 0;
            int[,] test = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    test[i, j] = cipher3[count];
                    count++;
                }
            }
            count = 0;
            for (int i = 0; i < cipher3.Count / 3; i++)
            {

                for (int cc = 0; cc < 3; cc++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        acc += (transpose_matrix[count, j] * test[j, cc]);
                    }
                    plaintext.Add(((acc % 26) + 26) % 26);
                    acc = 0;
                }
                count++;
            }
            count = 0;
            int[,] show = new int[3, 3];
            int[,] show_x = new int[3, 3];

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    show[i, j] = plaintext[count];
                    count++;
                }
            }
            count = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    show_x[j, i] = show[i, j];

                }
            }
            List<int> t = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    t.Add(show_x[i, j]);
                }
            }
            return t;

        }

      
    }
}