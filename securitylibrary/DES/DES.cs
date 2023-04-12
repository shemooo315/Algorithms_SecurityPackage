using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {

        int[,] Permutation_Function = new int[8, 4] {
                { 16, 7, 20, 21 },
                { 29, 12, 28, 17 },
                { 1, 15, 23, 26 },
                { 5, 18, 31, 10 },
                { 2, 8, 24, 14 },
                { 32, 27, 3, 9 },
                { 19, 13, 30, 6 },
                { 22, 11, 4, 25 } };

        int[,] Expansion_Permutation = new int[8, 6] {
                { 32, 1, 2, 3, 4, 5 },
                { 4, 5, 6, 7, 8, 9 },
                { 8, 9, 10, 11, 12, 13 },
                { 12, 13, 14, 15, 16, 17 },
                { 16, 17, 18, 19, 20, 21 },
                { 20, 21, 22, 23, 24, 25 },
                { 24, 25, 26, 27, 28, 29 },
                { 28, 29, 30, 31, 32, 1 } };

        int[,] Initial_Permutation = new int[8, 8] {
                { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1 },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 } };

        int[,] Inverse_Initial_Permutation = new int[8, 8] {
                { 40, 8, 48, 16, 56, 24, 64, 32 },
                { 39, 7, 47, 15, 55, 23, 63, 31 },
                { 38, 6, 46, 14, 54, 22, 62, 30 },
                { 37, 5, 45, 13, 53, 21, 61, 29 },
                { 36, 4, 44, 12, 52, 20, 60, 28 },
                { 35, 3, 43, 11, 51, 19, 59, 27 },
                { 34, 2, 42, 10, 50, 18, 58, 26 },
                { 33, 1, 41, 9, 49, 17, 57, 25 } };

        int[,] Permutation_Choice1 = new int[8, 7]
        { { 57, 49, 41, 33, 25, 17, 9 },
            { 1, 58, 50, 42, 34, 26, 18 },
            { 10, 2, 59, 51, 43, 35, 27 },
            { 19, 11, 3, 60, 52, 44, 36 },
            { 63, 55, 47, 39, 31, 23, 15 },
            { 7, 62, 54, 46, 38, 30, 22 },
            { 14, 6, 61, 53, 45, 37, 29 },
            { 21, 13, 5, 28, 20, 12, 4 } };

        int[,] Permutation_Choice2 = new int[8, 6]
        { { 14, 17, 11, 24, 1, 5 },
            { 3, 28, 15, 6, 21, 10 },
            { 23, 19, 12, 4, 26, 8 },
            { 16, 7, 27, 20, 13, 2 },
            { 41, 52, 31, 37, 47, 55 },
            { 30, 40, 51, 45, 33, 48 },
            { 44, 49, 39, 56, 34, 53 },
            { 46, 42, 50, 36, 29, 32 } };

        int[,] Sbox_Round1 = new int[4, 16] {
                { 14, 4, 13, 1, 2, 15, 11, 8, 3,
                    10, 6, 12, 5, 9, 0, 7 },
                    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        int[,] Sbox_Round2 = new int[4, 16] {
                { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        int[,] Sbox_Round3 = new int[4, 16] {
                { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        int[,] Sbox_Round4 = new int[4, 16] {
                { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        int[,] Sbox_Round5 = new int[4, 16] {
                { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        int[,] Sbox_Round6 = new int[4, 16] {
                { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        int[,] Sbox_Round7 = new int[4, 16] {
                { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        int[,] Sbox_Round8 = new int[4, 16] {
                { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };


        public override string Decrypt(string cipherText, string key)
        {

            string Plain_Text = "";
            string permutated_key = null;
            List<string> first_half = new List<string>();
            List<string> second_half = new List<string>();
            List<string> combined_keys = new List<string>();
            List<string> key_of_each_round = new List<string>();
            string converted_ciphertext = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');

            // dividing the plain text into left and right
            string C_left = "";
            string C_right = "";
            for (int i = 0; i < converted_ciphertext.Length / 2; i++)
            {
                C_left = C_left + converted_ciphertext[i];
                C_right = C_right + converted_ciphertext[i + converted_ciphertext.Length / 2];
            }

            // key discarding process (Permutation_Choice1 for the KEY) 
            key = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    permutated_key = permutated_key + key[Permutation_Choice1[i, j] - 1];
                }
            }

            // dividing the KEY into left and right halves, C and D , where each half has 28 bits.
            string C = permutated_key.Substring(0, 28);
            string D = permutated_key.Substring(28, 28);

            // shift key per round
            for (int i = 0; i <= 16; i++)
            {
                first_half.Add(C);
                second_half.Add(D);
                string tmp = "";

                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    tmp = tmp + C[0];
                    C = C.Remove(0, 1);
                    C = C + tmp;
                    tmp = "";
                    tmp = tmp + D[0];
                    D = D.Remove(0, 1);
                    D = D + tmp;
                }
                else
                {
                    tmp = tmp + C.Substring(0, 2);
                    C = C.Remove(0, 2);
                    C = C + tmp;
                    tmp = "";
                    tmp = tmp + D.Substring(0, 2);
                    D = D.Remove(0, 2);
                    D = D + tmp;
                }
            }

            // permutation choice 2
            for (int i = 0; i < second_half.Count; i++)
            {
                combined_keys.Add(first_half[i] + second_half[i]);
            }
            for (int k = 1; k < combined_keys.Count; k++)
            {
                permutated_key = "";
                string tmp = "";
                tmp = combined_keys[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        permutated_key = permutated_key + tmp[Permutation_Choice2[i, j] - 1];
                    }
                }
                key_of_each_round.Add(permutated_key);
            }

            // initial permutation (ip) for ciphertext
            string ip = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ip = ip + converted_ciphertext[Initial_Permutation[i, j] - 1];
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = ip.Substring(0, 32);
            string r = ip.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string outer_bits = "";
            string middle_bits = "";

            string E_bit = "";
            string c_xor_k = "";
            List<string> sbox = new List<string>();
            string split_6 = "";
            int row = 0;
            int col = 0;
            string splited_4 = "";
            string pf_result = "";
            string new_RCT = "";
            ///// 16 round //////////
            for (int i = 0; i < 16; i++)
            {
                L.Add(r);
                c_xor_k = "";
                E_bit = "";
                new_RCT = "";
                pf_result = "";
                sbox.Clear();
                splited_4 = "";
                col = 0;
                row = 0;
                split_6 = "";

                // expansion permutation
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        E_bit = E_bit + r[Expansion_Permutation[j, k] - 1];
                    }
                }

                for (int g = 0; g < E_bit.Length; g++)
                {
                    c_xor_k = c_xor_k + (key_of_each_round[key_of_each_round.Count - 1 - i][g] ^ E_bit[g]).ToString();
                }


                /// sbox
                for (int z = 0; z < c_xor_k.Length; z = z + 6)
                {
                    split_6 = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= c_xor_k.Length)
                            split_6 = split_6 + c_xor_k[y];
                    }

                    sbox.Add(split_6);
                }

                split_6 = "";
                int sb = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    split_6 = sbox[s];
                    outer_bits = split_6[0].ToString() + split_6[5];
                    middle_bits = split_6[1].ToString() + split_6[2] + split_6[3] + split_6[4];

                    row = Convert.ToInt32(outer_bits, 2);
                    col = Convert.ToInt32(middle_bits, 2);
                    if (s == 0)
                        sb = Sbox_Round1[row, col];

                    if (s == 1)
                        sb = Sbox_Round2[row, col];

                    if (s == 2)
                        sb = Sbox_Round3[row, col];

                    if (s == 3)
                        sb = Sbox_Round4[row, col];

                    if (s == 4)
                        sb = Sbox_Round5[row, col];

                    if (s == 5)
                        sb = Sbox_Round6[row, col];

                    if (s == 6)
                        sb = Sbox_Round7[row, col];

                    if (s == 7)
                        sb = Sbox_Round8[row, col];

                    splited_4 = splited_4 + Convert.ToString(sb, 2).PadLeft(4, '0');
                }

                outer_bits = "";
                middle_bits = "";
                //final permutation
                for (int k = 0; k < 8; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pf_result = pf_result + splited_4[Permutation_Function[k, j] - 1];
                    }
                }

                for (int k = 0; k < pf_result.Length; k++)
                {
                    new_RCT = new_RCT + (pf_result[k] ^ l[k]).ToString();
                }

                r = new_RCT;
                l = L[i + 1];
                R.Add(r);
            }
            // inverse initial permutation
            string R16_L16 = R[16] + L[16];
            string plaintxt = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    plaintxt = plaintxt + R16_L16[Inverse_Initial_Permutation[i, j] - 1];
                }
            }
            Plain_Text = "0x" + Convert.ToInt64(plaintxt, 2).ToString("X").PadLeft(16, '0');
            return Plain_Text;
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
        public override string Encrypt(string plainText, string key)
        {
            string Cipher_Text = "";
            string permutated_key = null;
            List<string> first_half = new List<string>();
            List<string> second_half = new List<string>();
            List<string> combined_keys = new List<string>();
            List<string> key_of_each_round = new List<string>();

            string converted_plaintext = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');

            // dividing the plain text into left and right
            string P_left = "";
            string P_right = "";

            for (int i = 0; i < converted_plaintext.Length / 2; i++)
            {
                P_left = P_left + converted_plaintext[i];
                P_right = P_right + converted_plaintext[i + converted_plaintext.Length / 2];
            }


            // key discarding process (Permutation_Choice1 for the KEY) 
            key = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    permutated_key = permutated_key + key[Permutation_Choice1[i, j] - 1];
                }
            }

            // dividing the KEY into left and right halves, C and D , where each half has 28 bits.
            string C = permutated_key.Substring(0, 28);
            string D = permutated_key.Substring(28, 28);

            // shift key per round
            for (int i = 0; i <= 16; i++)
            {
                first_half.Add(C);
                second_half.Add(D);
                string tmp = "";

                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    tmp = tmp + C[0];
                    C = C.Remove(0, 1);
                    C = C + tmp;
                    tmp = "";
                    tmp = tmp + D[0];
                    D = D.Remove(0, 1);
                    D = D + tmp;
                }
                else
                {
                    tmp = tmp + C.Substring(0, 2);
                    C = C.Remove(0, 2);
                    C = C + tmp;
                    tmp = "";
                    tmp = tmp + D.Substring(0, 2);
                    D = D.Remove(0, 2);
                    D = D + tmp;
                }
            }

            // permutation choice 2
            for (int i = 0; i < second_half.Count; i++)
            {
                combined_keys.Add(first_half[i] + second_half[i]);
            }
            for (int k = 1; k < combined_keys.Count; k++)
            {
                permutated_key = "";
                string tmp = "";
                tmp = combined_keys[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        permutated_key = permutated_key + tmp[Permutation_Choice2[i, j] - 1];
                    }
                }
                key_of_each_round.Add(permutated_key);
            }

            // initial permutation (ip) for plaintext
            string ip = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ip = ip + converted_plaintext[Initial_Permutation[i, j] - 1];
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = ip.Substring(0, 32);
            string r = ip.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string outer_bits = "";
            string middle_bits = "";

            string E_bit = "";
            string p_xor_k = "";
            List<string> sbox = new List<string>();
            string split_6 = "";
            int row = 0;
            int col = 0;
            string splited_4 = "";
            string pf_result = "";
            string new_RPT = "";

            for (int i = 0; i < 16; i++)
            {
                L.Add(r);
                p_xor_k = "";
                E_bit = "";
                new_RPT = "";
                pf_result = "";
                sbox.Clear();
                splited_4 = "";
                col = 0;
                row = 0;
                split_6 = "";
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        E_bit = E_bit + r[Expansion_Permutation[j, k] - 1];
                    }
                }

                for (int g = 0; g < E_bit.Length; g++)
                {
                    p_xor_k = p_xor_k + (key_of_each_round[i][g] ^ E_bit[g]).ToString();
                }
                /// sbox
                for (int z = 0; z < p_xor_k.Length; z = z + 6)
                {
                    split_6 = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= p_xor_k.Length)
                            split_6 = split_6 + p_xor_k[y];
                    }

                    sbox.Add(split_6);
                }

                split_6 = "";
                int s_box_result = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    split_6 = sbox[s];
                    outer_bits = split_6[0].ToString() + split_6[5];
                    middle_bits = split_6[1].ToString() + split_6[2] + split_6[3] + split_6[4];

                    row = Convert.ToInt32(outer_bits, 2);
                    col = Convert.ToInt32(middle_bits, 2);
                    if (s == 0)
                        s_box_result = Sbox_Round1[row, col];

                    if (s == 1)
                        s_box_result = Sbox_Round2[row, col];

                    if (s == 2)
                        s_box_result = Sbox_Round3[row, col];

                    if (s == 3)
                        s_box_result = Sbox_Round4[row, col];

                    if (s == 4)
                        s_box_result = Sbox_Round5[row, col];

                    if (s == 5)
                        s_box_result = Sbox_Round6[row, col];

                    if (s == 6)
                        s_box_result = Sbox_Round7[row, col];

                    if (s == 7)
                        s_box_result = Sbox_Round8[row, col];

                    splited_4 = splited_4 + Convert.ToString(s_box_result, 2).PadLeft(4, '0');
                }

                outer_bits = "";
                middle_bits = "";
                //final permutation
                for (int k = 0; k < 8; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pf_result = pf_result + splited_4[Permutation_Function[k, j] - 1];
                    }
                }

                for (int k = 0; k < pf_result.Length; k++)
                {
                    new_RPT = new_RPT + (pf_result[k] ^ l[k]).ToString();
                }

                r = new_RPT;
                l = L[i + 1];
                R.Add(r);
            }
            // inverse initial permutation
            string R16_L16 = R[16] + L[16];
            string ciphertxt = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt = ciphertxt + R16_L16[Inverse_Initial_Permutation[i, j] - 1];
                }
            }
            Cipher_Text = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X");

            return Cipher_Text;
        }
    }
}