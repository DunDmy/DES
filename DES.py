import sys
import binascii

key_pc1 = [57, 49, 41, 33, 25, 17, 9, 
        1, 58, 50, 42, 34, 26, 18, 
        10, 2, 59, 51, 43, 35, 27, 
        19, 11, 3, 60, 52, 44, 36, 
        63, 55, 47, 39, 31, 23, 15, 
        7, 62, 54, 46, 38, 30, 22, 
        14, 6, 61, 53, 45, 37, 29, 
        21, 13, 5, 28, 20, 12, 4 ]

key_pc2 = [14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32]

init_perm = [58, 50, 42, 34, 26, 18, 10, 2, 
        60, 52, 44, 36, 28, 20, 12, 4, 
        62, 54, 46, 38, 30, 22, 14, 6, 
        64, 56, 48, 40, 32, 24, 16, 8, 
        57, 49, 41, 33, 25, 17, 9, 1, 
        59, 51, 43, 35, 27, 19, 11, 3, 
        61, 53, 45, 37, 29, 21, 13, 5, 
        63, 55, 47, 39, 31, 23, 15, 7] 

s_perm = [16, 7, 20, 21,
        29, 12, 28, 17, 
        1, 15, 23, 26, 
        5, 18, 31, 10, 
        2, 8, 24, 14, 
        32, 27, 3, 9, 
        19, 13, 30, 6, 
        22, 11, 4, 25]

final_perm = [ 40, 8, 48, 16, 56, 24, 64, 32, 
               39, 7, 47, 15, 55, 23, 63, 31, 
               38, 6, 46, 14, 54, 22, 62, 30, 
               37, 5, 45, 13, 53, 21, 61, 29, 
               36, 4, 44, 12, 52, 20, 60, 28, 
               35, 3, 43, 11, 51, 19, 59, 27, 
               34, 2, 42, 10, 50, 18, 58, 26, 
               33, 1, 41, 9, 49, 17, 57, 25 ]

#NOTE: the firt value in this array is ignored
left_sht = [0, 1, 1, 2, 2, 2, 2, 2, 2, 1,
         2, 2, 2, 2, 2, 2, 1]

#E BIT - Selection table
exp_e = [32, 1 , 2 , 3 , 4 , 5 , 4 , 5, 
         6 , 7 , 8 , 9 , 8 , 9 , 10, 11, 
         12, 13, 12, 13, 14, 15, 16, 17, 
         16, 17, 18, 19, 20, 21, 20, 21, 
         22, 23, 24, 25, 24, 25, 26, 27, 
         28, 29, 28, 29, 30, 31, 32, 1 ]

#S-box table
sbox =  [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], 
          [ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], 
          [ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], 
          [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ]],
             
         [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], 
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], 
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], 
           [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ]], 
    
         [ [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], 
           [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], 
           [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], 
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ]], 
        
          [ [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], 
           [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], 
           [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], 
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14] ], 
         
          [ [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], 
           [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], 
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], 
           [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ]], 
        
         [ [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], 
           [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], 
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], 
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13] ], 
          
          [ [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], 
           [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], 
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], 
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12] ], 
         
         [ [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], 
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], 
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], 
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11] ] ]


# This funtion produces a list of blocks
def get_blocks(block_size, plaint_text):
    # check if plaint text size is divisible by a block size
    if len(plaint_text) % block_size != 0:
        num_of_zeros = block_size - (len(plaint_text) % block_size)
        new_plaint_text = '0'* num_of_zeros + plaint_text
        return create_blocks(block_size, new_plaint_text, len(new_plaint_text))
    else:
        return create_blocks(block_size, plaint_text, len(plaint_text))


# calculating xow of two strings of binary number a and b
def get_xor(right_text, keys):
    xor_result = ""
    for i in range(0, len(right_text)):
        if right_text[i] == keys[i]:
            xor_result = xor_result + "0"
        else:
            xor_result = xor_result + "1"
    return xor_result


# This function creates a block
def create_blocks(block_size, plaint_text, plaint_size):
    blocks = []
    block = ''
    counter = 1
    #print(plaint_size)
    for i in range (0, plaint_size):
        # create a block
        block += plaint_text[i]
        if(counter == block_size):
            # append to the blcok and reset
            blocks.append(block)
            block = ''
            counter = 0
        counter += 1
    return blocks


# This function gets encryption keys
def get_key(key, key_pc1, key_pc2, left_sht):
    keys = []
    subkeys = get_subkeys(key, key_pc1, left_sht)
    concat_key = get_concat_key(subkeys)

    for i in range(0, len(concat_key)):
        keys.append(get_permutation(concat_key[i], key_pc2))

    return keys


# This function returns the list of subkeys 
def get_subkeys(key, key_pc1, left_sht):
    subkeys = [None] * 17
    key_bin = get_bin(key)
    keys_list = list(key_bin)
    key_perm = get_permutation(keys_list, key_pc1)
    split_keys = get_key_split(key_perm, len(key_perm)/2)
    subkeys[0] = split_keys
    # create subkey
    for i in range (1, 17):
        temp_subkey = []
        lf_key = get_left_shift(left_sht[i], subkeys[i-1][0])
        rg_key = get_left_shift(left_sht[i], subkeys[i-1][1])
        temp_subkey.append(lf_key)
        temp_subkey.append(rg_key)
        subkeys[i] = temp_subkey
    
    #print_subkeys(subkeys)
    
    return subkeys


# This function concatenates the keys
def get_concat_key(subkeys):
    concat_key = []
    for i in range(1, len(subkeys)):
        lf_key = subkeys[i][0]
        rg_key = subkeys[i][1]
        ct_key = lf_key + rg_key
        concat_key.append(ct_key)
    #print(concat_key)
    return concat_key


# This function takes hex and returns bins
def get_bin(hex_value):
    bin_value = bin(int(hex_value, 16))[2:].zfill(64)
    return bin_value


# This function takes hex and returns bins
def get_bin_s_table(hex_value):
    bin_value = bin(int(hex_value, 16))[2:].zfill(4)
    return bin_value


# This funcion returns takes a string and returns the hex 
def get_hex(text):
    return text.encode('ISO-8859-1').hex()


# This function coverts bins to dec
def get_dec(bin_value):
    return int(bin_value, 2)


# This function takes an array of bins and an array of pemutation and create a new order
def get_permutation(keys_list, key_pc):
    permutation_result = []
    for i in range(0, len(key_pc)):
        permutation_result.append(keys_list[key_pc[i]-1])
    return permutation_result


# This function takes a key and splits into key based on give split value
def get_key_split(key, split_value):
    key_split = []
    key_split.append(key[0:int(split_value)])
    key_split.append(key[int(split_value):int(split_value) * 2])
    return key_split


# This function shifts values either by 1 or 2, based on the given shift parameter
def get_left_shift(shift, key):
    shifted_key = []
    if shift == 1:
        for i in range(1,len(key)):
            shifted_key.append(key[i])
        shifted_key.append(key[0])
    else:
        for i in range(2,len(key)):
            shifted_key.append(key[i])
        shifted_key.append(key[0])
        shifted_key.append(key[1])
    return shifted_key


def get_s_box(xor_result):
    s_box_result = " "
    for i in range(0, 8):
        s_row = int(xor_result[i * 6] + xor_result[i * 6 + 5], 2)
        s_col = int(xor_result[i * 6 + 1] + xor_result[i * 6 + 2] + xor_result[i * 6 + 3] + xor_result[i * 6 + 4], 2)
        s_val = sbox[i][s_row][s_col]
        #print(s_val)
        s_val_hex = hex(s_val)
        s_box_result = s_box_result + get_bin_s_table(s_val_hex)
        # remove leading space before return
    return s_box_result[1:]


# Print subkeys 
def print_subkeys(subkeys):
    for i in range(0, len(subkeys)):
        lf_key = ''.join(subkeys[i][0])
        rg_key = ''.join(subkeys[i][1])    
        print("C: " + str(i) + " " + lf_key)
        print("D: " + str(i) + " " + rg_key + '\n')


# Print keys
def print_keys(keys):
    for i in range(0, len(keys)):
        k = ''.join(keys[i])
        print("K: " + str(i) + " " + k)


# Encryption/Decryption function
def f_function(text_blocks, keys, output_file):
    # process multiple blocks of text
    for block in text_blocks:
        #print(block)
        cipher_text = ""
        text_perm = get_permutation(block, init_perm)
        text_split = get_key_split(text_perm, 32)
        left_side = text_split[0]
        right_side = text_split[1]
        # run 16 rounds of ecryption
        for i in range(0, 16):
            right_text = get_permutation(right_side, exp_e)
            xor_result = get_xor(right_text, keys[i])
            s_result = get_s_box(xor_result)
            s_perm_result = get_permutation(list(s_result), s_perm)
            left_side = get_xor(left_side, s_perm_result)
   
            if(i != 15):
                left_side, right_side = right_side, left_side
    
        l_r_concat = left_side + right_side
        cipher_array = get_permutation(l_r_concat, final_perm)
        # convert to a string of bits
        for i in range(0, len(cipher_array)):
            cipher_text += ''.join(cipher_array[i])
        # convert to hex
        cipher_text = hex(int(cipher_text, 2))[2:]

        cipher_writer = open(output_file, "a")
        cipher_writer.writelines(cipher_text)
        cipher_writer.close()

    return 0


# This function encrypts the plaint text.
def DES_encrypt(plainttext_line, key, ciphertextFileName):

    text_bin = get_bin(plainttext_line)

    keys = get_key(key, key_pc1, key_pc2, left_sht)

    text_blocks = get_blocks(64, text_bin)

    f_function(text_blocks, keys, ciphertextFileName)
    
    return 1


# This function decrypts the plaint text.
def DES_decrypt(cypher_text, key, plain_text):

    keys = get_key(key, key_pc1, key_pc2, left_sht)
    #reverse keys
    rev_keys = keys[::-1]

    text_bin = get_bin(cypher_text)
    # get blocks from plain text
    text_blocks = get_blocks(64, text_bin)
 
    f_function(text_blocks, rev_keys, plain_text)
    
    return 0


def main(argv):
    plain_text_file = ''
    ecryption_text_file = ''
    operation = argv[1]

    if operation == 'e':
        plain_text_file = argv[2]
    else:
        ecryption_text_file = argv[2]
    
    key_file = argv[3]
    output_file = argv[4]

    if operation == 'e':
        key_reader = open(key_file, 'r')
        output_writer = open(output_file, 'x')

        # get a key
        key = key_reader.readline()

        # close files
        key_reader.close()
        output_writer.close()
        with open(plain_text_file, 'r') as reader:
            # handle a new line
            lines = (line.rstrip() for line in reader) 
            lines = list(line for line in lines if line)
            # read line
            for line in lines:
                DES_encrypt(line, key, output_file)
    elif operation == 'd':
        key_reader = open(key_file, 'r')
        output_writer = open(output_file, 'x')
        # get a key
        key = key_reader.readline()

        # close files
        key_reader.close()
        output_writer.close()

        with open(ecryption_text_file, 'r') as reader:
            # handle a new line
            lines = (line.rstrip() for line in reader) 
            lines = list(line for line in lines if line)
            # read line
            for line in lines:
                DES_decrypt(line, key, output_file)
    else:
        print("INVALID OPERATION!")


if __name__ == "__main__":
   main(sys.argv)