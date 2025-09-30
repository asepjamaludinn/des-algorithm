function main_des() 
plaintext_string = 'Next.js adalah framework berbasis React.js yang menggabungkan pendekatan Server-Side Rendering (SSR) dan Static Site Generation (SSG). Next.js dirancang untuk mengatasi keterbatasan Client-Side Rendering (CSR) dengan menyediakan fitur rendering sisi server dan pre-rendering halaman secara statis, yang memungkinkan peningkatan performa dan visibilitas SEO. Namun, meskipun banyak digunakan, masih terbatas penelitian empiris yang mengkaji dampak penerapannya terhadap pengalaman pengguna secara langsung. Walaupun seharusnya peningkatan SEO dan performa juga berkontribusi terhadap kepuasan pengguna (Vishal Patel, 2023), situasi ini memperkuat perlunya kajian empiris yang membandingkan efektivitas kedua pendekatan dalam konteks pengembangan aplikasi web secara nyata. Tanpa adanya landasan berbasis data, pemilihan framework cenderung dilakukan berdasarkan preferensi umum industri, bukan berdasarkan evaluasi menyeluruh.';
key_hex = '133457799BBCDFF1'; 

disp('Analisis Enkripsi & Dekripsi DES Standar');
fprintf('Plaintext Asli: %s\n', plaintext_string);
fprintf('Kunci (HEX): %s\n\n', key_hex);

key_bin = hexToBinaryVector(key_hex, 64);

subkeys = generate_subkeys(key_bin);
fprintf('Berhasil membuat 16 sub-kunci untuk proses enkripsi/dekripsi.\n\n');

plaintext_ascii = uint8(plaintext_string);
plaintext_bin_vector = dec2bin(plaintext_ascii, 8)';
plaintext_bin_vector = plaintext_bin_vector(:)';
remainder = mod(length(plaintext_bin_vector), 64);
if remainder ~= 0
    padding_length = 64 - remainder;
    padding = repmat('0', 1, padding_length);
    plaintext_bin_vector = [plaintext_bin_vector, padding];
end

num_blocks = length(plaintext_bin_vector) / 64;
plaintext_blocks = reshape(plaintext_bin_vector, 64, num_blocks)';
fprintf('Plaintext akan diproses dalam %d blok 64-bit.\n', num_blocks);

disp('MEMULAI PROSES ENKRIPSI');
ciphertext_blocks = [];
for i = 1:num_blocks
    fprintf('\nMengenkripsi Blok %d\n', i);
    permuted_block = apply_permutation(plaintext_blocks(i, :), get_des_tables('IP'));
   
    L = permuted_block(1:32);
    R = permuted_block(33:64);
    
    fprintf('Setelah Permutasi Awal: L0=%s, R0=%s\n', binaryVectorToHex(L), binaryVectorToHex(R));
    
    for round_num = 1:16
        temp_L = L;
        L = R;
        
        f_result = feistel_function(R, subkeys(round_num, :));
        
        R_dec = bitxor(bin2dec(temp_L), bin2dec(f_result));
        R = dec2bin(R_dec, 32);
        
        fprintf('Putaran %2d: L=%s, R=%s\n', round_num, binaryVectorToHex(L), binaryVectorToHex(R));
    end
    
    pre_final_block = [R L];
    
    final_ciphertext_block = apply_permutation(pre_final_block, get_des_tables('FP'));
    
    ciphertext_blocks = [ciphertext_blocks; final_ciphertext_block];
    fprintf('Hasil Enkripsi Blok %d (HEX): %s\n', i, binaryVectorToHex(final_ciphertext_block));
end

temp_matrix = ciphertext_blocks';
ciphertext_bin_vector = temp_matrix(:)';
ciphertext_hex = binaryVectorToHex(ciphertext_bin_vector);
fprintf('\nHasil Akhir Enkripsi\n');
fprintf('Ciphertext (HEX): %s\n\n', ciphertext_hex);

disp('MEMULAI PROSES DEKRIPSI');
decrypted_blocks = [];
for i = 1:num_blocks
    fprintf('\nMendekripsi Blok %d\n', i);
    permuted_block = apply_permutation(ciphertext_blocks(i, :), get_des_tables('IP'));
    
    L = permuted_block(1:32);
    R = permuted_block(33:64);
    
    fprintf('Setelah Permutasi Awal: L16=%s, R16=%s\n', binaryVectorToHex(L), binaryVectorToHex(R));
    
    for round_num = 1:16
        temp_L = L;
        L = R;
        
        subkey = subkeys(17 - round_num, :);
        f_result = feistel_function(R, subkey);
        
        R_dec = bitxor(bin2dec(temp_L), bin2dec(f_result));
        R = dec2bin(R_dec, 32);
        
        fprintf('Putaran %2d: L=%s, R=%s\n', 17 - round_num, binaryVectorToHex(L), binaryVectorToHex(R));
    end
    
    pre_final_block = [R L];
    
    final_decrypted_block = apply_permutation(pre_final_block, get_des_tables('FP'));
    
    decrypted_blocks = [decrypted_blocks; final_decrypted_block];
    fprintf('Hasil Dekripsi Blok %d (HEX): %s\n', i, binaryVectorToHex(final_decrypted_block));
end

decrypted_bin_vector = reshape(decrypted_blocks', 1, []);
num_chars = floor(length(decrypted_bin_vector)/8);
decrypted_ascii = bin2dec(reshape(decrypted_bin_vector(1:num_chars*8), 8, num_chars)');

decrypted_string = char(decrypted_ascii(decrypted_ascii ~= 0)');

fprintf('\nHasil Akhir Dekripsi dan Perbandingan\n');
fprintf('Decrypted Text: %s\n', decrypted_string);
if strcmp(strtrim(plaintext_string), strtrim(decrypted_string))
    disp('Perbandingan: SUKSES! Plaintext asli dan hasil dekripsi sama.');
else
    disp('Perbandingan: GAGAL! Plaintext asli dan hasil dekripsi berbeda.');
end
end 

function subkeys = generate_subkeys(key_bin)
    tables = get_des_tables();
    
    permuted_key = apply_permutation(key_bin, tables.PC1);
    
    C = permuted_key(1:28);
    D = permuted_key(29:56);
    
    subkeys = char(zeros(16, 48));
    
    for i = 1:16
        C = circshift(C, [0, -tables.SHIFTS(i)]);
        D = circshift(D, [0, -tables.SHIFTS(i)]);
        
        combined_key = [C D];
        subkeys(i, :) = apply_permutation(combined_key, tables.PC2);
    end
end

function result = feistel_function(R_32bit, subkey_48bit)
    tables = get_des_tables();
    
    expanded_R = apply_permutation(R_32bit, tables.E);
    
    xored_result_dec = bitxor(bin2dec(expanded_R), bin2dec(subkey_48bit));
    xored_result_bin = dec2bin(xored_result_dec, 48);
    
    sbox_output = '';
    for i = 1:8
        chunk = xored_result_bin((i-1)*6 + 1 : i*6);
      
        row = bin2dec([chunk(1) chunk(6)]) + 1; 
    
        col = bin2dec(chunk(2:5)) + 1;
        
        val = tables.S_BOXES(row, col, i);
        sbox_output = [sbox_output, dec2bin(val, 4)];
    end

    result = apply_permutation(sbox_output, tables.P);
end

function output_vector = apply_permutation(input_vector, permutation_table)
    output_vector = input_vector(permutation_table);
end

function hex_string = binaryVectorToHex(bin_vector)
    if isempty(bin_vector), hex_string = ''; return; end
    reshaped_bin = reshape(bin_vector, 4, [])';
    dec_values = bin2dec(reshaped_bin);
    hex_string = dec2hex(dec_values)';
    hex_string = hex_string(:)';
end

function bin_vector = hexToBinaryVector(hex_string, bit_length)
    dec_values = hex2dec(hex_string');
    bin_matrix = dec2bin(dec_values, 4);
    bin_vector = reshape(bin_matrix', 1, []);
    if nargin > 1 && length(bin_vector) < bit_length
        bin_vector = [repmat('0', 1, bit_length - length(bin_vector)), bin_vector];
    end
end

function tables = get_des_tables(table_name)
    persistent S_BOXES IP FP PC1 PC2 E P SHIFTS;
    if isempty(IP)
        IP = [58, 50, 42, 34, 26, 18, 10, 2, ...
              60, 52, 44, 36, 28, 20, 12, 4, ...
              62, 54, 46, 38, 30, 22, 14, 6, ...
              64, 56, 48, 40, 32, 24, 16, 8, ...
              57, 49, 41, 33, 25, 17, 9,  1, ...
              59, 51, 43, 35, 27, 19, 11, 3, ...
              61, 53, 45, 37, 29, 21, 13, 5, ...
              63, 55, 47, 39, 31, 23, 15, 7];
        
        FP = [40, 8, 48, 16, 56, 24, 64, 32, ...
              39, 7, 47, 15, 55, 23, 63, 31, ...
              38, 6, 46, 14, 54, 22, 62, 30, ...
              37, 5, 45, 13, 53, 21, 61, 29, ...
              36, 4, 44, 12, 52, 20, 60, 28, ...
              35, 3, 43, 11, 51, 19, 59, 27, ...
              34, 2, 42, 10, 50, 18, 58, 26, ...
              33, 1, 41,  9, 49, 17, 57, 25];
        
        PC1 = [57, 49, 41, 33, 25, 17,  9,  1, ...
               58, 50, 42, 34, 26, 18, 10,  2, ...
               59, 51, 43, 35, 27, 19, 11,  3, ...
               60, 52, 44, 36, 63, 55, 47, 39, ...
               31, 23, 15,  7, 62, 54, 46, 38, ...
               30, 22, 14,  6, 61, 53, 45, 37, ...
               29, 21, 13,  5, 28, 20, 12,  4];
        
        PC2 = [14, 17, 11, 24,  1,  5,  3, 28, ...
               15,  6, 21, 10, 23, 19, 12,  4, ...
               26,  8, 16,  7, 27, 20, 13,  2, ...
               41, 52, 31, 37, 47, 55, 30, 40, ...
               51, 45, 33, 48, 44, 49, 39, 56, ...
               34, 53, 46, 42, 50, 36, 29, 32];
               
        E = [32,  1,  2,  3,  4,  5,  4,  5, ...
              6,  7,  8,  9,  8,  9, 10, 11, ...
             12, 13, 12, 13, 14, 15, 16, 17, ...
             16, 17, 18, 19, 20, 21, 20, 21, ...
             22, 23, 24, 25, 24, 25, 26, 27, ...
             28, 29, 28, 29, 30, 31, 32,  1];
             
        P = [16,  7, 20, 21, 29, 12, 28, 17, ...
              1, 15, 23, 26,  5, 18, 31, 10, ...
              2,  8, 24, 14, 32, 27,  3,  9, ...
             19, 13, 30,  6, 22, 11,  4, 25];
        
        SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
        
        S_BOXES = zeros(4, 16, 8);
        S_BOXES(:,:,1) = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7;
                          0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8;
                          4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0;
                          15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13];
        S_BOXES(:,:,2) = [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10;
                          3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5;
                          0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15;
                          13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9];
        S_BOXES(:,:,3) = [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8;
                          13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1;
                          13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7;
                          1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12];
        S_BOXES(:,:,4) = [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15;
                          13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9;
                          10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4;
                          3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14];
        S_BOXES(:,:,5) = [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9;
                          14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6;
                          4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14;
                          11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3];
        S_BOXES(:,:,6) = [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11;
                          10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8;
                          9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6;
                          4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13];
        S_BOXES(:,:,7) = [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1;
                          13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6;
                          1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2;
                          6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12];
        S_BOXES(:,:,8) = [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7;
                          1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2;
                          7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8;
                          2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11];
    end
    
    if nargin < 1
        tables.S_BOXES = S_BOXES; tables.IP = IP; tables.FP = FP;
        tables.PC1 = PC1; tables.PC2 = PC2; tables.E = E; tables.P = P;
        tables.SHIFTS = SHIFTS;
    else
        switch upper(table_name)
            case 'S_BOXES', tables = S_BOXES; case 'IP', tables = IP;
            case 'FP', tables = FP; case 'PC1', tables = PC1;
            case 'PC2', tables = PC2; case 'E', tables = E;
            case 'P', tables = P; case 'SHIFTS', tables = SHIFTS;
            otherwise, error('Nama tabel tidak dikenal.');
        end
    end
end