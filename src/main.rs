use std::error::Error;
use std::io::Read;
use std::{fmt};

use crate::constants::{INV_S_BOX, RCON_VALUES, S_BOX};



use crate::helper::{decode_hex_string, encode_hex_string};
use crate::{helper::{xor_vec}};
// mod aes;
mod constants;
mod helper;
// mod gcm;


#[derive(Debug, Clone)]
struct InvalidKeyLengthError{
    message:String
}

impl InvalidKeyLengthError{
    pub fn new(msg:String)->Self{
        Self { message:msg }
    }
}


impl fmt::Display for InvalidKeyLengthError{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "input key. was not of the correct length, required either 128 bits, 196 bits or 256 bits")
    }
}

impl Error for InvalidKeyLengthError{
    fn description(&self) -> &str {
        &self.message
    }
}

fn make_state(input_bytes:&[u8;16])->[[u8; 4];4]{
    /*
        input: 
        [ 0 1 2 3
          4 5 6 7
          8 9 a b
          c d e f
        ]
    state
        [
            [0 4 8 c]
            [1 5 9 d]
            [2 6 a e]
            [3 7 b f]
        ]

     */
    let mut state:[[u8; 4]; 4]  = [[0u8; 4];4];
    for row in 0..4{
        for col in 0..4{
            state[row][col] = input_bytes[row+(4*col)];
        }
    }
    return state;
}

fn unwrap_state_array(state_array: [[u8;4];4])->Vec<u8>{
    let mut ret: Vec<u8> = vec![0u8;16];
    for row in 0..4{
        for col in 0..4{
            ret[row+(4*col)] = state_array[row][col]
        }
    }
    ret
}

const M_X:u8 = 0b0001_1011;

fn mul_gf_8(a:u8, b:u8)->u8{
    let mut result = 0;
    let mut a_copy= a;
    let mut b_copy = b;
    for _ in 0..8{
        if (b_copy & 1) != 0 {
            result ^= a_copy;
        }
        let high_bit_set = (a_copy & 0x80) != 0;
        a_copy <<= 1;
        
        if high_bit_set {
            a_copy ^= M_X;
        }

        b_copy >>= 1;
    }
    result  
}



const NK_VALS:[u8; 3] = [4,6,8];
const NR_VALS:[u8;3] = [10,12,14];

fn sub_word(word:Vec<u8>)->Vec<u8>{
    return word.iter().map(|x| S_BOX[*x as usize]).collect::<Vec<u8>>();
}

fn rot_word(word:Vec<u8>)->Vec<u8>{
    let mut rotated = word.clone();
    rotated.rotate_left(1);
    rotated
}

/// key expansion given either of the 3 length's of keys (128bit, 196bit or 256 bit)
fn key_expansion(key:&Vec<u8>)->Vec<[u8;4]>{
    let mut decider_const = 0;
    if key.len() == 24{
        decider_const = 1;
    }else if key.len() == 32{
        decider_const = 2;
    }
    let nk = NK_VALS[decider_const] as usize; //The number of words comprising the key.
    let nr = NR_VALS[decider_const] as usize; //number of rounds expected to be run.
    let mut i = 0 as usize;
    let mut w: Vec<[u8;4]> = vec![];
    while i <= nk-1{
        w.push(key[4*i..4*i+4].try_into().unwrap());
        i+=1;
    }   
    i = nk;
    while i<=(4*nr)+3{
        let mut temp = w[i-1].clone().to_vec();
        if i.rem_euclid(nk) == 0{
            temp = xor_vec(&sub_word(rot_word(temp)) ,&RCON_VALUES[i/nk].to_vec());
        }
        else if nk > 6 && (i.rem_euclid(nk)==4){
            temp = sub_word(temp);
        }
        w.push(xor_vec(&w[i-nk].to_vec(), &temp)[0..4].try_into().unwrap());
        i+=1;
    }
    return w;
    
}

fn make_keys(words:Vec<[u8;4]>, key_len_bytes:usize)->Result<Vec<[[u8; 4]; 4]>, InvalidKeyLengthError>{
    if key_len_bytes != 16 && key_len_bytes != 24 && key_len_bytes != 32{
        // raise an key length error
        return Err(InvalidKeyLengthError::new("cannot make keys from words because key_len_bytes wasn't right sized".to_string()));
    }
    let keys = words.chunks_exact(4).map(|x| x.try_into().unwrap()).collect::<Vec<[[u8;4];4]>>();
       let expected_keys = match key_len_bytes {
        16 => 11,  // AES-128: rounds 0-10
        24 => 13,  // AES-192: rounds 0-12
        32 => 15,  // AES-256: rounds 0-14
        _ => unreachable!(),
    };
    if keys.len() != expected_keys {
        return Err(InvalidKeyLengthError::new(
            format!("Expected {} round keys for {}-byte key, but got {}", 
                   expected_keys, key_len_bytes, keys.len())
        ));
    }
    Ok(keys)
}

fn shift_rows(mut state_array: [[u8;4];4])->[[u8;4];4]{
    state_array[1].rotate_left(1);
    state_array[2].rotate_left(2);
    state_array[3].rotate_left(3);
    state_array
}

fn inv_shift_rows(mut state_array: [[u8;4];4])->[[u8;4];4]{
    state_array[1].rotate_right(1);
    state_array[2].rotate_right(2);
    state_array[3].rotate_right(3);
    state_array
}


fn mix_cols(state_array: [[u8;4];4])->[[u8;4];4]{
    let mut new_state_array = [[0u8;4];4];
    for col in 0..4
    {
        new_state_array[0][col] = 
            mul_gf_8(02, state_array[0][col]) ^ 
            mul_gf_8(03, state_array[1][col]) ^ 
            state_array[2][col] ^ 
            state_array[3][col];

        new_state_array[1][col] = 
            state_array[0][col] ^ 
            mul_gf_8(02, state_array[1][col]) ^ 
            mul_gf_8(3, state_array[2][col]) ^ 
            state_array[3][col];
        new_state_array[2][col] = 
            state_array[0][col] ^ 
            state_array[1][col] ^ 
            mul_gf_8(02, state_array[2][col]) ^ 
            mul_gf_8(03, state_array[3][col]);
        new_state_array[3][col] = 
            mul_gf_8(03, state_array[0][col]) ^ 
            state_array[1][col] ^
            state_array[2][col] ^ 
            mul_gf_8(02, state_array[3][col]);
    }
    new_state_array
}

const inv_mix_col_matrix:[[u8;4];4] = [[0x0e, 0x0b, 0x0d, 0x09],[0x09,0x0e, 0x0b, 0x0d],[0x0d, 0x09, 0x0e, 0x0b],[0x0b,0x0d,0x09,0x0e]];

fn inv_mix_cols(state_array: [[u8;4];4])->[[u8;4];4]{
    let mut new_state_array = [[0u8;4];4];
    for col in 0..4
    {
        new_state_array[0][col] = 
            mul_gf_8(inv_mix_col_matrix[0][0], state_array[0][col]) ^ 
            mul_gf_8(inv_mix_col_matrix[0][1], state_array[1][col]) ^ 
            mul_gf_8(inv_mix_col_matrix[0][2], state_array[2][col]) ^ 
            mul_gf_8(inv_mix_col_matrix[0][3], state_array[3][col]);
        
        new_state_array[1][col] = 
            mul_gf_8(inv_mix_col_matrix[1][0], state_array[0][col]) ^
            mul_gf_8(inv_mix_col_matrix[1][1], state_array[1][col]) ^ 
            mul_gf_8(inv_mix_col_matrix[1][2], state_array[2][col]) ^ 
            mul_gf_8(inv_mix_col_matrix[1][3], state_array[3][col]); 
            
        new_state_array[2][col] = 
            mul_gf_8(inv_mix_col_matrix[2][0], state_array[0][col]) ^ 
            mul_gf_8(inv_mix_col_matrix[2][1], state_array[1][col]) ^
            mul_gf_8(inv_mix_col_matrix[2][2], state_array[2][col]) ^ 
            mul_gf_8(inv_mix_col_matrix[2][3], state_array[3][col]);
        
        new_state_array[3][col] = 
            mul_gf_8(inv_mix_col_matrix[3][0], state_array[0][col]) ^ 
            mul_gf_8(inv_mix_col_matrix[3][1], state_array[1][col]) ^ 
            mul_gf_8(inv_mix_col_matrix[3][2], state_array[2][col]) ^
            mul_gf_8(inv_mix_col_matrix[3][3], state_array[3][col]); 
    }
    
    new_state_array
}


fn add_round_key(mut state_array: [[u8;4];4], round_keys: &[[u8;4];4])->[[u8;4];4]{
    for col in 0..4{
        for row in 0..4{
            state_array[row][col] ^= round_keys[col][row];
        }
    }
    state_array
}


fn sub_bytes(mut state_array: [[u8;4];4])->[[u8;4];4]{
    for row in 0..4{
        for col in 0..4{
           state_array[row][col] = S_BOX[state_array[row][col] as usize];
        }
    }
    
    state_array
}

fn inv_sub_bytes(mut state_array: [[u8;4];4])->[[u8;4];4]{
    for row in 0..4{
        for col in 0..4{
           state_array[row][col] = INV_S_BOX[state_array[row][col] as usize];
        }
    }
    state_array

}

fn cipher(input_bytes:&Vec<u8>, input_key:&Vec<u8>)->Result<Vec<u8>, InvalidKeyLengthError>{
    let mut deciding_const = 0;
    if input_key.len() == 24{
        deciding_const = 1;
    }else if input_key.len() == 32{
        deciding_const = 2;
    }else if input_key.len() != 16{
        return Result::Err(InvalidKeyLengthError::new("key length was: ".to_string()))
    }
    let nr = NR_VALS[deciding_const] as usize;
    let keys = make_keys(key_expansion(&input_key), input_key.len()).expect("invalid key length");
    let mut states = input_bytes.chunks_exact(16).map(|x: &[u8]| make_state(x.try_into().unwrap()) ).collect::<Vec<[[u8;4];4]>>();
    // in future we should look to see about parallelisation of the states through the cipher
    for i in 0..states.len(){    
        states[i] = add_round_key(states[i], &keys[0]);
        for round in 1..nr{
            states[i] = sub_bytes(states[i]);
            states[i] = shift_rows(states[i]);
            states[i] = mix_cols(states[i]);
            states[i] = add_round_key(states[i], &keys[round]);
        }
        states[i] = sub_bytes(states[i]);
        states[i] = shift_rows(states[i]);
        states[i] = add_round_key(states[i], &keys[nr]);
    }
    let mut out = vec![];
    for x in 0..states.len(){
        out.append(&mut unwrap_state_array(states[x]));
    }
    
    Result::Ok(out)
}

fn inv_cipher( input_bytes:&Vec<u8>,input_key:&Vec<u8>)->Result<Vec<u8>, InvalidKeyLengthError>{
    let mut deciding_const = 0;
    if input_key.len() == 24{
        deciding_const = 1;
    }else if input_key.len() == 32{
        deciding_const = 2;
    }else if input_key.len() != 16{
        return Result::Err(InvalidKeyLengthError::new("key length was: ".to_string()))
    }
    let nr = NR_VALS[deciding_const] as usize;
    let keys = make_keys(key_expansion(&input_key), input_key.len()).expect("invalid key length");
    let mut states = input_bytes.chunks_exact(16).map(|x: &[u8]| make_state(x.try_into().unwrap()) ).collect::<Vec<[[u8;4];4]>>();
    
    for i in 0..states.len(){    

        states[i] = add_round_key(states[i], &keys[nr]);
        
        for round in (1..nr).rev(){
            states[i] = inv_shift_rows(states[i]);
            states[i] = inv_sub_bytes(states[i]);
            states[i] = add_round_key(states[i], &keys[round]);
            states[i] = inv_mix_cols(states[i]);
        }
        states[i] = inv_shift_rows(states[i]);
        states[i] = inv_sub_bytes(states[i]);
        states[i] = add_round_key(states[i], &keys[0]);
    }
    let mut out = vec![];
    for x in 0..states.len(){
        out.append(&mut unwrap_state_array(states[x]));
    }
    
    return Ok(out);

}



fn main(){
    
    
    
}


// this module should soon have its own file
#[cfg(test)]
mod tests{

    #[test]

    fn ecb_mode_tests(){
        use std::io::Read;

        let mut result = std::fs::OpenOptions::new().read(true).write(false).open(".test_vectors/ECBVarTxt128.txt").expect("unable to read file");
        let mut file_content = String::new();
        result.read_to_string(&mut file_content).expect("unable to read from file");
        
        //get rid of the metadata at the start of the file 
        let split = file_content.split("[ENCRYPT]").collect::<Vec<&str>>()[1..].to_vec().join("");
        let split = split.split("[DECRYPT]").collect::<Vec<&str>>();
        let enc_parts = split[0].to_string();
        let enc_split = enc_parts.split("COUNT = ").collect::<Vec<&str>>()[1..].to_vec().join("");
        let enc_split = enc_split.split("\n").collect::<Vec<&str>>().iter().map(|x| x.trim()).collect::<Vec<&str>>();
        // enc_split contains a repeated pattern of 5 things, a number for the test, key to use for the test, a plain text to use for the test, the 
        // output cipher text, and an empty element which represents the \r character which remained after the split on \n because the break line used was a \r\n
        for x in 0..enc_split.len() /5{
            
            // its called a count number in the file but should really be called a test number or something more representative

            use crate::{cipher, helper::{decode_hex_string, encode_hex_string}, inv_cipher};
            let test_num = enc_split[x*5].parse::<u8>().expect("unable to unwrap count number");
            println!("TEST #{test_num}");
            // we specifically specify split on "KEY = " and so on so that we know for sure it found those patterns in the places we expected
            // the " = " pattern could have been used just as easily but doesn't actually prove that we go the thing we needed.
            let key = enc_split[(x*5)+1].split("KEY = ").collect::<Vec<&str>>()[1].to_string();
            println!("\tKEY:                 {key}");
            let pt = enc_split[(x*5)+2].split("PLAINTEXT = ").collect::<Vec<&str>>()[1].to_string();
            println!("\tPLAINTEXT:           {pt}");
            let ct = enc_split[(x*5)+3].split("CIPHERTEXT = ").collect::<Vec<&str>>()[1].to_string();
            println!("\tEXPECTED CIPHERTEXT: {ct}");
            let result = cipher(&decode_hex_string(&pt), &decode_hex_string(&key)).expect("invalid key length");
            println!("\tRESULTED CIPHERTEXT: {}", &encode_hex_string(&result));
            assert_eq!(encode_hex_string(&result), ct);
            let inv_cip_result: Vec<u8> = inv_cipher(&result, &decode_hex_string(&key)).expect("invalid key length");
            // assert that we got the plain text back after running the inverse cipher
            println!("\tRESULTED PLAINTEXT:  {}", encode_hex_string(&inv_cip_result));
            assert_eq!(encode_hex_string(&inv_cip_result), pt);
        }
    }


}
