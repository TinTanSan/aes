/*
    most code derived from official NIST publications:
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    and it's updated version
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    
    
    official citation as recommended by NIST:
    National Institute of Standards and Technology (2001) Advanced Encryption
    Standard (AES). (Department of Commerce, Washington, D.C.), Federal Information Processing Standards Publication (FIPS) NIST FIPS 197-upd1, updated
    May 9, 2023. https://doi.org/10.6028/NIST.FIPS.197-upd1
*/




use crate::{constants::*, helper::*};

///single byte substitution by using the lookup table called S-BOX in constants.rs
pub fn s_byte(byte:u8)->u8{
    S_BOX[byte as usize]
}

/// byte substitution for all bytes in a vector using s_byte function on each byte
pub fn vec_sub_bytes(mut input_vec:Vec<u8>)->Vec<u8>{
    for x in 0..input_vec.len(){
        input_vec[x] = s_byte(input_vec[x]);
    }
    input_vec
}   

pub fn sub_bytes(mut state_array:Vec<Vec<u8>>)->Vec<Vec<u8>>{
    for r in 0..4{
        for c in 0..4{
            state_array[r][c] = s_byte(state_array[r][c]);
        }
    }
    state_array
}


pub fn shift_rows(state_array:Vec<Vec<u8>>)->Vec<Vec<u8>>{
    let mut temp = vec![vec![0u8;4];4];
    for r in 0..4{
        for c in 0..4{
            temp[r][c] = state_array[r][(c+r).rem_euclid(4)];
        }
    }
    temp
}

pub fn add_round_key(mut state_array:Vec<Vec<u8>>, keys:Vec<Vec<u8>>)->Vec<Vec<u8>>{
    for c in 0..4{
        let col = [state_array[0][c], state_array[1][c], state_array[2][c], state_array[3][c]];
        let vals = xor_vec(&col.to_vec(), &keys[c].clone());
        for x in 0..4{
            state_array[x][c] = vals[x];
        }
        let col = [state_array[0][c], state_array[1][c], state_array[2][c], state_array[3][c]];
    }
    state_array
}

pub fn key_expansion(input_key:&Vec<u8>)->Vec<Vec<u8>>{
    
    let mut i = 0;
    let mut ret:Vec<Vec<u8>> = vec![vec![0u8;4];60];
    while i <NK{
        ret[i] = input_key[i*4..i*4+4].to_vec();
        i+=1;
    }
    i = NK;
    while i< NB * (NR+1){
        let mut temp = ret[i-1].to_vec();
        if i.rem_euclid(NK) == 0{
            temp = xor_vec(
                    &vec_sub_bytes(left_shift_bytes(temp, 1)), &calc_rcon(i/NK).to_vec());
        }
        else if NK > 6 && i.rem_euclid(NK) == 4{
            temp = vec_sub_bytes(temp);
        }
        ret[i] = xor_vec(&ret[i-NK].clone(), &temp);
        i+=1;
    }
    ret

}

pub fn mix_columns(mut state_array:Vec<Vec<u8>>)->Vec<Vec<u8>>{
    /*
        mix columns matrix:
        [02,03,01,01]
        [01,02,03,01]
        [01,01,02,03]
        [03,01,01,02]
        s'[0,c] = (02*s[0,c]) XOR (03*s[1,c]) XOR s[2,c] XOR s[3,c]
        s'[1,c] = s[0,c] XOR (02*s[1,c]) XOR (03*s[2,c]) XOR s[3,c]
        s'[2,c] = s[0,c] XOR s[1,c] XOR (02*s[2,c]) XOR (03*s[3,c])
        s'[3,c] = (03*s[0,c]) XOR s[1,c] XOR s[2,c] XOR (02*s[3,c])
     */
    for c in 0..4{
        let col = [state_array[0][c],state_array[1][c],state_array[2][c],state_array[3][c]];
        state_array[0][c] = calc_mix_col_val(col.clone(), 0).unwrap();
        state_array[1][c] = calc_mix_col_val(col.clone(), 1).unwrap();
        state_array[2][c] = calc_mix_col_val(col.clone(), 2).unwrap();
        state_array[3][c] = calc_mix_col_val(col.clone(), 3).unwrap();
    }
    state_array
}


pub fn encrypt(mut input_vec:&Vec<u8>, input_key:&Vec<u8>)->Vec<u8>{
    let keys = key_expansion(&input_key);
    let mut state_array = convert_vec_to_state_array(&input_vec);
    state_array = add_round_key(state_array, keys[0..4].to_vec());
    for round in 1..NR{
        state_array = sub_bytes(state_array);
        state_array = shift_rows(state_array);
        state_array = mix_columns(state_array);
        state_array = add_round_key(state_array, keys[round*4..round*4+4].to_vec());
    }
    state_array = sub_bytes(state_array);
    state_array = shift_rows(state_array);
    state_array = add_round_key(state_array, keys[NR*NB..(NR+1)*NB].to_vec());
    convert_state_array_to_vec(state_array)
}


/*
    inverse cipher functions below
        decrypt mode:
            inverse sub bytes
            inverse shift rows
            inverse mix columns
*/

pub fn inv_s_byte(byte:u8)->u8{
    INV_S_BOX[byte as usize]
}

pub fn inverse_sub_bytes(mut state_array:Vec<Vec<u8>>)->Vec<Vec<u8>>{
    for r in 0..4{
        state_array[r][0] = inv_s_byte(state_array[r][0]);
        state_array[r][1] = inv_s_byte(state_array[r][1]);
        state_array[r][2] = inv_s_byte(state_array[r][2]);
        state_array[r][3] = inv_s_byte(state_array[r][3]);
    }
    state_array
}

pub fn inverse_shift_rows(state_array:Vec<Vec<u8>>)->Vec<Vec<u8>>{
    let mut temp = vec![vec![0u8;4];4];
    for r in 0..4{
        for c in 0..4{
            temp[r][c] = state_array[r][(c as i8 -r as i8).rem_euclid(4) as usize];
        }
    
    }
    temp
}

pub fn inverse_mix_columns(mut state_array:Vec<Vec<u8>>)->Vec<Vec<u8>>{
    for c in 0..4{
        let col = [state_array[0][c],state_array[1][c],state_array[2][c],state_array[3][c]];
        state_array[0][c] = inv_calc_mix_col_val(col.clone(), 0).unwrap();
        state_array[1][c] = inv_calc_mix_col_val(col.clone(), 1).unwrap();
        state_array[2][c] = inv_calc_mix_col_val(col.clone(), 2).unwrap();
        state_array[3][c] = inv_calc_mix_col_val(col.clone(), 3).unwrap();
    }
    
    state_array
}

pub fn decrypt(  input_vec:&Vec<u8>,input_key:&Vec<u8>)->Vec<u8>{
    let mut state_array = convert_vec_to_state_array(input_vec);
    let keys = key_expansion(input_key);
    state_array = add_round_key(state_array, keys[NR*NB..(NR+1)*NB].to_vec());
    let mut round = 13;
    while round > 0{
        state_array = inverse_shift_rows(state_array);
        state_array = inverse_sub_bytes(state_array);
        state_array = add_round_key(state_array, keys[round*NB..(round+1)*NB].to_vec());
        state_array = inverse_mix_columns(state_array);

        round-=1;
    }
    state_array = inverse_shift_rows(state_array);
    state_array = inverse_sub_bytes(state_array);
    state_array = add_round_key(state_array, keys[0..NB].to_vec());
    convert_state_array_to_vec(state_array)
}



