use std::iter::zip;
use rand::{rngs::OsRng, TryRngCore};
use crate::constants::*;

pub fn make_key()->Vec<u8>{
    let  mut key = vec![0u8; 32];
    OsRng.try_fill_bytes( &mut key).expect("something went wrong filling in bytes");
    key.to_vec()
}

pub fn make_iv(len:usize)->Vec<u8>{
    let mut iv = vec![0u8;len];
    OsRng.try_fill_bytes( &mut iv).expect("something went wrong filling in bytes");
    return iv
}

pub fn decode_hex_string(s: &str) -> Vec<u8> {
    let mut ret:Vec<u8> = vec![];
    let s:String = s.replace(" ", "").to_string();
    if s.len() % 2 != 0{
        return ret;
    }
    for x in (0..s.len()).step_by(2){
        ret.push(u8::from_str_radix(&s[x..x+2], 16).unwrap());
    }
    ret
}

//used to display a state array as a long string of characters, NIST publication does it this way
//this is to make it easier for us to follow along with them and test the code as we go
pub fn encode_hex_string(input:&Vec<u8>)->String{
    let mut string = "".to_string();
    for c in 0..input.len(){
        string += &format!("{:02x?}", input[c]);
    }
    string
}   

pub fn calc_mix_col_val(col:[u8;4], matrix_col_index:usize)->Option<u8>{
    if matrix_col_index >3{
        println!("matrix column index given to calc mix columns was incorrect, must be between 0 and 3");
        return None;
    }
    let mix_col_multipliers = &MIX_COL_MATRIX[matrix_col_index*4..matrix_col_index*4+4];
    let mut ret = 0u8;
    for x in 0..4{
        if mix_col_multipliers[x] == 1{
            ret ^= col[x];
        }
        if mix_col_multipliers[x] == 2{
            ret ^= G_MUL_2[col[x] as usize]
        }
        if mix_col_multipliers[x] == 3{
            ret ^= G_MUL_3[col[x] as usize]
        }
    }
    Some(ret)
}

pub fn inv_calc_mix_col_val(col:[u8;4], matrix_col_index:usize)->Option<u8>{
    if matrix_col_index >3{
        println!("matrix column given to inv calc mix columns was incorrect, must be between 0 and 3");
        return None;
    }
    let mut ret= 0u8;
    let mix_col_multipliers = &INV_MIX_COL_MATRIX[matrix_col_index*4..matrix_col_index*4+4];
    for x in 0..4{
        if mix_col_multipliers[x] == 14{
            ret ^= G_MUL_14_TABLE[col[x] as usize];
        }if mix_col_multipliers[x] == 13{
            ret ^= G_MUL_13_TABLE[col[x] as usize];
        }if mix_col_multipliers[x] == 11{
            ret ^= G_MUL_11_TABLE[col[x] as usize];
        }if mix_col_multipliers[x] == 9{
            ret ^= G_MUL_9_TABLE[col[x] as usize];
        }
    }

    Some(ret)
}


#[allow(unused)]
pub fn xor_vec(left:&Vec<u8>, right:&Vec<u8>)->Vec<u8>{
    let mut left = left.clone();
    let mut right = right.clone();
    if left.len() < right.len(){
        //push the extra bits as they are 
        for _ in 0..right.len()-left.len(){
            left.push(0);
        }
    }if right.len() < left.len(){
        let diff_len = left.len() - right.len();
        // time complexity 0(m) , m = difference in lengths
        let mut front = (0..diff_len).map(|_|0).collect::<Vec<u8>>();
        // below 3 time complexity = O(n) + O(n+m)
        left.reverse();
        left.append(&mut front);
        left.reverse();
    }
    let mut right = right.clone();
    let mut left = left.clone();
    return zip(left, right).map(|x| return x.0^x.1).collect::<Vec<u8>>();
}


pub fn left_shift_bytes(input_vec:Vec<u8>, times:usize)->Vec<u8>{
    if times >= input_vec.len(){
        println!("didn't shift anything because \'times\' was larger than the length of the input vector");
        return input_vec;
    }
    let right_seg = input_vec[times..input_vec.len()].to_vec();
    let mut ret = right_seg;
    ret.append(&mut input_vec[0..times].to_vec());
    ret
}

pub fn convert_vec_to_state_array(input_vec:&Vec<u8>)->Vec<Vec<u8>>{
    if input_vec.len() != 16{
        println!("soft panick input vec was not 16 length, {:?}", input_vec.len());
        return vec![];
    }
    let mut state_array:Vec<Vec<u8>> = vec![vec![0u8;4];4];
    for c in 0..4{
        for r in 0..4{
            state_array[r][c] = input_vec[r+4*c];
        }
    }
    state_array

}

pub fn convert_state_array_to_vec(state_array:Vec<Vec<u8>>)->Vec<u8>{
    let mut ret: Vec<u8> = vec![0u8;16];
    for r in 0..4{
        for c in 0..4{
            ret[r+4*c] = state_array[r][c];
        }
    }
    ret
}



/*below you will find functions used in GCM functions */
///as you can probably tell by the return type, this function converts a vector of length 16 (16 bytes = 128 bits) into slices of 16 bytes
pub fn convert_vec_to_slice(input:Vec<u8>)->[u8;16]{
    if input.len() !=16{
        println!("be careful, this function is used to convert vectors of length 16");
        return [0u8;16];
    }
    let mut ret = [0u8;16];
    for x in 0..ret.len(){
        ret[x] = input[x];
    }
    ret
}

#[allow(unused)]
pub fn galois_multiplication(left:u8, right:u8)->u8{
    let mut left = left.clone() as u16;
    let mut right = right.clone() as u16;
    let mut ret = 0u16;
    while left != 0 && right != 0{
        if right&1 == 1{
            ret ^=left;
        }
        if (left & 0x80) == 1{
            left = (left<<1)^0x11b;
        }else{
            left <<=1;
        }
        right >>=1;
    }
    ret as u8
}

pub fn galois_multiplication_u128(left:Vec<u8>, right:Vec<u8>)->u128{
    let r_const:u8 = 0xe1;
    let mut z = [0u8;3];
    let mut v = [0u8;3];
    let mask: u8 = 0x80;
    let rnd = false;
    for i in 0..3{
        z[i]=0x00;
        z[i] *= right[i];
    }
    let mut l = 0;
    let mut val1 = left[l];
    let mut r = 0;
    let mut val2 = right[r];

    for i in 0..24{
        if val1 & 1 ==1{
            for j in 0..3{
                z[j] ^=v[j];
            }
        }
        if v[2] & 0x01 == 0{
            for j in 0..3{
                if j!=0{
                    if v[2-j] & 1 == 1{
                        v[3-j] |= 0x80;
                    }
                }
                v[2-j] >>=1;
            } 
        }else{
            for j in 0..3{
                if j !=0{
                    if v[2-j] & 0x01 == 1{
                        v[3-j] |=0x80;
                    }
                }
                v[2-j] >>=1;
            }
            v[0] ^=r_const;
        }   
    }
    if mask & 1 ==1 {
        l +=1;
    }

    0u128
}

///zero pads a string to be a multiple of 128 bits (16 bytes)
pub fn pad_string(mut input:String)->String{
    loop{
        if input.len() % 16 == 0{
            break;
        }
        input.push(0 as char);
    }
    input
}


//same function as the pad string but for a vector as it is sometimes easier to manipulate a vector
pub fn pad_vec(mut input:Vec<u8>)->Vec<u8>{
    loop {
        if input.len() % 16 == 0{
            break;
        }
        input.push(0);
    }
    input
}

///return the s right-most bits of x as described in the aes 
pub fn lsb(x:u128, s:usize)->u128{
    return u128::from_str_radix(&(0..s).map(|_| "1").collect::<String>(),2).unwrap() & x;
}

/// faster lsb function to calculate lsb1(x) which does not do as many operation
pub fn lsb1(x:u128)->u128{
    return x & 1;
}


///find the s left-most bits of x
/*
    x = 0b_0111_1000 s = 5
    then we get 0b_0111_1 as the return value
    we can notice that a simple right shift by 5 should suffice

*/
pub fn msb(x:u128,s:usize)->u128{
    return x >> (128-s)
}
///gets the bit at the sth index of the u128 value
pub fn get_bit(x:u128, s:usize)->bool{
    /*
        x = 0b_0111_1000 s = 5
        then we want 1 as the return value
    */
    (1<<s) & x ==1
}