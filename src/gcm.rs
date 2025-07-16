use std::{error::Error, fmt};

use crate::{aes::cipher as encrypt, helper::{encode_hex_string, make_iv, make_key, xor_vec}};

#[derive(Debug, Clone)]
struct AuthenticationError{
    details: String
}
#[allow(dead_code)]
impl AuthenticationError {
    fn new(msg: &str) -> AuthenticationError {
        AuthenticationError{details: msg.to_string()}
    }
}

impl fmt::Display for AuthenticationError{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to authenticate the tag")
    }
}

impl Error for AuthenticationError{
    fn description(&self) -> &str {
        &self.details
    }
}


fn msb(block:&u128, bits_to_get:usize)->u128{
    if bits_to_get >= 128{
        return block.clone();
    }
    block >> (128-bits_to_get)
}



#[allow(dead_code)]
fn lsb(block:&u128, bits_to_get:usize)->u128{
    if bits_to_get >=128{
        return  block.clone();
    }
    block.rem_euclid((2 as u128).pow(bits_to_get as u32))
}

// the irreducible polynomial for galois field multiplication
const R:u128 = 0xe1 <<120;
pub fn gm_2_128_slice(x:&[u8;16], y:&[u8;16])->[u8;16]{
    let mut result = [0u8; 16];
    let mut a = *x;
    let mut b = *y;
    let r_bytes =  R.to_be_bytes();
    for  _ in 0..128{
        if (b[15] &1) == 1{
            for i in 0..16{
                result[i] ^=a[i];
            }
        }
        let mut carry = 0;
        for i in (0..16).rev(){
            let new_carry = (a[i] & r_bytes[i]) != 0;
            a[i] = (a[i] << 1) | carry;
            carry = new_carry as u8;
        }
        if carry == 1 {
            a[15] ^= 0x87;
        }
        // Shift b right by 1 bit
        let mut borrow = 0;
        for i in 0..16 {
            let new_borrow = (b[i] & 1) != 0;
            b[i] = (b[i] >> 1) | (borrow << 7);
            borrow = new_borrow as u8;
        }
    }
    
    
    result
}


/// galois multiplication of two elements in the finite field GF(2^128) given 2 128 bit numbers x and y
pub fn galois_multiplication_2_128(x:u128,y:u128)->u128{
    const R:u128 =  0x87u128;
    let mut result = 0u128;
    let mut a = x;
    let mut b = y;
    for _ in 0..128{
        if b &1 == 1{
            result ^= a;
        }
        let needs_reduction = (a & (1u128 << 127)) != 0;
        a <<=1;
        if needs_reduction{
            a ^= R;
        }
        b >>= 1;
    }
    
    result
}


pub fn ghash(h_block:u128, x:Vec<u8>)->u128{
    let mut y0 = 0u128;
    for chunk in x.chunks_exact(16){
        let chunk_padded = if chunk.len() < 16 {
            let mut padded = [0u8; 16];
            padded[..chunk.len()].copy_from_slice(chunk);
            padded
        } else {
            chunk.try_into().unwrap()
        };
        let x_i_u128 = u128::from_be_bytes(chunk_padded.try_into().unwrap());
        println!("ghash chunck xor {:02x?} | h_block: {h_block:02x?}", y0 ^x_i_u128);
        let y1 = galois_multiplication_2_128(y0^x_i_u128,h_block);
        y0=y1;
    }
    return y0;
}

fn incr32( block:&Vec<u8>)->Vec<u8>{
    let mut left_alone_bits = block[4..block.len()].to_vec();
    let u32_mid = u32::from_be_bytes(block[0..4].try_into().unwrap());
    let mut incremented_bits:u64 = u64::from(u32_mid);
    incremented_bits = (incremented_bits + 1).rem_euclid((2 as u64).pow(32));
    let mut temp = incremented_bits.to_be_bytes().to_vec();
    
    temp = temp.split_off(4);
    temp.append(&mut left_alone_bits);
    return temp
}


fn gctr(icb:&Vec<u8>, x: &Vec<u8>, key:&Vec<u8>)->Vec<u8>{
    if x.len() == 0{
        return vec![];
    }
    let mut cur_counter: Vec<u8> = icb.clone();
    let full_blocks = x.len() / 16;
    let mut y: Vec<u8> = vec![];
    for i in 0..full_blocks{
        let cur_block = x[i*16.. (i+1)*16].to_vec();
        println!("cur block is: {cur_block:02X?}");
        cur_counter = incr32(&cur_counter);
        let enc_block = encrypt(&cur_counter, &key).expect("invalid key length");
        y.append(&mut xor_vec(&enc_block, &cur_block));
    }
    let remaining_len = x.len().rem_euclid(16);
    if remaining_len > 0{
        let partial_block = x[full_blocks*16..].to_vec();
        cur_counter = incr32(&cur_counter);
        let enc_block = encrypt(&cur_counter, &key).expect("invalid key length");
        for byte_idx in 0..remaining_len {
            y.push(partial_block[byte_idx] ^ enc_block[byte_idx]);
        }
    }
    return y
}



pub fn gcm_ae(input_key:Option<Vec<u8>>,input_iv:Option<Vec<u8>>,plain_text:Vec<u8>, aad:Vec<u8>)->(Vec<u8>,Vec<u8>,u128){
    let key = input_key.unwrap_or(make_key());
    let iv = input_iv.unwrap_or(make_iv(96));
    let h: Vec<u8> = encrypt(&vec![0u8;16], &key).expect("unable to encrypt initial hash block");
    println!("h: {:02X?}",&h);
    let mut j_0 = vec![0u8;0];
    let iv_len_bits = (iv.len() * 8) as f32;
    if iv_len_bits as u32 == 96{
        j_0.append(&mut iv.clone());
        j_0.append(&mut vec![0u8;3]);
        j_0.push(1);
    }else{
        let _s = 128;
        
        let s_bits = (128.0 * (iv_len_bits / 128.0).ceil() - iv_len_bits) as usize;
        let mut padded_iv: Vec<u8> = iv.clone();
        padded_iv.append(&mut vec![0u8;s_bits]);
        padded_iv.append(&mut (iv.len()).to_be_bytes().to_vec());
        println!("padded_iv:{padded_iv:02X?} | iv len: {iv_len_bits:02X?}");
        j_0 = ghash(u128::from_be_bytes(h.as_slice().try_into().unwrap()), padded_iv).to_be_bytes().to_vec();
    }
    println!("J_0:{:02X?}",&j_0);
    // c is the ciphertext
    let cipher_text = gctr(&j_0, &plain_text, &key);
    println!("ct: {cipher_text:02X?}");
    let len_c = cipher_text.len()*8;
    let len_a = aad.len()*8;
    let u = 128 * ((len_c + 127) / 128) - len_c;
    let v = 128 * ((len_a + 127) / 128) - len_a;
    println!("u:{u:?} v:{v:?}");
    let mut c_plus_aad = aad.clone();
    c_plus_aad.append(&mut vec![0u8;v]);
    c_plus_aad.append(&mut cipher_text.clone());
    c_plus_aad.append(&mut vec![0u8;u]);
    c_plus_aad.append(&mut (aad.len() as u64).to_be_bytes().to_vec());
    c_plus_aad.append(&mut (cipher_text.len() as u64).to_be_bytes().to_vec());
    println!("hex str: {}", encode_hex_string(&c_plus_aad));
    let s = ghash(u128::from_be_bytes(h.as_slice().try_into().unwrap()), c_plus_aad).to_be_bytes().to_vec();
    println!("running gctr on s, {}", encode_hex_string(&s));
    let tag = msb(&u128::from_be_bytes(gctr(&j_0,&s , &key).as_slice().try_into().unwrap()), 128 as usize);
    return (iv,cipher_text, tag);

}


pub fn gcm_ad(key:Vec<u8>, iv:Vec<u8>, cipher_text:Vec<u8>, tag:u128, aad:Vec<u8> )->Result<Vec<u8>, AuthenticationError>{
    let mut iv_copy = iv.clone();
    let mut c = cipher_text.clone();
    
    
    let h = encrypt(&vec![0u8;16], &key).expect("unable to encrypt initial hash block") ;
    let mut j_0 = vec![0u8;0];
    
    if iv.len() == 12{
        j_0.append(&mut iv_copy);
        j_0.append(&mut vec![0u8;3]);
        j_0.push(1);
    }else{
        let _s = 128;
        let iv_len_bits = (iv.len() * 8) as f32;
        let s_bits = (128.0 * (iv_len_bits / 128.0).ceil() - iv_len_bits) as usize;
        let mut padded_iv: Vec<u8> = iv.clone();
        padded_iv.append(&mut vec![0u8;s_bits]);
        padded_iv.append(&mut (iv.len()).to_be_bytes().to_vec());
        j_0 = ghash(u128::from_be_bytes(h.as_slice().try_into().unwrap()), padded_iv).to_be_bytes().to_vec();
    }
    let p = gctr(&j_0, &cipher_text, &key);
    let u = ((cipher_text.len()*8) % 128)/16;
    let v = ((aad.len() * 8) % 128)/16;
    let mut c_plus_aad = aad.clone();
    c_plus_aad.append(&mut vec![0u8;u]);
    c_plus_aad.append(&mut c);
    c_plus_aad.append(&mut vec![0u8;v]);

    let s = ghash(u128::from_be_bytes(h.as_slice().try_into().unwrap()), c_plus_aad);
    let b = &s.to_be_bytes().to_vec();
    let t_dash = msb(&u128::from_be_bytes(gctr(&j_0,b , &key).as_slice().try_into().unwrap()), 128 as usize);
    if t_dash == tag{
        return Ok(p);
    }
    return  Err(AuthenticationError::new("FAILED to authenticate the tag"));
}
