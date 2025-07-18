use std::{error::Error, fmt, iter::zip};

use crate::{aes::cipher as encrypt, helper::{make_iv, make_key}};

#[derive(Debug, Clone)]
pub struct AuthenticationError{
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

/// galois multiplication of two elements in the finite field GF(2^128) given 2 128 bit numbers x and y
pub fn galois_multiplication_2_128(x:u128,y:u128)->u128{
    let mut result = 0u128;
    let a = x;
    let mut b = y;
    for i in 0..128{
        // we do it this way around as to preserve the little-endian-ness required of bit strings in 
        if ((a >> (127-i)) & 1) == 1{
            result ^= b;
        }
        let is_reduction_required = (b & 1) == 1;
        b >>=1;
        if is_reduction_required{
            b ^=R;
        }
        
        
    }
    
    return result
}


pub fn ghash(h_block:u128, string_x:Vec<u8>)->u128{
    let pad_len = if string_x.len() % 16 == 0 {
        0  // No padding needed if already multiple of 16
    } else {
        16 - (string_x.len() % 16)
    };

    let mut x = string_x.to_vec();

    x.extend(vec![0u8; pad_len]);

    let mut y_0: [u8; 16] = [0u8;16];
    for chunk in x.chunks_exact(16) {
        let chunk_array: &[u8; 16] = chunk.try_into().unwrap();
        for j in 0..16 {
            y_0[j] ^= chunk_array[j];
        }
        y_0 = galois_multiplication_2_128(u128::from_be_bytes(y_0), h_block).to_be_bytes();
    }
    u128::from_be_bytes(y_0)
}

pub fn incr32(block:&Vec<u8>)->Vec<u8>{
    assert!(block.len()%16 ==0);
    let excess_len = block.len()-4;
    let mut lower_bits = u32::from_be_bytes(block[(excess_len)..].try_into().unwrap());
    lower_bits = (lower_bits + 1) % (0xffffffff);
    return [block[0..excess_len].to_vec(), lower_bits.to_be_bytes().to_vec()].concat();
}


pub fn gctr(icb:&Vec<u8>, x: &Vec<u8>, key:&Vec<u8>)->Vec<u8>{
    if x.len() == 0{
        println!("SOFT WARNING x was empty");
        return  vec![];
    }
    let n = ((x.len() as f32)/(16 as f32)).ceil() as usize;
    let blocks = x.chunks(16).collect::<Vec<&[u8]>>();
    let mut cb = vec![icb.clone()];
    for i in 1..n{
    
        cb.push(incr32(&cb[i-1]));
    }
    let mut y_blocks = vec![];
    for i in 0..n{
        
        y_blocks.append(&mut zip(blocks[i], encrypt(&cb[i], key).expect("unable to encrypt counter block, key length not correct")).map(|(a,b)| a^b).collect::<Vec<u8>>());
    }
    y_blocks
}



pub fn gcm_ae(input_key:Option<Vec<u8>>,input_iv:Option<Vec<u8>>,plain_text:Vec<u8>, aad:Vec<u8>, tag_len:usize)->(Vec<u8>,Vec<u8>,Vec<u8>){
    let key = input_key.unwrap_or(make_key());
    let iv = input_iv.unwrap_or(make_iv(96));
    let h: Vec<u8> = encrypt(&vec![0u8;16], &key).expect("unable to encrypt initial hash block");
    println!("h:{h:02x?}");
    let mut j_0 = iv.clone();
    let iv_len_bits = (iv.len() * 8) as u32;
    if iv_len_bits == 96{
        j_0.append(&mut vec![0u8,0u8,0u8,1u8]);
    }else{
        let s_bits = (128.0 * ((iv_len_bits as f32) / 128.0).ceil() - iv_len_bits as f32) as usize;
        let mut padded_iv: Vec<u8> = iv.clone();
        padded_iv.append(&mut vec![0u8;(s_bits + 64 )/8]);
        padded_iv.append(&mut (iv_len_bits as u64).to_be_bytes().to_vec());
        j_0 = ghash(u128::from_be_bytes(h.as_slice().try_into().unwrap()), padded_iv).to_be_bytes().to_vec();
    }
    println!("j_0:{j_0:02x?}");
    // c is the ciphertext
    let pt =  plain_text.clone();
    let cipher_text = gctr(&incr32(&j_0), &pt, &key);
    let len_c = cipher_text.len()*8;
    let len_a = aad.len()*8;
    let u = 128 * (len_c as f32 / 128.0).ceil() as usize - len_c;
    let v = 128 * (len_a as f32/ 128.0).ceil() as usize - len_a;
    let mut c_plus_aad = aad.clone();
    c_plus_aad.append(&mut vec![0u8;v/8]);
    c_plus_aad.append(&mut cipher_text.clone());
    c_plus_aad.append(&mut vec![0u8;u/8]);
    c_plus_aad.append(&mut (len_a as u64).to_be_bytes().to_vec());
    c_plus_aad.append(&mut (len_c as u64).to_be_bytes().to_vec());
    println!("c_plus_aad{c_plus_aad:02x?}");
    let s = ghash(u128::from_be_bytes(h.as_slice().try_into().unwrap()), c_plus_aad).to_be_bytes().to_vec();
    println!("s:{s:02x?}");
    let mut tag = msb(&u128::from_be_bytes(gctr(&j_0,&s , &key).as_slice().try_into().unwrap()), tag_len).to_be_bytes().to_vec();
    // basically we are given all the bits of a u128 number, it may be the case that we don't need all the bits (i.e. tag len < 128)
    // so here we try to get only what we need
    if tag_len < 128{
        tag = tag[tag.len()-tag_len/8..].to_vec();
    }
    
    return (iv,cipher_text, tag);

}


pub fn gcm_ad(key:Vec<u8>, iv:Vec<u8>, cipher_text:Vec<u8>, tag:Vec<u8>, aad:Vec<u8> )->Result<Vec<u8>, AuthenticationError>{
    let mut c = cipher_text.clone();
    let h = encrypt(&vec![0u8;16], &key).expect("unable to encrypt initial hash block") ;
    println!("h:{h:02x?}");
    let mut j_0 = iv.clone();
    let iv_len_bits = (iv.len() * 8) as u32;
    if iv_len_bits == 96{
        j_0.append(&mut vec![0u8,0u8,0u8,1u8]);
    }else{
        let s_bits = (128.0 * ((iv_len_bits as f32) / 128.0).ceil() - iv_len_bits as f32) as usize;
        let mut padded_iv: Vec<u8> = iv.clone();
        padded_iv.append(&mut vec![0u8;(s_bits + 64 )/8]);
        padded_iv.append(&mut (iv_len_bits as u64).to_be_bytes().to_vec());
        j_0 = ghash(u128::from_be_bytes(h.as_slice().try_into().unwrap()), padded_iv).to_be_bytes().to_vec();
    }
    let p = gctr(&incr32(&j_0), &cipher_text, &key);
    let len_c = cipher_text.len()*8;
    let len_a = aad.len()*8;
    let u = 128 * (len_c as f32 / 128.0).ceil() as usize - len_c;
    let v = 128 * (len_a as f32/ 128.0).ceil() as usize - len_a;
    let mut c_plus_aad = aad.clone();
    c_plus_aad.append(&mut vec![0u8;v/8]);
    c_plus_aad.append(&mut c);
    c_plus_aad.append(&mut vec![0u8;u/8]);
    c_plus_aad.append(&mut (len_a as u64).to_be_bytes().to_vec());
    c_plus_aad.append(&mut (len_c as u64).to_be_bytes().to_vec());
    let s = ghash(u128::from_be_bytes(h.as_slice().try_into().unwrap()), c_plus_aad).to_be_bytes().to_vec();
    let t_dash = msb(&u128::from_be_bytes(gctr(&j_0,&s , &key).as_slice().try_into().unwrap()), tag.len()*8).to_be_bytes();
    
    if t_dash[t_dash.len()-tag.len()..] == *tag.as_slice(){
        return Ok(p);
    }
    return  Err(AuthenticationError::new("FAILED to authenticate the tag"));
}
