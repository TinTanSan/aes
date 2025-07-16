use crate::{gcm::{galois_multiplication_2_128}, helper::{decode_hex_string}};
mod aes;
mod constants;
mod helper;
mod gcm;
fn test_gf_mul_128(x:Vec<u8>, y:Vec<u8>)->Vec<u8>{
    const R:u128 =  0xe1u128 << 120;
    let mut result = 0u128;
    let a = u128::from_be_bytes(x.as_slice().try_into().unwrap());
    let mut b = u128::from_be_bytes(y.as_slice().try_into().unwrap());
    println!("NOR: x: {a} | y: {b}");
    println!("HEX: x:{a:x} | y:{b:x}");
    println!("BIN: x:{a:b} \n y: {b:b}");
    for i in 0..128{
        println!("iteration: #{i}");
        println!("cur: {result:x}");
        // we do it this way around as to preserve the little-endian-ness required of bit strings in 
        if ((a >> (127-i)) & 1) == 1{
            println!("res XORred");
            result ^= b;
        }
        // println!(" x_b:{:0128b}",(a >> i));
        // println!(" res:{result:0128b}");
        // println!(" y_b:{b:0128b}");
        let is_reduction_required = (b & 1) == 1;
        b >>=1;
        if is_reduction_required{
            println!("B reduced to {b:x}");
            b ^=R;
        }
        
        
    }
    
    return result.to_be_bytes().to_vec();
}

fn test_ghash(string_x:&[u8], block_h:&[u8;16])->[u8;16]{
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
        y_0 = galois_multiplication_2_128(u128::from_be_bytes(y_0), u128::from_be_bytes(*block_h)).to_be_bytes();
        println!("multiplied: {:02x?}", y_0)
    }
    y_0
}


fn main(){
    let h = decode_hex_string("b83b533708bf535d0aa6e52980d53b78");
    // let input = decode_hex_string("6f288b846e5fed9a18376829c86a6a16");
    // let result = test_ghash(&input.as_slice(), h.as_slice().try_into().unwrap());
    
    let test_mul = decode_hex_string("6f288b846e5fed9a18376829c86a6a16");
    let result = test_gf_mul_128(test_mul, h);
    println!("{:02x?}", &result);
    
}


// this module should soon have its own file
#[cfg(test)]
mod tests{
    use std::io::Read;
    use crate::aes::{cipher, inv_cipher};
    use crate::{helper::{decode_hex_string, encode_hex_string}};
    
    
    #[test]
    fn ecb_mode_tests(){
        
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
