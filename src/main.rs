use crate::{aes::cipher, gcm::{galois_multiplication_2_128, gcm_ad, gcm_ae, incr32}, helper::{decode_hex_string, encode_hex_string, xor_vec}};
mod aes;
mod constants;
mod helper;
mod gcm;

fn main(){
    let key: Vec<u8> = decode_hex_string("CF063A34D4A9a76c2c86787d3f96db71");
    let iv = decode_hex_string("113b9785971864c83b01c787");
    let ct = decode_hex_string("a8fe5adbfa");
    let aad = decode_hex_string("");
    let tag = decode_hex_string("e04980e9e4c3f200f0c52010d162f9d2");
    // let (iv, ct, tag) = gcm_ae(Some(key), Some(iv), "hello".to_string().as_bytes().to_vec(), aad, 128);
    // let orig_calc = gcm_ad(key, iv, ct, tag.to_vec(), aad).expect("unable to authenticate the cipher text");
    println!("{:?}",String::from_utf8(gcm_ad(key, iv, ct, tag, aad).expect("unable to authenticate tag")).unwrap());
    
    // println!("ct:{ct:02x?} \n tag:{tag:02x?}");
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
