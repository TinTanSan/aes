use crate::{aes::cipher, gcm::{galois_multiplication_2_128, gcm_ae, incr32}, helper::{decode_hex_string, encode_hex_string, xor_vec}};
mod aes;
mod constants;
mod helper;
mod gcm;




fn main(){
    let key: Vec<u8> = decode_hex_string("11ca26a3e3490f050372301b0d394c8b");
    let iv: Vec<u8> = decode_hex_string("36");
    let pt: Vec<u8> = decode_hex_string("6331cd4badf459182ceb3ee120");
    let aad: Vec<u8> = decode_hex_string("a082139c1c90b6de9be9ef2391d7e3a1ff3b66080d15e342ed54c4ccc12f21e3b549b0c38d6e27e7f3cd6d3343681f04761b52a0b39758c498007eb65522a95f9c675311298631592ba8cc11b6b9074a18d5183e3e8306e63d09");
    
    let result = gcm_ae(Some(key), Some(iv), pt, aad);
    println!("iv: {:02x?} | ct: {:02x?} | tag: {:02x?} ", result.0, result.1, result.2);
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
