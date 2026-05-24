#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;
namespace fs = filesystem;

const uint8_t duality[] = { 0xAE, 0x53, 0xCC, 0xFF }; //extra "flag" to say "this file is encrypted"
const size_t key_len= 32; //32 byte key length
const size_t  IV_LEN = 16; //16 byte counter (to be encrypted and XOR'd with data)

uint8_t key[key_len]; //to hold 32 byte key
const fs::path key_FILE = "aes_tool.key"; //a file to hold the generated key on first program run 

void loadOrCreatekey() { //so that every program run doesnt generate a new key
    if (fs::exists(key_FILE)) { //if a key exist, use it
        ifstream f(key_FILE, ios::binary);
        f.read(reinterpret_cast<char*>(key), key_len);
        cout << "Loaded key from " << key_FILE << "\n";
    } else { //if a key doesn't exist, create one
        RAND_bytes(key,key_len);
        ofstream f(key_FILE, ios::binary);
        f.write(reinterpret_cast<const char*>(key),key_len);
        cout << "Generated new key and saved to " << key_FILE << "\n";
    }
}

vector<uint8_t> readFile(const fs::path& p) { //reads file in binary bc os changes textfiles which may corrupt encrypted files decryption
    ifstream f(p, ios::binary); //open file for read in binary
    return { istreambuf_iterator<char>(f), istreambuf_iterator<char>() }; //iterates over the file byte by byte
}

void writeFile(const fs::path& p, const vector<uint8_t>& data) { 
    ofstream f(p, ios::binary); //open file for write in binary (wipe out old data)
    f.write(reinterpret_cast<const char*>(data.data()), data.size()); 
    // data.data() = raw pointer to the vector's bytes
    // reinterpret_cast since fstream expects a char *
    // data.size() = how many bytes to write
    //called at the end of processFile() to overwrite the file's old data
}

vector<uint8_t> aesCTR(const vector<uint8_t>& data, const uint8_t* key, const uint8_t* iv) {
    vector<uint8_t> out(data.size() + 32); //create output buffer to temporarily store data (extra padded for safety and prevent buffer overflow)
    int olen = 0, flen = 0; //counters to keep track of processing (olen for the 16 byte chunk/process, flen for what's left after)

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); //start AES process
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv); //hand it the key and IV
    EVP_EncryptUpdate(ctx, out.data(), &olen, data.data(), (int)data.size()); //encrypt IV with key, then xor result with data
    EVP_EncryptFinal_ex(ctx, out.data() + olen, &flen); //remove whatever was not used from the extra padding
    EVP_CIPHER_CTX_free(ctx); //end process
    out.resize(olen + flen); //resize the buffer to be exactly as big as processed data
    return out; //return result (encrypted/decrypted)
}

void processFile(const fs::path& p) {
    vector<uint8_t> raw = readFile(p); //load file to memory
    bool encrypted = raw.size() >= 4 && equal(duality, duality + 4, raw.begin()); //check first 4 bytes
    //if they match duality then it's encrypted, decrypt it, if not then encrypt it

    if (encrypted) { //true means it has duality attached
        uint8_t iv[IV_LEN];
        copy(raw.begin() + 4, raw.begin() + 4 + IV_LEN, iv); //skip first 4 bytes, the following 16 are the IV
        vector<uint8_t> cipher(raw.begin() + 4 + IV_LEN, raw.end()); //the encrypted text is after the first 20 bytes of the file
        writeFile(p, aesCTR(cipher, key, iv)); //decrypt the cipher data using the key and the IV in the file
        cout << "Decrypted: " << p << "\n";
    } else { //plantext
        uint8_t iv[IV_LEN];
        RAND_bytes(iv, IV_LEN); //generate the random IV (counter starting offset)
        vector<uint8_t> cipher = aesCTR(raw, key, iv); //encrypt the raw binary data
        vector<uint8_t> out; //temp buffer
        out.insert(out.end(), duality, duality + 4); //insert the 4 duality bytes to flag it as encrypted
        out.insert(out.end(), iv, iv + IV_LEN); //insert the IV so it can be decrypted 
        out.insert(out.end(), cipher.begin(), cipher.end()); //insert ciphertext
        writeFile(p, out); //overwrite old data
        cout << "Encrypted: " << p << "\n";
    }
}

int main() {
    loadOrCreatekey(); //creates key on first program run, loads on all subsequent runs

    string inputPath;
    cout << "Path (file or directory): ";
    getline(cin, inputPath); //cin doesn't accept spaces, getline() will process full path with spaces if they exist

    fs::path target(inputPath); //covert the string to a filesystem path object for processing 
    if (!fs::exists(target)) { cerr << "Path not found.\n"; return 1; }

    //cool part!
    if (fs::is_directory(target)) { //if it's a directory
        for (auto& entry : fs::recursive_directory_iterator(target)) //iterate through it
            if (fs::is_regular_file(entry)) //if plaintext file, then send it to be encrypted/decrypted
                processFile(entry.path()); //(if it's anything else, it just ignores it)
    } else { //if it's a regular file, and not a directory
        processFile(target); //process directly
    }

    cout << "Done.\n";
    return 0;
}