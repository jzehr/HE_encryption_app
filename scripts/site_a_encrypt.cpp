#include <chrono> 
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <iostream>
#include <list>
#include <vector>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#define poly_mod 8192


#include "/usr/local/Cellar/seal/3.4.5/include/SEAL-3.4/seal/seal.h"


using namespace std;
using namespace seal;



vector<uint64_t> one_hot(string seq) {

    vector<uint64_t> one_hot_encoded;

    std::map<char, vector<uint64_t>> one_hot_map;

    one_hot_map['A'] = vector<uint64_t>{0, 0, 0, 0, 1};
    one_hot_map['G'] = vector<uint64_t>{0, 0, 0, 1, 0};
    one_hot_map['C'] = vector<uint64_t>{0, 0, 1, 0, 0};
    one_hot_map['T'] = vector<uint64_t>{0, 1, 0, 0, 0};
    one_hot_map['-'] = vector<uint64_t>{1000, 0, 0, 0, 0};

    if (!seq.empty()) {

        for (auto n : seq) {
            std::copy(one_hot_map[n].begin(), one_hot_map[n].end(),
                      std::back_inserter(one_hot_encoded));
        }

        return one_hot_encoded;
    }

    return {};
}

int main(int argc, char*argv[])

{
    cout << endl;
    char *data_file = NULL;
    opterr = 0;
    
    int c;

    while ((c = getopt (argc, argv, "i:")) != -1)
    switch (c)
      {
      case 'i':
        data_file = optarg ;
        break;
      /*
      case 'c':
        cvalue = optarg;
        break;
      */  
      case '?':
        if (optopt == 'i')
          fprintf (stderr, "Option -%c Input Fasta File.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
         return 1;
       default:
         abort ();
      }

    cout << "Generating Encryption Parameters" << endl;
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(poly_mod);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_mod));
    parms.set_plain_modulus(PlainModulus::Batching(poly_mod, 20));
   
    // save the parms here, write to a file to then be loaded in another script //    
    ofstream parm_file;
    parm_file.open("data/A/parameters/parms_A.txt");
    parms.EncryptionParameters::save(parm_file);
   
    /*
    We create the SEALContext as usual and print the parameters.
    */
    auto context = SEALContext::Create(parms);

    // new qualifiers ~~ batching will throw error if it doesnt work //
    auto qualifiers = context->first_context_data()->qualifiers();

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    
    // need for later 
    auto gal_keys = keygen.galois_keys();
    auto relin_keys16 = keygen.relin_keys();
 
    
    ofstream gk_file;
    gk_file.open("data/A/keys/gk_A.txt");
    gal_keys.save(gk_file);

    ofstream rk_file;
    rk_file.open("data/A/keys/rk_A.txt");
    relin_keys16.save(rk_file);   
    
    ofstream pk_file;
    pk_file.open("data/A/keys/pk_A.txt");
    public_key.save(pk_file);

    ofstream sk_file;
    sk_file.open("data/A/sk_A.txt");
    secret_key.save(sk_file);
   
    cout << endl;
    cout << "Writing Public Key to File for Site B" << endl;
    
    /*
    We also set up an Encryptor here.
    */
    Encryptor encryptor(context, public_key);

    /*
    Batching is done through an instance of the BatchEncoder class so need to
    construct one.
    */
    BatchEncoder batch_encoder(context);

    /*
    The total number of batching `slots' is poly_modulus_degree. The matrices
    we encrypt are of size 2-by-(slot_count / 2).
    */
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    //cout << "Plaintext matrix row size: " << row_size << endl;

    /*
    Remeber each vector has to be of type uint64_t
    */
    
    // Read FASTA file
    ifstream hxb2;
    cout << endl;
    cout << "Reading the Input Fasta File: " << data_file << endl;
    
    hxb2.open(data_file);
    string header;
    string sequence;
    string line;
    vector<pair<string, string>> sequences;

    while (getline(hxb2, line)) {
        if (line.rfind(">", 0) == 0) {
            if (!sequence.empty()) {
                sequences.push_back(make_pair(header, sequence));
            }

            header = line;
            sequence.clear();
        } else {
            sequence += line;
        }
    }

    if (!sequence.empty()) {
        sequences.push_back(make_pair(header, sequence));
    }

    hxb2.close();

    cout << endl;
    //cout << "One Hot Encoding sequences from Site A" << endl;

    vector<vector<uint64_t>> siteA;

    for (auto const& i : sequences) {
        auto sequence = one_hot(i.second);
        siteA.push_back(sequence);
    }
    
    // write a file for the lenth of siteA 
    // this will be read in to compare the two sites
    ofstream number_of_seqs("data/A/encrypted/Site_A_number_seqs.txt");
    number_of_seqs << siteA.size();
    number_of_seqs.close();

    cout << "Encrypting Data Locally" << endl;
    for (int i = 0; i < siteA.size(); i++) {

        auto siteA_vector = siteA[i];
        auto siteA_size = siteA_vector.size();

        Plaintext plain_matrix;
        batch_encoder.encode(siteA_vector, plain_matrix);

        // plaintext (input 1) becomes the `encrypted_matrix` 
        Ciphertext encrypted_matrix;
        encryptor.encrypt(plain_matrix, encrypted_matrix);
        
        // saving the ciphertext here //
        string s = to_string(i);
      
        ofstream myfile;
        myfile.open("data/A/encrypted/encrypted_A_" + s + ".txt");
        encrypted_matrix.save(myfile);
        
    }
    cout << endl;
    cout << "Data is Homomorphically Encrypted and Ready to be Sent to the Cloud" << endl;
    cout << endl;
}
