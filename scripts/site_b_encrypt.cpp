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
#define plain_mod_batch 114689


#include "../SEAL/native/src/seal/seal.h"

using namespace std;
using namespace seal;

/*
This scheme will operate on INTS
*/

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

int main(int argc, char **argv)

{
    cout << endl;
    char *data_file = NULL;
    char *enc_parms = NULL;
    char *pubkey = NULL;
    opterr = 0;

    int c;

    while ((c = getopt (argc, argv, "i:e:k:")) != EOF)
        switch (c)
          {
          case 'i':
            data_file = optarg;
            break;
          case 'e':
            enc_parms = optarg;
            break;
          case 'k':
            pubkey = optarg;
            break;
          case '?':
            if (optopt == 'c')
              fprintf (stderr, "Option -%c requires an argument.\n", optopt);
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
    cout << "Using Encryption Parameters and Public Key from Site A" << endl;
    cout << endl;
    // Set up encryption parameters
    // read in site_A parms //
    ifstream infile_parms_A;
    infile_parms_A.open(enc_parms);
    EncryptionParameters parms(scheme_type::BFV);
    parms.load(infile_parms_A);

    /*
    We create the SEALContext as usual and print the parameters.
    */
    //auto context = SEALContext::Create(parms);
    auto context = SEALContext::Create(parms);

    auto qualifiers = context->first_context_data()->qualifiers();

    ifstream pk_A;
    pk_A.open(pubkey);

    PublicKey pk;
    pk.load(context, pk_A);
    
    /*
    We also set up an Encryptor here.
    */
    Encryptor encryptor(context, pk);

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
    ifstream ref;
    //ref.open("../rsrc/Site_2_aligned.fa");
    cout << "Reading in the Input Fasta File: " << data_file << endl;
    cout << endl;

    ref.open(data_file);
    string header;
    string sequence;
    string line;
    vector<pair<string, string>> sequences2;

    while (getline(ref, line)) {
        // cout << "line in the file: " << line << endl;
        if (line.rfind(">", 0) == 0) {
            if (!sequence.empty()) {
                sequences2.push_back(make_pair(header, sequence));
            }

            header = line;
            sequence.clear();
        } else {
            sequence += line;
        }
    }

    if (!sequence.empty()) {
        sequences2.push_back(make_pair(header, sequence));
    }
    ref.close();

    //cout << endl << "One Hot Encoding sequences from Site B" << endl;

    vector<vector<uint64_t>> siteB;
    for (auto const& i : sequences2) {
        auto sequence = one_hot(i.second);
        siteB.push_back(sequence);
    }
    
    // write a file for the lenth of siteB
    // this will be read in to compare the two sites
    ofstream number_of_seqs("data/B/encrypted/Site_B_number_seqs.txt");
    number_of_seqs << siteB.size();
    number_of_seqs.close();
    
    cout << "Encrypting Data Locally" << endl;
    for (int i = 0; i < siteB.size(); i++) {

        auto siteB_vector = siteB[i];

        Plaintext plain_matrix;
        batch_encoder.encode(siteB_vector, plain_matrix);

        // plaintext (input 1) becomes the `encrypted_matrix` 
        Ciphertext encrypted_matrix;
        encryptor.encrypt(plain_matrix, encrypted_matrix);
        
        // saving the ciphertext here //
        string s = to_string(i);

        ofstream myfile;
        myfile.open("data/B/encrypted/encrypted_B_" + s + ".txt");
        encrypted_matrix.save(myfile);
    }
    cout << endl;
    cout << "Data is Homomorphically Encrypted and Ready to be sent to the Cloud" << endl;
    cout << endl;
}
