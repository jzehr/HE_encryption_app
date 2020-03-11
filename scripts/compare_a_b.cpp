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


int main(int argc, char **argv)

{
    cout << endl;
    char *enc_parms = NULL;
    char *gal_key_file = NULL;
    char *reli_key_file = NULL;
    char *a_site_size = NULL;
    char *b_site_size = NULL;
    opterr = 0;

    int c;
    
    while ((c = getopt (argc, argv, "a:b:e:g:r:")) != EOF)
        switch (c)
        {
            case 'a':
                a_site_size = optarg;
                break;
            case 'b':
                b_site_size = optarg;
                break;
            case 'e':
                enc_parms = optarg;
                break;
            case 'g':
                gal_key_file = optarg;
                break;
            case 'r':
                reli_key_file = optarg;
                break;
            case '?':
                if (optopt == 'c')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                return 1;
            default:
                abort ();
        }

    //cout << a_site_size << "\n" << b_site_size << "\n" << enc_parms << "\n" << gal_key_file << "\n" << reli_key_file << endl;

    // Set up encryption parameters
    // read in site_A parms //
    cout << "Reading in Encryption Parameters" << endl;
    cout << endl;

    ifstream infile_parms_A;
    infile_parms_A.open(enc_parms);
    EncryptionParameters parms(scheme_type::BFV);
    parms.load(infile_parms_A);

    /*
    We create the SEALContext as usual and print the parameters.
    auto context = SEALContext::Create(parms);
    */

    auto context = SEALContext::Create(parms, false, sec_level_type::none);
    
    /*
    We can verify that batching is indeed enabled by looking at the encryption
    parameter qualifiers created by SEALContext.
    auto qualifiers = context->context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching
         << endl;
    */
    auto qualifiers = context->first_context_data()->qualifiers();

    cout << "Reading in Galois and Relin Keys" << endl;
    cout << endl;

    KeyGenerator keygen(context);
    ifstream gk_A;
    gk_A.open(gal_key_file);
    GaloisKeys g_keys;
    g_keys.load(context, gk_A);
    
    ifstream rk_A;
    rk_A.open(reli_key_file);
    RelinKeys r_keys;
    r_keys.load(context, rk_A);

    
    /*
    We also set up an Evaluator here.
    */
    Evaluator evaluator(context);
    
    ifstream in_file_A;
    in_file_A.open(a_site_size);
    int num_seqs_A = 0;
    
    // add a error message if file empty //
    string line;
    while (getline(in_file_A, line)) {
        stringstream seq_num(line);
        seq_num >> num_seqs_A;
    }
    cout << "There are " << num_seqs_A << " in Site A" << endl;

    ifstream in_file_B;
    in_file_B.open(b_site_size);
    int num_seqs_B = 0;
    
    // add a error message if file empty //
    line = "";
    while (getline(in_file_B, line)) {
        stringstream seq_num(line);
        seq_num >> num_seqs_B;
    }
    cout << "There are " << num_seqs_B << " in Site B" << endl;
    cout << endl;

    cout << "Calculating Biologically Informed Hamming Distance" << endl;
    cout << endl;

    for(int i = 0; i < num_seqs_A; i++){
        for(int j = 0; j < num_seqs_B; j++){
            // do a comparison //
            string a_num_str = to_string(i); 
            string b_num_str = to_string(j);

            string a_file = "data/A/encrypted/encrypted_A_" + a_num_str + ".txt";
            string b_file = "data/B/encrypted/encrypted_B_" + b_num_str + ".txt";
            string o_file =  "results/enc_ham/Enc_A_" + a_num_str + "_B_" + b_num_str + ".txt";

            //cout << "A goes to --> " << a_file << " B goes to --> " << b_file << endl;
            
            ifstream in_file_A;
            ifstream in_file_B;

            in_file_A.open(a_file);
            in_file_B.open(b_file);

            Ciphertext cipher_A;
            Ciphertext cipher_B;

            cipher_A.load(context, in_file_A);
            cipher_B.load(context, in_file_B);

            //cout << "A goes to --> " << a_file << " B goes to --> " << b_file << endl;
            evaluator.sub_inplace(cipher_A, cipher_B);
            evaluator.square_inplace(cipher_A);
            evaluator.relinearize_inplace(cipher_A, r_keys);
            
            // making changes 11/5
            Ciphertext temp_enc_mat;
            for (auto i = 0; i < (log2(poly_mod) - 1); i++) {
            //for (auto i = 0; i < log2(poly_mod); i++) {
                evaluator.rotate_rows(cipher_A, -(pow(2,i)), g_keys, temp_enc_mat);
                evaluator.add_inplace(cipher_A, temp_enc_mat);
            }
            
            ofstream myfile;
            myfile.open(o_file);
            cipher_A.save(myfile);

        }
    }
    
    cout << "Encrypted Results have been Written in the 'results' directory" << endl;
    cout << endl;
    cout << "Erasing ALL Data on Server and Closing Server Now" << endl;
    cout << endl;
}
