# HIV-TRACE Homomorphic Encryption (tentative title)

## Dependencies

### Microsoft SEAL 
https://github.com/microsoft/SEAL.git

## Installation

```
brew install seal
```

```
git clone https://github.com/veg/hivtrace-homomorphic-encryption.git
cd hivtrace-homomorphic-encryption
cmake .
make
```
## Running 

```
1) ./bin/site_a -i Site_1_aligned.fa
2) ./bin/site_b -i Site_2_aligned.fa -e data/A/parameters/parms_A.txt -k data/A/keys/pk_A.txt
3) ./bin/compare_a_b -a data/A/encrypted/Site_A_number_seqs.txt 
    -b data/B/encrypted/Site_B_number_seqs.txt 
    -e data/A/parameters/parms_A.txt 
    -g data/A/keys/gk_A.txt 
    -r data/A/keys/rk_A.txt
4) ./bin/read_hamming -a data/A/encrypted/Site_A_number_seqs.txt
    -b data/B/encrypted/Site_B_number_seqs.txt
    -e data/A/parameters/parms_A.txt
    -s data/A/sk_A.txt

```
