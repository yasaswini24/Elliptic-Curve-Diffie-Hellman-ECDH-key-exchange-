//Bob's code
#include <tomcrypt.h>
#include <string>
#include <iostream>
#include <cstdlib>
#include <iomanip>
#include <fstream>
#include <math.h>
#include <chrono>
#include <thread>
#include "zmq.hpp"
#include "methods.cpp"
extern ltc_math_descriptor ltc_mp;
extern const ltc_math_descriptor ltm_desc;
using namespace std;
using namespace std::chrono_literals;

int main()
{
ltc_mp = ltm_desc;

//initialize PRNG state
prng_state p_state;
p_state=make_prng(&p_state);
cout<<endl<<"PRNG state initialized\n";

//generate bob's keys
ecc_key b_keys=make_pk_sk_pair(p_state);
cout<<endl<<"Bob Keys generated\n";

//export keys
unsigned long int b_key_len=5000;
unsigned char b_export_key[5000];
export_public_key(b_keys, &b_key_len, b_export_key);
cout<<"Bob's public key\n"<<b_export_key<<endl<<"Size is:"<<b_key_len<<endl;


//ZMQ - receive alice's public key
unsigned char a_pub_key[5000];
zmq::context_t context (1);
zmq::socket_t socket (context, zmq::socket_type::rep);
socket.bind ("tcp://*:5556");

//receive alice key
zmq::message_t request;
zmq::recv_result_t ret = socket.recv (request);
string rpl = string(static_cast<char*>(request.data()), request.size());
memcpy(a_pub_key,rpl.data(),rpl.size());
unsigned long int a_length=(unsigned long int)rpl.size();
cout<<endl<<"ALice's public key\n"<<a_pub_key<<endl<<"Size is:"<<a_length<<endl;

//send bob's public key
size_t size_zmq=b_key_len;
zmq::message_t b_zmq_msg (size_zmq);
memcpy (b_zmq_msg.data(), b_export_key, size_zmq);
cout << "Sending BoB's Public key..." << std::endl;
socket.send(b_zmq_msg);


//import alice keys
ecc_key a_ecc_public_key = import_public_key(a_length, a_pub_key);
cout<<"\nECC form of Alice's Public key imported"<<endl;

// shared key
unsigned char b_secret[5000];
unsigned long int b_secret_length=4096;
compute_shared_secret(b_keys,a_ecc_public_key, b_secret, &b_secret_length);
cout<<"Bob's shared key\n"<<b_secret<<endl<<"Size is:"<<b_secret_length<<endl;


//Read Message from handshake.txt
    ifstream msg_file("handshake.txt");
    string message((istreambuf_iterator<char>(msg_file)),istreambuf_iterator<char>());
    int n_message=message.length();
    char message_array[n_message];
    strcpy(message_array,message.c_str());
    //cout<<message_array<<endl;

//HMAC     
    unsigned char mac_b[5000];
    HMAC_Computation((char *)message_array, mac_b, b_secret);
    cout<<endl<<"\nBob's mac\n"<<mac_b<<endl;
//receive Alice's HMAC
unsigned char mac_a[5000];
zmq::message_t request1;
zmq::recv_result_t ret1 = socket.recv (request1, zmq::recv_flags::none);
string rpl1 = string(static_cast<char*>(request1.data()), request1.size());
memcpy(mac_a,rpl1.data(),rpl1.size());
//unsigned long int a_length=(unsigned long int)rpl.size();
cout<<endl<<"ALice's mac\n"<<mac_a<<endl;


string str_mac_a = string((const char*)mac_a);


string str_mac_b = string((const char*)mac_b);

if(str_mac_a == str_mac_b){
cout<<"Verified"<<endl;
}
else{
cout<<"Not Verified"<<endl;
}

return 0;
}
