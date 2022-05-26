//Alice Code
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

//generate alice keys
ecc_key a_keys=make_pk_sk_pair(p_state);
cout<<endl<<"Alice Keys generated\n";

//----------export keys-------
unsigned long int a_key_len=5000;
unsigned char a_export_key[5000];
export_public_key(a_keys, &a_key_len, a_export_key);
cout<<"ALice's public key\n"<<a_export_key<<endl<<"Size is:"<<a_key_len<<endl;

// ------ ZeroMQ ------
// Prepare our context and socket
zmq::context_t context (1);
zmq::socket_t socket (context, zmq::socket_type::req);
socket.connect ("tcp://localhost:5556");

// Send alice's ZMQ message
size_t size_zmq=a_key_len;
zmq::message_t a_zmq_msg (size_zmq);
memcpy (a_zmq_msg.data(), a_export_key, size_zmq);
cout << "Sending Alice Public key..." << std::endl;
socket.send(a_zmq_msg);

//receive Bob's ZMQ message
zmq::message_t request;
unsigned char b_pub_key[5000];
zmq::recv_result_t ret = socket.recv (request, zmq::recv_flags::none);
string rpl = string(static_cast<char*>(request.data()), request.size());
memcpy(b_pub_key,rpl.data(),rpl.size());
unsigned long int b_length=(unsigned long int)rpl.size();
cout<<endl<<"Bob's public key\n"<<b_pub_key<<endl<<"Size is:"<<b_length<<endl;

//import alice keys
ecc_key b_ecc_public_key = import_public_key(b_length, b_pub_key);
cout<<"\nECC form of Bob's Public key imported"<<endl;

// shared key
unsigned char a_secret[5000];
unsigned long int a_secret_length=5000;
compute_shared_secret(a_keys,b_ecc_public_key, a_secret, &a_secret_length);
cout<<"Alices's shared key\n"<<a_secret<<endl<<"Size is:"<<a_secret_length<<endl;

//Read Message from handshake.txt
    ifstream msg_file("handshake.txt");
    string message((istreambuf_iterator<char>(msg_file)),istreambuf_iterator<char>());
    int n_message=message.length();
    char message_array[n_message];
    strcpy(message_array,message.c_str());
//cout<<message_array<<endl;

//HMAC     
    unsigned char mac_a[5000];
    HMAC_Computation((char *)message_array, mac_a, a_secret);
    cout<<endl<<"ALice's mac\n"<<mac_a<<endl;
string str_mac_a = string((const char*)mac_a);

//Send Alice's HMAC

size_zmq=str_mac_a.size();
zmq::message_t a_mac (size_zmq);
memcpy (a_mac.data(), mac_a, size_zmq);
cout << "Sending Alice MAC ..." << std::endl;
socket.send(a_mac);

    
    
    
return 0;
}
