//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/



#include "cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::Redirector;
using CryptoPP::HashFilter;
using CryptoPP::StringSink;
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;
using CryptoPP::SHA1;
#include "cryptopp/sha3.h"
using CryptoPP::SHA3_256;
#include"cryptopp/md5.h"
using CryptoPP::MD5;
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1


#include <ctime>
#include <iostream>
#include <string>
using namespace std;

/* Randomly generator*/
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;
#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;

#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
using CryptoPP::ECP;    // Prime field p
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include <cryptopp/pubkey.h>
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

/* standard curves*/
#include <cryptopp/asn.h>
#include <cryptopp/oids.h> // 
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

#include <sstream>
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include<iostream>
#include<string>
#include<WS2tcpip.h>
#pragma comment (lib,"ws2_32.lib")

string HashCalc(ECP::Point X);
string Integer_to_string(const Integer& i)
{
    std::ostringstream os;
    os << i;

    return os.str();
}

int main(int argc, char* argv[])
{
    //step 1: Initialize system params
    AutoSeededRandomPool rng;
    // Contruct  ECP(const Integer &modulus, const FieldElement &A, const FieldElement &B);

            // User Defined Domain Parameters for curve y^2 =x^3 + ax +b
            // Modulus p
    Integer p("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffh");
    // Coefiction a
    Integer a("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffch");
    // Coefiction b
    Integer b("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefh");
    /* create a curve*/
    a %= p;     b %= p; // a mod p, b mod p
    /* ECC curve */
    CryptoPP::ECP eqcurve384(p, a, b); // buide curve y^2 =x^3 +ax +b
    /* subgroup <G> on curve */
     // x, y: Base Point G
    Integer x("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7h");
    Integer y("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fh");
    // Creat point G
    ECP::Point G(x, y);
    // Oder n of group <G>
    Integer n("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973h");
    //Cofactors
    Integer h("01h");
    /* Set ECC parameters and subgroup <G>*/
    // CryptoPP::DL_GroupParameters_EC<ECP> curve256(eqcurve256,G,n,h);
    CryptoPP::DL_GroupParameters_EC<ECP> curve384;
    curve384.Initialize(eqcurve384, G, n, h);
    /* Get curve paramaters p, a, b, G, n, h*/
    cout << "Cofactor h=" << curve384.GetCofactor() << endl;
    cout << "Subgroup Order n=" << curve384.GetSubgroupOrder() << endl;
    cout << "Gx=" << curve384.GetSubgroupGenerator().x << endl;
    cout << "Gy=" << curve384.GetSubgroupGenerator().y << endl;
    cout << "Coefficient  a=" << curve384.GetCurve().GetA() << endl;
    cout << "Coefficient  b=" << curve384.GetCurve().GetB() << endl;
    //cout <<"Prime number p=" <<curve384.GetCurve().GetField()<<endl;
    /* Computation on Curve Add, double, scalar mutiplication*/
    ECP::Point Q = curve384.GetCurve().Double(G); // G+G;
    cout << "Qx=" << Q.x << endl;
    cout << "Qy=" << Q.y << endl;
    Integer r("3451");
    r %= p;
    cout << "number r=" << r << endl;
    ECP::Point H = curve384.GetCurve().ScalarMultiply(G, r); // rP;
    cout << "Hx=" << H.x << endl;
    cout << "Hy=" << H.y << endl;
    ECP::Point I = curve384.GetCurve().Add(Q, H); // Q+H=2G+3451G
    cout << "Ix=" << I.x << endl;
    cout << "Iy=" << I.y << endl;
    // Verify
    Integer r1("3453");
    r1 %= p;
    cout << "number r1=" << r1 << endl;
    ECP::Point I1 = curve384.GetCurve().ScalarMultiply(G, r1); // r1.G;
    cout << "I1x=" << I1.x << endl;
    cout << "I1y=" << I1.y << endl;
    cout << curve384.GetCurve().Equal(I, I1) << endl;


    cout << "---------------------------------\n";
    cout << "____________ECDH_____________\n";
    //Step2: Self-gen a pair of keys
    Integer privatekeyA = Integer("11517981818447497085967951605465729846919455156164689798014638985875583987829406262183357738592749044441967993136875");// Integer(rng, 2, curve384.GetSubgroupOrder() - 1);
    cout << "Private key A: " << privatekeyA << endl;
    ECP::Point publickeyA = curve384.GetCurve().ScalarMultiply(G, privatekeyA);
    cout << "Public key A(PU_A): \nPU_A.x = " << publickeyA.x << "\nPU_A.y = " << publickeyA.y << endl;
    //hashcal for publickey
     string hash_pubkey = HashCalc(publickeyA);
     cout << "Hash value of A's public key: "<< hash_pubkey << endl;


    string ipaddrr = "192.168.140.66";  // địa chỉ ip của máy partner 
    int port = 8080;
    //initialize winsocket
    WSAData data;
    WORD ver = MAKEWORD(2, 2);
    int wsRes = WSAStartup(ver, &data);
    if (wsRes != 0) {
        cerr << "There is an Error#" << wsRes << endl;
        return 0;
    }
    //create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        cerr << "Can't create socket. Err#" << WSAGetLastError() << endl;
        return 0;
    }
    //Hint structure
    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(port);
    inet_pton(AF_INET, ipaddrr.c_str(), &hint.sin_addr);

    //connect to server
    int connectRes = connect(sock, (sockaddr*)&hint, sizeof(hint));
    if (connectRes == SOCKET_ERROR)
    {
        cerr << "Can't connect to server, Err#" << SOCKET_ERROR << endl;
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    //Receive and send 
    char buf[4096];
    string init = "\r\n";
    bool flag = false;
    for (int i = 0;i < 2;i++) {
        int init_res = send(sock, init.c_str(), init.size() + 1, 0);
        if (init_res != SOCKET_ERROR) {
            ZeroMemory(buf, 4096);
            int bytesReceived = recv(sock, buf, 4096, 0);
            if (bytesReceived > 0 && !flag) {
                std::cout << "Server> " << std::string(buf, 0, bytesReceived) << std::endl;
                //flag = true;
            }
            else {
                cout << "\r\n" << endl;
            }
        }
    }


    string userInput = "PU_Ax = " + Integer_to_string(publickeyA.x) + "\nPU_Ay = " + Integer_to_string(publickeyA.y) +"\nDigest A: " + hash_pubkey;
        
    cout << "> "  ;


        if (userInput.size() > 0) {
            int sendRes = send(sock, userInput.c_str(), userInput.size() + 1, 0);
            if (sendRes != SOCKET_ERROR) {
                ZeroMemory(buf, 4096);
                int bytesReceived = recv(sock, buf, 4096, 0);
                if (bytesReceived > 0) {
                    std::cout << "Server> " << string(buf, 0, bytesReceived) << endl;
                }

            }
        }


   

    closesocket(sock);
    WSACleanup();





    
    //illustrate MITM attack:
    Integer attacker_prikey = Integer("26988257286192865480571104439904191407903659847737489305985422201543174684479007433839364782847644548943412542528678");
    cout << "Private key Attacker: " << attacker_prikey << endl;
    //ECP::Point attacker_pubkey = curve384.GetCurve().ScalarMultiply(G, attacker_prikey);
    Integer _x_a("36144630541865396044941435801119258870753962498000801199871147425319301283809956752746448328897225083002566932522903");
    Integer _y_a("6737059266827092707485834579447557237665665027622884830871729387225241558579834758274651292025036791178668023199702");

    ECP::Point attacker_pubkey(_x_a, _y_a);
    cout << "Attacker's Public key A(PU_A): \nPU.x = " << attacker_pubkey.x << "\nPU.y = " << attacker_pubkey.y << endl;

    ECP::Point sharedkey_fake = curve384.GetCurve().ScalarMultiply(publickeyA, attacker_prikey);
    cout << "Sharedkey fake for A: \n";
    cout << "x = " << sharedkey_fake.x << endl;
    cout << "y = " << sharedkey_fake.y << endl;


    //Receive public key from partner
    
    Integer _x("22127068231875614136172755532963635488621304567311586549968494059237297970173332750964229514210448295658111413003317");
    Integer _y("21104228800329003896559718959944548501931957079383483794577681501294835137130342591195121471215291836343396551739847");
    ECP::Point publickeyB(_x, _y);
    
    cout << "Public key B(PU_B): \nPU_B.x = " << publickeyB.x << "\nPU_B.y = " << publickeyB.y << endl;

    ECP::Point sharedkey_fake1 = curve384.GetCurve().ScalarMultiply(publickeyB, attacker_prikey);
    cout << "Sharedkey fake for B: \n";
    cout << "x = " << sharedkey_fake1.x << endl;
    cout << "y = " << sharedkey_fake1.y << endl;

    // 1. Verify key
    string digest = HashCalc(publickeyB);
    cout << digest << endl;
    string original_hash = "B3BFE893971302CF6C098E6264D053BA3BC8D59B621295340CA8E6C6FC765A6E";
    if (digest == original_hash) {
        cout << "Verified\n";

        //calculate sharedkey
        ECP::Point sharedkey = curve384.GetCurve().ScalarMultiply(publickeyB, privatekeyA);
        cout << "Sharedkey: \n";
        cout << "x = " << sharedkey.x << endl;
        cout << "y = " << sharedkey.y << endl;
    }
    else {
        cout << "Not verified\n";
        return 0;
    }
    

    

}
string HashCalc(ECP::Point X) {
    
    ostringstream os1, os2;
    os1 << X.x;
    os2 << X.y;
    string x = os1.str();
    
    string y = os2.str();
    x.erase(x.find("."), 1);
    y.erase(y.find("."), 1);
    
    string msg_input = x + y;//"2212706823187561413617275553296363548862130456731158654996849405923729797017333275096422951421044829565811141300331721104228800329003896559718959944548501931957079383483794577681501294835137130342591195121471215291836343396551739847";
    

    int sel_m;
    cout << "Which mode do you want to conduct:\n1.SHA1\n2.SHA2(SHA256)\n3.SHA3(SHA3_256)\n";
    cin >> sel_m;
    HexEncoder encoder(new FileSink(std::cout));
    std::string digest;
   
    if (sel_m == 1) {
        SHA1 hash;
        StringSource(msg_input, true, new HashFilter(hash, new StringSink(digest)));
    }
    else if (sel_m == 2) {
        SHA256 hash;
        StringSource(msg_input, true, new HashFilter(hash, new StringSink(digest)));
    }
    else if (sel_m==3){
        SHA3_256 hash;
        StringSource(msg_input, true, new HashFilter(hash, new StringSink(digest)));
    }
    else {
        cout << "Invalid!";
        return 0;
    }


   
    string encoded;
    
    StringSource ssk(digest, true /*pump all*/,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexDecoder
    ); // StringSource
    return encoded;
   
   // return 0;
     
}

