# SGX-enclave-to-enclave-ra

## Notice

- This project has only been tested on Ubuntu 18.04.1 x86_64.
- This project has only been tested under **hardware** mode.

## Build

... with CMake.

``` console
$ mkdir build
$ cmake ..
$ make
```

## Run

- Copy the config file `config.toml` into `build`
- Modify the config file
    - `SPID`, `IAS_PRIMARY_SUBSCRIPTION_KEY`, `IAS_SECONDARY_SUBSCRIPTION_KEY` should come from Intel API portal
    - `POLICY_MRSIGNER` is `SHA256(modulus)` where `modulus` come from the RSA-3072bit public key corresponding to the private key you used to sign the Enclave
        - `modulus` should be 384 bytes long, serialized in **little-endian**
        - `MRSIGNER` can also be extracted from the signed enclave, [see here](https://github.com/intel/sgx-ra-sample/blob/master/mrsigner.c)
- Run a server
- Run a client

## Description

Remote attestation (RA) was designed to be conducted between an Enclave and a Service Provider on different platforms. 
That is, the service provider dont't have to be in an enclave, thus untrusted. 
However, in P2P applications, we need inter-platform attestation with both the ends in enclave.

This project demonstrates how two enclaves can do RA with each other.
Generally speaking, this work implements a service provider with in enclaves. 
When doing enclave-to-enclave remote attestation (EERA), every enclave acts as a SP and an ISV and plays a role in two session of RA at the same time.
After the two sessions finished, there should be two shared secrets within them.
We use the XOR of the two shared shared secrets to be the key of the secure channel established between the two enclaves.

### Things Considered

- IAS report response has to be verified within enclave. 
    If an enclave didn't see the original report, verify the certificate chain and verify Intel's signature, it should trust the other enclave.
- In this project, the whole process of service provider was conducted within enclave.
    Actually, everything but the verification of IAS report and calculate the shared key can be done outside the enclave.
    However, there's something should be noticed.
    
    Remember that we have 4 pairs of ephemeral EC key during the EERA,
    Since the ephemeral EC key used by SP in ECDH was generated in OS, it cannot be used to compute the shared session key.
    Instead, they can generate the shared secret using the to key pairs generated in enclave. 
    This means the ephemeral public key of the remote enclave has to be passed into the local enclave together with IAS report.
- We can also reduce the number of key pairs used during EERA to two. 
    That is, an enclave uses the same ephemeral EC key in the two sessions. 
    But the SP session has to get the private key generated in ISV session then. 
    This requires us to hack into the SDK and to modify the ISV code provided by Intel.    
- The final session key can be generated in other ways. 
    I chose to do XOR only because it's symmetric and this reduce the code on distinguishing which secret was generated when I was an SP and which secret was generated when I acted as an ISV.
    