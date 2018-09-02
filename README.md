# cryptic
SHA1, SHA2 and BASE64 algorithms header only implementations with C++17.

Usage is straight forward.

Example #1
```c++
auto test1 = "The quick brown fox jumps over the lazy dog"s;
cout << cryptic::sha1::base64(test1) << endl;
```
Example #2
```c++
auto test2 = "The quick brown fox jumps over the lazy dog"s;
cout << cryptic::sha256::hexadecimal(test2) << endl;
```
Example #3
```c++
auto test3 = cryptic::base64::encode("Man"s);
cout << test3 << endl;
```
Example #4
```c++
auto test4 = cryptic::base64::decode(test3);
cout << test4 << endl;
```

## Benchmarking
- SHA1 implementation seems to be around 3 times faster than openssl's implementation of SHA1.
- SHA256 implementation seems to be around 5 times faster than openssl's implementation of SHA256.
- I assume the better performance is mainly the result of clang++ complier's optimisation and the usage of some advanced c++ data structures i.e. gsl::span.

./bin/benchmark

SHA1 & SHA256 benchmark against openssl crypto - looping 5000000 times:  
372483deb82c3a1415b049c5934615e91a734ee3  
cryptic SHA1: 3555 ms  
372483deb82c3a1415b049c5934615e91a734ee3  
openssl crypto SHA1: 13046 ms  
cryptic SHA1 was 3 times faster  
02165c33ed6e9b170deadb2362498878fd4fb7eb620fefffd48fd9adb9ab1e0d  
cryptic SHA256: 5585 ms  
02165c33ed6e9b170deadb2362498878fd4fb7eb620fefffd48fd9adb9ab1e0d  
openssl crypto SHA256: 30688 ms  
cryptic SHA256 was 5 times faster  
