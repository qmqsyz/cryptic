# cryptic
SHA1 and base64 algorithms header only library implemented with C++17.

Usage is straight forward.

Example #1
```c++
auto test1 = "The quick brown fox jumps over the lazy dog"s;
cout << cryptic::sha1::base64(test1) << endl;
```
Example #2
```c++
auto test2 = cryptic::base64::encode("Man"s);
cout << test2 << endl;
```
Example #3
```c++
auto test3 = cryptic::base64::decode(test2);
cout << test3 << endl;
```
