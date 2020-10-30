# TurboRex
---------------------
TurboRex is a Ruby gem for exploring MSRPC and COM. It is mainly a proof of concept for the topic "Automated Hunting for Cross-Server Xrefs in Microsoft RPC and COM" on Code Blue 2020.


## Author
Exist@SycloverSecurity

## Features
---------------------
* MSRPC server/client routines finder
* COM interface methods finder
* COM client finder(Not very useful)
* ALPC server/client
* COM client

## Installation
------------------
To install Turborex, run
```
gem install turborex
```
And then [install Metasm](https://github.com/jjyg/metasm/blob/master/INSTALL), please DON'T use the old version of Metasm hosted by Rubygems

## Examples
-----------------
Please take a look at the examples directory.


## Troubleshooting
-----------------
#### It is too slow, especially when searching for RPC client routines
There are many reasons for this result, such as my poor code quality, and the Ruby interpreter runs slower on Windows than Linux. There is a trick that can greatly increase the speed without changing too much code: running in WSL. But I did not fully test whether it is available in WSL, it may be necessary to modify the core library code.


## License
-----------------
See this license at LICENSE file.