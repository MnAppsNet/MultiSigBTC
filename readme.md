
# MultiSigBTC

## About the project
MultiSigBTC is a project that is created in the context of the subject “Decentralized Technologies”, that take place in the master’s degree program "Data and Web Science" of Aristotle University of Thessaloniki.
It is developed from scratch by Kalyvas Emmanouil using the python library [bitcoin-utils](https://github.com/karask/python-bitcoin-utils) developed by Kostas Karasavvas.

## What does MultiSigBTC do?
MultiSigBTC is a tool that can be used to create and maintain multi signature addresses that can be used to send and receive funds the Bitcoin blockchain. A multi signature address, is an address that have m owners and requires n of them to agree upon a transaction. MultiSigBTC can theoretically create multi signature addresses with any m and n combination.
**Please note that this a an experimental tool that was not tested thoroughly (at least not yet) and it is not recommended using it on mainnet.**

## How to use?
### Usage:

    MultiSigBTC.py [--help] [-n {testnet,mainnet,regtest}] [-u RPCUSER] [-p RPCPASS] [-h HOST] [-o] command
                     
### Commands:
- create_new_address
- create_multisig_address
- create_multisig_transaction
- sign_multisig_transaction
- get_private_key
- get_signed_multisig_transaction
- get_address_balance
- send_transaction

### Optional arguments:
||Description|
|--|--|
| --help | show help and exit |
| -n, --network | Set the network type we are working with. One of these values: {'regtest','testnet','mainnet'}. Default value is 'regtest'. |
|-u, --rpcuser | Set the the rpc user used to connect to the network |
|-p, --rpcpass | Set the rpc password used to connect to the network  |
| -h, --host | Set thr host to connect to. By default localhost (127.0.0.1) is used. |
| -o , --output | Write results to file, can be combined with all the commands that return a result. Results are in JSON. |

### Command : create_new_address

    MultiSigBTC.py create_new_address [-h] [-s SEED] keyName password

#### Description:
Create a new private-public key pair along with its legacy bitcoin address
#### Positional arguments:
||Description|
|--|--|
|**keyName**|The name of the key (can be anything, avoid create multiple keys with the same name)|
|**password**| Password to lock the private key (remember it, you need it to unlock it)|
#### Optional arguments:
||Description|
|--|--|
|  -h, --help | show help exit|
| -s SEED, --seed SEED | The seed used for the random generator (a specific seed produces the same address)|


### Command : create_multisig_address

    MultiSigBTC.py create_multisig_address [-h] signaturesRequired keyfile [keyfile ...]

### Description : 
Create a multi signature address given the public keys you want to be involved

#### Positional arguments:
||Description|
|--|--|
|**signaturesRequired**|Number of required signatures to unlock UTXO|
|**keyfile**| The file containing the key to be used for the multi signature address funds (can be created with the command create_new_address -o path). You can also privide the JSON result of create_new_address or name and public key pairs or any combination of the expected input formats.

#### Optional arguments:
||Description|
|--|--|
|-h, --help | show help and exit |


### Command : create_multisig_transaction

    MultiSigBTC.py create_multisig_transaction [-h] address amount fee multisigKeyFile
#### Description:
Create an unsigned multisignature transaction (Note: it needs to be signed by
the owners with the command sign_transaction)

#### Positional arguments:
||Description|
|--|--|
|address          |Address to send the transaction to|
|amount           |Amount to spend|
|fee              |Fee amount to pay|
|multisigKeyFile  |The file containing the multi signature keys (can be created with create_multisig_address -o path). You can also provide the json result of create_multisig_address in place of multisigKeyFile|

#### Optional arguments:
||Description|
|--|--|
| -h, --help|show help and exit|


### Command : sign_multisig_transaction

    MultiSigBTC.py sign_multisig_transaction [-h] transactionFile addressFile password
    
#### Description :
Add a signature to a multisig transaction. Use to sign a transaction created
with create_multisig_transaction. Please note that every time someone signs
the transaction, the next person needs to sign the transaction using the
previous result in order to maintain all the signatures

#### Positional arguments:
||Description|
|--|--|
|  transactionFile  |The file containing the details for the unsigned or partially signed transaction (can be created with create_multisig_transaction -o path). You can also provide the json result of create_multisig_transaction in place of transactionFile|
|addressFile      |The file containing the encrypted private key (can becreated with create_new_address -o path) or the private key itself. If you provide the private key itself, you must give the key name in place of password. This is important  for the order of the keys. The name of the key is defined durting the multisig address creation|
|  password         |The password to decrypt the private key or if you gave the private key itself you need to set the name of the key as defined during the multisig address generation|

#### Optional arguments:
||Description|
|--|--|
|  -h, --help       |show help and exit|


### Command : get_private_key
    MultiSigBTC.py get_private_key [-h] keyFile password
#### Desciption:
Decrypts a private key created with this script using the user password

#### Positional arguments:
||Description|
|--|--|
| keyFile  | Key file containing private key (can be created with create_new_address -o path). In place of keyFile you can also put the encrypted private key string
| password | Password used to lock the private key|

#### Optional arguments:
||Description|
|--|--|
| -h, --help|  show this help message and exit|


### Command : get_signed_multisig_transaction

    MultiSigBTC.py get_signed_multisig_transaction [-h] transactionFile
#### Description:
Signs and returns the given transaction

#### Positional arguments:
||Description|
|--|--|
|transactionFile  |The file containing the details for the transaction and the  required signatures (can be created with -o path sign_multisig_transaction) You can also provide the json result of  sign_multisig_transaction in place of transactionFile

#### Optional arguments:
||Description|
|--|--|
| -h, --help |show help and exit|

### Command : get_address_balance

    MultiSigBTC.py get_address_balance [-h] addressFile
#### Description:
Get the balance of the given address

#### Positional arguments:
||Description|
|--|--|
| addressFile |A result file containing an address (the file can be cerated with create_new_address -o path or create_multisig_address -o path) You can also set the address string itself

### Command : send_transaction

    MultiSigBTC.py send_transaction [-h] transactionFile
#### Description:
Sends the transaction to the network

#### Positional arguments:
||Description|
|--|--|
| transactionFile | A file containing the signed transaction (the file can be cerated with get_signed_multisig_transaction -o path or  get_signed_multisig_transaction -o path) You can also provide the signed transaction in raw hex format in place of transactionFile|

#### Optional arguments:
||Description|
|--|--|
|  -h, --help  | show help and exit|
