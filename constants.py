#Network constants :
class Network:
    MAINNET = 'mainnet'
    TESTNET = 'testnet'
    REGTEST = 'regtest'

#Parameters of the UTXO list returned from bitcoin network
class UTXO:
    TOTAL_AMOUNT = 'total_amount'
    UNSPENTS = 'unspents'
    UNSPENTS_AMOUNT = 'amount'
    UNSPENTS_TXID = 'txid'
    UNSPENTS_VOUT = 'vout'

#Addresses types
class AddressType:
    LEGACY = "legacy"
    SEGWIT = "segwit"

#Argument constants
class Arguments:
    NETWORK = 'network'
    RPCUSER = 'rpc_user'
    RPCPASS = 'rpc_pass'
    HOST = 'host'
    OUTPUT = 'output'
    CREATE_NEW_ADDRESS = 'create_new_address'
    KEYNAME = 'key_name'
    PASSWORD = 'password'
    SEED = 'seed'
    CREATE_MULTISIG_ADDRESS = 'create_multisig_address'
    SIGNATURESREQUIRED = 'signatures_required'
    CREATE_MULTISIG_TRANSACTION = 'create_multisig_transaction'
    ADDRESS = 'address'
    AMOUNT = 'amount'
    FEE = 'fee'
    MULTISIGKEYFILE = 'multisig_key_file'
    SIGN_MULTISIG_TRANSACTION = 'sign_multisig_transaction'
    TRANSACTION_FILE = 'transaction_file'
    KEY_FILE = 'key_file'
    GET_PRIVATE_KEY = 'get_private_key'
    GET_SIGNED_MULTISIG_TRANSACTION = 'get_signed_multisig_transaction'
    GET_ADDRESS_BALANCE = 'get_address_balance'
    ADDRESS_FILE = 'address_file'
    SEND_TRANSACTION = 'send_transaction'
    TYPE = 'address_type'