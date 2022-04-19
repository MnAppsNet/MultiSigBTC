#=========================================================#
# Creation Date : 04/2022                                 #
# Author        : Kalyvas Emmanouil                       #
# Description   : Bitcoin Multi Signature Transactions    #
#=========================================================#

import commands, sys
from argparse import ArgumentParser,RawTextHelpFormatter
from bitcoin import Bitcoin
from pprint import pprint
from tools import Output,HelpAction, getArgument as getArg
from constants import Arguments as args, AddressType

DEBUG = True #<= Show debugging information on exceptions

parser = ArgumentParser(description='MultiSigBTC - Create and maintain Multi Signature Addresses', formatter_class=RawTextHelpFormatter, add_help=False)

parser.add_argument('--help', action=HelpAction)

#==================================#
# Choose the network to connect to #
#==================================#
parser.add_argument('-n',f'--{args.NETWORK}', choices=Bitcoin.NETWORKS, default=['regtest'], type=str, nargs=1, help=
'''Set the network type we are working with. One of these values: {'regtest','testnet','mainnet'}. Default value is 'regtest'.''')
parser.add_argument('-u',f'--{args.RPCUSER}', type=str, nargs=1, default=None, help=
'''Set the the rpc user used to connect to the network''')
parser.add_argument('-p',f'--{args.RPCPASS}', type=str, nargs=1, default=None, help=
'''Set the rpc password used to connect to the network''')
parser.add_argument('-h',f'--{args.HOST}', type=str, nargs=1, default=['127.0.0.1'], help=
'''Set thr host to connect to. By default localhost (127.0.0.1) is used.''')

#==========================#
# Set the output file path #
#==========================#
parser.add_argument('-o',f'--{args.OUTPUT}',dest=args.OUTPUT,nargs=1,default=None,help=
'''Write results to file, can be combined with all the commands that return a result. Results are in JSON.''')

subparser = parser.add_subparsers(title="Commands",dest="command")

#====================#
# Create new address #
#====================#
create_new_address = subparser.add_parser(args.CREATE_NEW_ADDRESS,description='Create a new private-public key pair along with its address')
create_new_address.add_argument(args.KEYNAME,help="The name of the key (can be anything, avoid create multiple keys with the same name)",nargs=1)
create_new_address.add_argument(args.PASSWORD,help="Password to lock the private key (remember it, you need it to unlock it)",nargs=1)
create_new_address.add_argument('-s',f'--{args.SEED}', default=None, help="The seed used for the random generator (a specific seed produces the same address)",nargs=1)
create_new_address.add_argument('-t',f'--{args.TYPE}', default=[AddressType.SEGWIT], choices={AddressType.LEGACY, AddressType.SEGWIT}, help="The type of the address",nargs=1)


#================================#
# Create Multi Signature Address #
#================================#
create_multisig_address = subparser.add_parser(args.CREATE_MULTISIG_ADDRESS,description='Create a multi signature address')
create_multisig_address.add_argument(args.SIGNATURESREQUIRED,help="Number of required signatures to unlock UTXO",nargs=1)
create_multisig_address.add_argument(args.KEY_FILE,nargs='+',help=
f'''The file containing the key to be used for the multi signature address funds (can be created with the command -o path {args.CREATE_NEW_ADDRESS}).
You can also privide the JSON result of {args.CREATE_NEW_ADDRESS} or name and public key pairs or any combination of the expected input formats.''')
create_multisig_address.add_argument('-t',f'--{args.TYPE}', default=[AddressType.SEGWIT], choices={AddressType.LEGACY, AddressType.SEGWIT}, help="The type of the address",nargs=1)

#======================================#
# Create a multi signature transaction #
#======================================#
create_multisig_transaction = subparser.add_parser(args.CREATE_MULTISIG_TRANSACTION,description=
f'''Create an unsigned multisignature transaction (Note: it needs to be signed by the owners with the command {args.SIGN_MULTISIG_TRANSACTION})''')
create_multisig_transaction.add_argument(args.ADDRESS,help="Address to send the transaction to",nargs=1)
create_multisig_transaction.add_argument(args.AMOUNT,help="Amount to spend",nargs=1)
create_multisig_transaction.add_argument(args.FEE,help="Fee amount to pay",nargs=1)
create_multisig_transaction.add_argument(args.MULTISIGKEYFILE,nargs=1,help=
f'''The file containing the multi signature keys (can be created with -o path {args.CREATE_MULTISIG_ADDRESS}).
You can also provide the json result of {args.CREATE_MULTISIG_ADDRESS} in place of {args.MULTISIGKEYFILE}''')

#==================================#
# Sign multi signature transaction #
#==================================#
sign_multisig_transaction = subparser.add_parser(args.SIGN_MULTISIG_TRANSACTION,description=
f'''Add a signature to a multisig transaction. Use to sign a transaction created with {args.CREATE_MULTISIG_TRANSACTION}.
Please note that every time someone signs the transaction, the next person needs to sign the transaction using the previous result
in order to maintain all the signatures''')
sign_multisig_transaction.add_argument(args.TRANSACTION_FILE,nargs=1,help=
f'''The file containing the details for the unsigned or partially signed transaction (can be created with -o path {args.CREATE_MULTISIG_TRANSACTION}).
You can also provide the json result of {args.CREATE_MULTISIG_TRANSACTION} in place of {args.TRANSACTION_FILE}''')
sign_multisig_transaction.add_argument(args.ADDRESS_FILE,nargs=1,help=
f'''The file containing the encrypted private key (can be created with -o path {args.CREATE_NEW_ADDRESS}) or the private key itself.
If you provide the private key itself, you must give the key name in place of {args.PASSWORD}. This is important for the order of the keys.
The name of the key is defined durting the multisig address creation ({args.CREATE_MULTISIG_ADDRESS})''')
sign_multisig_transaction.add_argument(args.PASSWORD,nargs=1,help=
'''The password to decrypt the private key or if you gave the private key itself you need to set the name of the key as defined during
the multisig address generation ({args.create_multisig_address})''')

#================================#
# Decrypt and return private key #
#================================#
get_private_key = subparser.add_parser(args.GET_PRIVATE_KEY,description=
'''Decrypts a private key created with this script using the user password''')
get_private_key.add_argument(args.KEY_FILE,nargs=1,help=
f'''Key file containing private key (can be created with -o path {args.CREATE_NEW_ADDRESS}).
In place of {args.KEY_FILE} you can also put the encrypted private key string''')
get_private_key.add_argument(args.PASSWORD,nargs=1,help=
'''Password used to lock the private key''')

#===================================#
# Get the signed transaction in hex #
#===================================#
get_signed_multisig_transaction = subparser.add_parser(args.GET_SIGNED_MULTISIG_TRANSACTION,description=
'''Signs and returns the given transaction''')
get_signed_multisig_transaction.add_argument(args.TRANSACTION_FILE,nargs=1,help=
f'''The file containing the details for the transaction and the required signatures (can be created with -o path {args.SIGN_MULTISIG_TRANSACTION})
You can also provide the json result of {args.SIGN_MULTISIG_TRANSACTION} in place of {args.TRANSACTION_FILE}''')

#=====================#
# Get Address Balance #
#=====================#
get_address_balance = subparser.add_parser(args.GET_ADDRESS_BALANCE,description=
'''Get the balance of the given address''')
get_address_balance.add_argument(args.ADDRESS_FILE,nargs=1,help=
f'''A result file containing an address (the file can be cerated with -o path {args.CREATE_NEW_ADDRESS} or -o path {args.CREATE_MULTISIG_ADDRESS})
You can also set the address string itself''')

#==================#
# Send transaction #
#==================#
send_transaction = subparser.add_parser(args.SEND_TRANSACTION,description=
'''Sends the transaction to the network''')
send_transaction.add_argument(args.TRANSACTION_FILE,nargs=1,help=
f'''A file containing the signed transaction (the file can be cerated with commands -o path {args.GET_SIGNED_MULTISIG_TRANSACTION} or -o path {args.GET_SIGNED_MULTISIG_TRANSACTION})
You can also provide the signed transaction in raw hex format in place of {args.TRANSACTION_FILE}''')

try:
    #Gather given arguments :
    inputs = parser.parse_args()

    #Create the bitcoin instance :
    bitcoin = Bitcoin(
        getArg(inputs,args.NETWORK),
        getArg(inputs,args.RPCUSER),
        getArg(inputs,args.RPCPASS),
        getArg(inputs,args.HOST))

    #Gather output path :
    savePath = getArg(inputs,args.OUTPUT)

#Execute command based on given arguments :
    if inputs.command == args.CREATE_MULTISIG_ADDRESS:
        settings = commands.createMultisigAddress(
            getArg(inputs,args.SIGNATURESREQUIRED),
            getArg(inputs,args.KEY_FILE,True),
            getArg(inputs,args.TYPE),
            bitcoin,
            savePath)
        pprint(settings)

    elif inputs.command == args.CREATE_NEW_ADDRESS:
        address = commands.createNewAddress(
            getArg(inputs,args.KEYNAME),
            getArg(inputs,args.PASSWORD),
            getArg(inputs,args.TYPE),
            getArg(inputs,args.SEED),
            bitcoin,
            savePath)
        pprint(address)

    elif inputs.command == args.GET_PRIVATE_KEY:
        privateKey = commands.getPrivateKey(
            getArg(inputs,args.keyfile),
            getArg(inputs,args.PASSWORD)
        )
        print(privateKey)

    elif inputs.command == args.CREATE_MULTISIG_TRANSACTION:
        transaction = commands.createMultisigTransaction(
            getArg(inputs,args.ADDRESS),
            getArg(inputs,args.AMOUNT),
            getArg(inputs,args.FEE),
            getArg(inputs,args.MULTISIGKEYFILE),
            bitcoin,
            savePath)
        pprint(transaction)

    elif inputs.command == args.SIGN_MULTISIG_TRANSACTION:
        transaction = commands.signMultisigTransaction(
            getArg(inputs,args.TRANSACTION_FILE),
            getArg(inputs,args.ADDRESS_FILE),
            getArg(inputs,args.PASSWORD),
            bitcoin,
            savePath)
        pprint(transaction)

    elif inputs.command == args.GET_SIGNED_MULTISIG_TRANSACTION:

        signedTransaction = commands.createdSignedTransaction(
            getArg(inputs,args.TRANSACTION_FILE),
            bitcoin,
            savePath)
        print(signedTransaction)

    elif inputs.command == args.GET_ADDRESS_BALANCE:

        UTXOs = commands.getAddressBalance(
            getArg(inputs,args.ADDRESS_FILE),
            bitcoin)
        pprint(UTXOs)

    elif inputs.command == args.SEND_TRANSACTION:

        results = commands.sendTransaction(
            getArg(inputs,args.TRANSACTION_FILE),
            bitcoin)
        pprint(results)

#Handle exceptions :
except Exception as exception:
    output = Output(Output.EXCEPTION)
    trace = []
    if DEBUG:
        tb = exception.__traceback__
        while tb is not None:
            trace.append({
                "name": tb.tb_frame.f_code.co_name,
                "line": tb.tb_lineno
            })
            tb = tb.tb_next
        output.addValue("trace",trace)
    output.addValue(Output.EXCEPTION,{
                'type': type(exception).__name__,
                'message': str(exception)
        })
    pprint(output.getOutput())