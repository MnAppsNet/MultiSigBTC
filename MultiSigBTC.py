#===================================================================#
# Creation Date : 04/2022                                           #
# Author        : Kalyvas Emmanouil                                 #
# Description   : Bitcoin Multi Signature Transactions with P2SH    #
#===================================================================#

import commands, sys
from argparse import ArgumentParser,RawTextHelpFormatter
from bitcoin import Bitcoin
from pprint import pprint
from tools import Output,HelpAction, getArgument as getArg
from constants import arguments as args

DEBUG = True #<= Show debugging information on exceptions

parser = ArgumentParser(description='MultiSigBTC - Create and maintain Multi Signature Addresses', formatter_class=RawTextHelpFormatter, add_help=False)

parser.add_argument('--help', action=HelpAction)

#==================================#
# Choose the network to connect to #
#==================================#
parser.add_argument('-n',f'--{args.network}', choices=Bitcoin.NETWORKS, default=['regtest'], type=str, nargs=1, help=
'''Set the network type we are working with. One of these values: {'regtest','testnet','mainnet'}. Default value is 'regtest'.''')
parser.add_argument('-u',f'--{args.rpcuser}', type=str, nargs=1, default=None, help=
'''Set the the rpc user used to connect to the network''')
parser.add_argument('-p',f'--{args.rpcpass}', type=str, nargs=1, default=None, help=
'''Set the rpc password used to connect to the network''')
parser.add_argument('-h',f'--{args.host}', type=str, nargs=1, default=['127.0.0.1'], help=
'''Set thr host to connect to. By default localhost (127.0.0.1) is used.''')

#==========================#
# Set the output file path #
#==========================#
parser.add_argument('-o',f'--{args.output}',dest=args.output,nargs=1,default=None,help=
'''Write results to file, can be combined with all the commands that return a result. Results are in JSON.''')

subparser = parser.add_subparsers(title="Commands",dest="command")

#==========================#
# Create new P2PKH address #
#==========================#
create_new_address = subparser.add_parser(args.create_new_address,description='Create a new private-public key pair along with its address')
create_new_address.add_argument(args.keyName,help="The name of the key (can be anything, avoid create multiple keys with the same name)",nargs=1)
create_new_address.add_argument(args.password,help="Password to lock the private key (remember it, you need it to unlock it)",nargs=1)
create_new_address.add_argument('-s',f'--{args.seed}', default=None, help="The seed used for the random generator (a specific seed produces the same address)",nargs=1)

#================================#
# Create Multi Signature Address #
#================================#
create_multisig_address = subparser.add_parser(args.create_multisig_address,description='Create a multi signature address')
create_multisig_address.add_argument(args.signaturesRequired,help="Number of required signatures to unlock UTXO",nargs=1)
create_multisig_address.add_argument(args.keyFile,nargs='+',help=
f'''The file containing the key to be used for the multi signature address funds (can be created with the command -o path {args.create_new_address}).
You can also privide the JSON result of {args.create_new_address} or name and public key pairs or any combination of the expected input formats.
''')

#======================================#
# Create a multi signature transaction #
#======================================#
create_multisig_transaction = subparser.add_parser(args.create_multisig_transaction,description=
f'''Create an unsigned multisignature transaction (Note: it needs to be signed by the owners with the command {args.sign_multisig_transaction})''')
create_multisig_transaction.add_argument(args.address,help="Address to send the transaction to",nargs=1)
create_multisig_transaction.add_argument(args.amount,help="Amount to spend",nargs=1)
create_multisig_transaction.add_argument(args.fee,help="Fee amount to pay",nargs=1)
create_multisig_transaction.add_argument(args.multisigKeyFile,nargs=1,help=
f'''The file containing the multi signature keys (can be created with -o path {args.create_multisig_address}).
You can also provide the json result of {args.create_multisig_address} in place of {args.multisigKeyFile}''')

#==================================#
# Sign multi signature transaction #
#==================================#
sign_multisig_transaction = subparser.add_parser(args.sign_multisig_transaction,description=
f'''Add a signature to a multisig transaction. Use to sign a transaction created with {args.create_multisig_transaction}.
Please note that every time someone signs the transaction, the next person needs to sign the transaction using the previous result
in order to maintain all the signatures''')
sign_multisig_transaction.add_argument(args.transactionFile,nargs=1,help=
f'''The file containing the details for the unsigned or partially signed transaction (can be created with -o path {args.create_multisig_transaction}).
You can also provide the json result of {args.create_multisig_transaction} in place of {args.transactionFile}''')
sign_multisig_transaction.add_argument(args.addressFile,nargs=1,help=
f'''The file containing the encrypted private key (can be created with -o path {args.create_new_address}) or the private key itself.
If you provide the private key itself, you must give the key name in place of {args.password}. This is important for the order of the keys.
The name of the key is defined durting the multisig address creation ({args.create_multisig_address})''')
sign_multisig_transaction.add_argument(args.password,nargs=1,help=
'''The password to decrypt the private key or if you gave the private key itself you need to set the name of the key as defined during
the multisig address generation ({args.create_multisig_address})''')

#================================#
# Decrypt and return private key #
#================================#
get_private_key = subparser.add_parser(args.get_private_key,description=
'''Decrypts a private key created with this script using the user password''')
get_private_key.add_argument(args.keyFile,nargs=1,help=
f'''Key file containing private key (can be created with -o path {args.create_new_address}).
In place of {args.keyFile} you can also put the encrypted private key string''')
get_private_key.add_argument(args.password,nargs=1,help=
'''Password used to lock the private key''')

#===================================#
# Get the signed transaction in hex #
#===================================#
get_signed_multisig_transaction = subparser.add_parser(args.get_signed_multisig_transaction,description=
'''Signs and returns the given transaction''')
get_signed_multisig_transaction.add_argument(args.transactionFile,nargs=1,help=
f'''The file containing the details for the transaction and the required signatures (can be created with -o path {args.sign_multisig_transaction})
You can also provide the json result of {args.sign_multisig_transaction} in place of {args.transactionFile}''')

#=====================#
# Get Address Balance #
#=====================#
get_address_balance = subparser.add_parser(args.get_address_balance,description=
'''Get the balance of the given address''')
get_address_balance.add_argument(args.addressFile,nargs=1,help=
f'''A result file containing an address (the file can be cerated with -o path {args.create_new_address} or -o path {args.create_multisig_address})
You can also set the address string itself''')

#==================#
# Send transaction #
#==================#
send_transaction = subparser.add_parser(args.send_transaction,description=
'''Sends the transaction to the network''')
send_transaction.add_argument(args.transactionFile,nargs=1,help=
f'''A file containing the signed transaction (the file can be cerated with commands -o path {args.get_signed_multisig_transaction} or -o path {args.get_signed_multisig_transaction})
You can also provide the signed transaction in raw hex format in place of {args.transactionFile}''')

try:
    #Gather given arguments :
    inputs = parser.parse_args()

    #Create the bitcoin instance :
    bitcoin = Bitcoin(
        getArg(inputs,args.network),
        getArg(inputs,args.rpcuser),
        getArg(inputs,args.rpcpass),
        getArg(inputs,args.host))

    #Gather output path :
    savePath = getArg(inputs,args.output)

#Execute command based on given arguments :
    if inputs.command == args.create_multisig_address:
        settings = commands.createMultisigAddress(
            getArg(inputs,args.signaturesRequired),
            getArg(inputs,args.keyFile,True),
            bitcoin,
            savePath)
        pprint(settings)

    elif inputs.command == args.create_new_address:
        address = commands.createNewAddress(
            getArg(inputs,args.keyName),
            getArg(inputs,args.password),
            getArg(inputs,args.seed),
            bitcoin,
            savePath)
        pprint(address)

    elif inputs.command == args.get_private_key:
        privateKey = commands.getPrivateKey(
            getArg(inputs,args.keyfile),
            getArg(inputs,args.password)
        )
        print(privateKey)

    elif inputs.command == args.create_multisig_transaction:
        transaction = commands.createMultisigTransaction(
            getArg(inputs,args.address),
            getArg(inputs,args.amount),
            getArg(inputs,args.fee),
            getArg(inputs,args.multisigKeyFile),
            bitcoin,
            savePath)
        pprint(transaction)

    elif inputs.command == args.sign_multisig_transaction:
        transaction = commands.signMultisigTransaction(
            getArg(inputs,args.transactionFile),
            getArg(inputs,args.addressFile),
            getArg(inputs,args.password),
            bitcoin,
            savePath)
        pprint(transaction)

    elif inputs.command == args.get_signed_multisig_transaction:

        signedTransaction = commands.createdSignedTransaction(
            getArg(inputs,args.transactionFile),
            bitcoin,
            savePath)
        print(signedTransaction)

    elif inputs.command == args.get_address_balance:

        UTXOs = commands.getAddressBalance(
            getArg(inputs,args.addressFile),
            bitcoin)
        pprint(UTXOs)

    elif inputs.command == args.send_transaction:

        results = commands.sendTransaction(
            getArg(inputs,args.transactionFile),
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