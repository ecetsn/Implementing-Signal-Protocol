import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

API_URL = 'http://harpoon1.sabanciuniv.edu:9999/'

stuID = 29554
stuIDB = 30746
curve = Curve.get_curve('secp256k1')

# Server's Identitiy public key
IKey_Ser = Point(13235124847535533099468356850397783155412919701096209585248805345836420638441, 93192522080143207888898588123297137412359674872998361245305696362578896786687, curve)

################################  Phase-1 Digital Signature Scheme #################################

def key_generation():
    sA = random.randint(1, curve.order - 2)
    QA = sA * curve.generator
    return sA, QA

def signature_generation(message , sA):
    k = randint(1, curve.order - 2) 
    R = k * curve.generator
    r = R.x % curve.order
    rm = r.to_bytes((r.bit_length()+7)//8, byteorder = 'big') + message.to_bytes((message.bit_length() + 7) // 8, byteorder="big")
    hashVal = SHA3_256.new(rm)
    h = int(hashVal.hexdigest(), 16)  % curve.order
    s = (k - sA * h) % curve.order
    return h,s

def signature_verification(message, signature, QA):
    h, s = signature
    V = s * curve.generator + h * QA
    v = V.x % curve.order
    v_bytes = v.to_bytes((v.bit_length() + 7) // 8, byteorder="big")
    message_bytes = message.to_bytes((message.bit_length() + 7) // 8, byteorder="big")
    vm = v_bytes + message_bytes
    hashVal = SHA3_256.new(vm)
    h_prime = int(hashVal.hexdigest(), 16) % curve.order
    return h == h_prime

############################### Server Communication #########################################

def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    print(response.json())

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    print(response.json())

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#Get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["IK.X"], res["IK.Y"], res["EK.X"], res["EK.Y"]

#Get the list of the deleted messages' ids.
def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

#If you decrypted the message, send back the plaintext for checking
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())

############################### OTK - HMAC Key Generation #####################################################

# Function to generate HMAC key (KHMAC)
def generate_khmac(IKey_Ser_, SPKey_Pr_):
    T = SPKey_Pr_ * IKey_Ser_   # Diffie-Hellman with SPK of the client and the IK of the server
    T_yx_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big') + \
                T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
    U = b'TheHMACKeyToSuccess' + T_yx_bytes
    hashVal = SHA3_256.new(U)
    KHMAC = hashVal.digest()
    return KHMAC 

################################### Key Generation ###############################################

def KSGen(EKB_pub,IKB_pub,IKA_pri, SPKA_pri, OTKA_pri):
    # Compute intermediate values
    T1 = IKB_pub * SPKA_pri
    T2 = EKB_pub * IKA_pri
    T3 = EKB_pub * SPKA_pri
    T4 = EKB_pub * OTKA_pri
    # Concatenate the x and y coordinates of the points
    U = T1.x.to_bytes((T1.x.bit_length() + 7) // 8, byteorder='big') + T1.y.to_bytes((T1.y.bit_length() + 7) // 8, byteorder='big') + \
        T2.x.to_bytes((T2.x.bit_length() + 7) // 8, byteorder='big') + T2.y.to_bytes((T2.y.bit_length() + 7) // 8, byteorder='big') + \
        T3.x.to_bytes((T3.x.bit_length() + 7) // 8, byteorder='big') + T3.y.to_bytes((T3.y.bit_length() + 7) // 8, byteorder='big') + \
        T4.x.to_bytes((T4.x.bit_length() + 7) // 8, byteorder='big') + T4.y.to_bytes((T4.y.bit_length() + 7) // 8, byteorder='big') + \
        b'WhatsUpDoc'
    # Compute the session key (KS) using SHA3-256
    #KS = int.from_bytes(SHA3_256.new(U).digest(), 'big') # bunu byte olarak bırakmak daha mantıklı olabilir
    KS = SHA3_256.new(U).digest()
    return KS

def KDFChainGen(KKDF): # KKDF is Ks for the first message
    KENC = SHA3_256.new(KKDF + b'JustKeepSwimming').digest()
    KHMAC = SHA3_256.new(KKDF + KENC + b'HakunaMatata').digest()
    KKDF_Next = SHA3_256.new(KENC + KHMAC + b'OhanaMeansFamily').digest()
    return KENC, KHMAC, KKDF_Next

# Generate one-time key pair
def genOTK(otkID, IKey_Ser, SPKey_Pr):
    print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
    OTK_Pr, OTK_Pub = key_generation()
    # Concatenate the public one-time key
    concat_key = OTK_Pub.x.to_bytes((OTK_Pub.x.bit_length() + 7) // 8, byteorder='big') + \
                OTK_Pub.y.to_bytes((OTK_Pub.y.bit_length() + 7) // 8, byteorder='big')

    KHMAC_OTK = generate_khmac(IKey_Ser, SPKey_Pr)

    # Generate HMAC value for the concatenated form of the one-time public keys
    hmac_value = HMAC.new(KHMAC_OTK, concat_key ,digestmod=SHA256).hexdigest()

    # Register with OTK
    OTKReg(otkID,OTK_Pub.x,OTK_Pub.y,hmac_value)

    return OTK_Pr, OTK_Pub

################################### Receiver Functions ############################################

# Function to Download 5 Messages from Pseudo-Client
def DownloadMsg(h, s):
    messages = []
    print("\nDowloading all the messages from the server...\n")
    for i in range(5):
        print(f"Message {i+1}:")
        # Request a message from the server
        idB, otkID, msgID, msg, iKX, iKY, eKX, eKY = ReqMsg(h, s)
        print()
        # Append the message to the list
        messages.append({
            'IDB': idB,
            'OTKID': otkID,
            'MSGID': msgID,
            'MSG': msg,
            'IK.X': iKX,
            'IK.Y': iKY,
            'EK.X': eKX,
            'EK.Y': eKY
        })
    return messages

# integrity
def CheckMAC(msg, HMAC_, KHMAC):
    HMAC_prime = HMAC.new(KHMAC, msg, SHA256).digest()
    if HMAC_prime == HMAC_:
        print("Hmac value is verified")
        return True
    else: 
        print("Hmac value couldn't be verified")
        return False

# confidentiality
def DecMsg(cipher_text, nonce_, KENC):
    cipher = AES.new(KENC, AES.MODE_CTR, nonce = nonce_)
    plain_text = cipher.decrypt(cipher_text)
    return plain_text

# Function to Decrypt and Check Messages from Pseudo-Client
def DecAndCheckMsg(messages, stuIDA, IKA_pr, SPKA_pr, OTKs):   
    decMsgs = []
    # sort the messages according to their Message ID
    sorted_messages = sorted(messages, key=lambda x: x['MSGID']) # just in case of messages coming in a unsorted way
    # initialize temp values 
    EKB_pub = 0
    IKB_pub = 0
    OTK_Pr = 0
    OTK_Pub = 0
    KENC = 0
    KHMAC = 0
    KKDF_Next = 0
    for msg in sorted_messages:
        print("\n+++++++++++++++++++++++++++++++++++++++++++++")
        # Extract message details
        stuIDB = msg['IDB']
        otkID = msg['OTKID']
        msgID = msg['MSGID']
        receviedMsg = msg['MSG'] # receviedMsg = nonce∥ciphertext∥MAC
        eKX = msg['EK.X']
        eKY = msg['EK.Y']
        iKX = msg['IK.X']
        iKY = msg['IK.Y']

        print("\nConverting message to bytes to decrypt it...\n")
        receviedMsg_bytes = receviedMsg.to_bytes((receviedMsg.bit_length() + 7) // 8, byteorder='big')
        print(f"Converted message is: {receviedMsg_bytes}")

        print("\nGenerating the key Ks, Kenc, & Khmac and then the HMAC value ..\n")
        # all messages in the same message block contain the same otkID and EKB.Pub information
        # therefore we only need to define them once in the first message
        if (msgID == 1):  # since in implementation, message index starts from 1 instead of 0
            EKB_pub = Point(eKX, eKY, curve) 
            IKB_pub = Point(iKX, iKY, curve) 
            OTK_Pr = OTKs[otkID][2]
            OTK_Pub = OTKs[otkID][1]
            KS = KSGen(EKB_pub,IKB_pub,IKA_pr, SPKA_pr, OTK_Pr) 
            KENC, KHMAC, KKDF_Next  = KDFChainGen(KS)
        else : 
            KENC, KHMAC, KKDF_Next  = KDFChainGen(KKDF_Next)

        # Extract the last 32 bytes as HMAC value
        HMAC = receviedMsg_bytes[-32:]
        print(f"HMAC is: {HMAC}\n")
        # Extract the rest as the plain message
        cipher_text = receviedMsg_bytes[8:-32]
        # Extract the nonce
        nonce = receviedMsg_bytes[:8]

        # decrypt the message after verifying the MAC
        decmsg = DecMsg(cipher_text, nonce, KENC) if CheckMAC(cipher_text, HMAC, KHMAC) else "INVALIDHMAC"
        if decmsg != "INVALIDHMAC" : print(f"The collected plaintext: {decmsg}\n")

        #store the decrypted messages
        decMsgs.append([msgID,decmsg])

    return decMsgs

# Function to Request Deleted Messages and Display the Final Message Block
def DisplayFinalMessageBlock(h, s , decMsgs):
    # Request the server to check for deleted messages
    deleted_messages = ReqDelMsg(h, s)
    print("\nChecking whether there were some deleted messages!!\n==========================================")
    # Display the messages
    for msg in decMsgs:
        if msg[1] != "INVALIDHMAC":
            if msg[0] not in deleted_messages:
                print(f"Message {msg[0]} - {msg[1]} - Read")
            else:
                print(f"Message {msg[0]} - Was deleted by sender - X")

# Function to Request Deleted Messages and Display the Final Message Block
def DisplayFinalMessages(decMsgs):
    # Request the server to check for deleted messages
    print("\nReceived Messages\n==========================================")
    # Display the messages
    for msg in decMsgs:
        if msg[1] != "INVALIDHMAC":
            print(f"Message {msg[0]} - {msg[1]}")

############################################### Main ########################################

IKey_Pub = Point(curve=curve, x= 0x9d12bf45ac3640d8d08ca8c7198db67b569258a04af745dd9f3166542946ddd0,
                 y=0x536d34e405da4e0c0a4f27a388218c75aa8ea8e4d666ee3e0bd81d8528390c8b)
IKey_Pr = 91211226826266738353892552971066616515851265614027797199616132892946974505236


signature_tuple_ID = (
    104155523675369917106254014760918213152147716167675169358719399642675722830363,
    69405685384196021172815426271988997563350000084266973890395564762079100351983
)

SPKey_Pub = Point(curve=curve, x= 0x6c509c746373745f616bda4ec4137f84a8382e6588ea00a1f3afc27e4756fc32   ,
                 y=0xd0d696633162df43ed325f0b27e31becb16936186bde8b8ee702f4682b30ca11)
SPKey_Pr = 32234212529418451494295479241486363428961803343711852417610179820439666003791

print()
ResetOTK(signature_tuple_ID[0], signature_tuple_ID[1])

####################################### Phase-2 ###############################################

OTKs = []
for i in range(0,10):
    OTK_Pr, OTK_Pub = genOTK(i, IKey_Ser, SPKey_Pr) 
    OTKs.append([i,OTK_Pub,OTK_Pr])

print(IKey_Pub.x)
print(OTKs[0][1].x)

wait = True
while wait:
    user_input = input("countinue? yes or no : ")
    wait = bool(user_input.lower() != 'yes')

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

print("Checking the inbox for incoming messages")

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

# dowload the messages and save them into an array
Messages = DownloadMsg(signature_tuple_ID[0], signature_tuple_ID[1])

# A refers to the receiver and B refers to the sender
decMsgs = DecAndCheckMsg(Messages, stuID, IKey_Pr, SPKey_Pr,OTKs)

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

DisplayFinalMessages(decMsgs)

exit()

################################ Deleting Keys  #############################

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

print("Trying to delete OTKs...")
h,s = signature_generation(stuID, IKey_Pr)
ResetOTK(h,s)

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

print("Trying to delete OTKs but sending wrong signatures...")
h,s = signature_generation(stuID, IKey_Pr)
ResetOTK(h+1,s+1)

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

print("Trying to delete SPK...")
h,s = signature_generation(stuID, IKey_Pr)
ResetSPK(h,s)

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

print("Trying to delete Identity Key...")
rcode = int(input("Enter the reset code : "))
ResetIK(rcode) 

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")