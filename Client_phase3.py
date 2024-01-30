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

stuID = int(input("\nEnter the student ID : "))
stuIDB = 18007
curve = Curve.get_curve('secp256k1')

# Server's Identitiy public key
IKey_Ser = Point(13235124847535533099468356850397783155412919701096209585248805345836420638441, 93192522080143207888898588123297137412359674872998361245305696362578896786687, curve)

################################  Phase-1 Digital Signature Scheme #################################

def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P + h*QA
    v = V.x%n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    if h_ == h:
        return True
    else:
        return False

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

def signature_verification_bytes(message_bytes, signature, QA):
    h, s = signature
    V = s * curve.generator + h * QA
    v = V.x % curve.order
    v_bytes = v.to_bytes((v.bit_length() + 7) // 8, byteorder="big")
    #message_bytes = message.to_bytes((message.bit_length() + 7) // 8, byteorder="big")
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

############## The new functions of phase 3 ###############

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsgPH3(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())

# Send a message to client idB
def SendMsg(idA, idB, otkID, msgid, msg, ikx, iky, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "IK.X": ikx, "IK.Y": iky, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())    


# Receive KeyBundle of the client stuIDB
def reqKeyBundle(stuID, stuIDB, h, s):
    key_bundle_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's Key Bundle ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqKeyBundle"), json=key_bundle_msg)
    print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['IK.X'], res['IK.Y'], res['SPK.X'], res['SPK.Y'], res['SPK.H'], res['SPK.s'], res['OTK.X'], res['OTK.Y']
        
    else:
        return -1, 0, 0, 0, 0, 0, 0, 0, 0


#Status control. Returns #of messages and remained OTKs
def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']


############## The new functions of BONUS ###############

# Exchange partial keys with users 2 and 4
def ExchangePartialKeys(stuID, z1x, z1y, h, s):
    request_msg = {'ID': stuID, 'z1.x': z1x, 'z1.y': z1y, 'H': h, 'S': s}
    print("Sending your PK (z) and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangePartialKeys"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['z2.x'], res['z2.y'], res['z4.x'], res['z4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0


# Exchange partial keys with user 3
def ExchangeXs(stuID, x1x, x1y, h, s):
    request_msg = {'ID': stuID, 'x1.x': x1x, 'x1.y': x1y, 'H': h, 'S': s}
    print("Sending your x and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangeXs"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['x2.x'], res['x2.y'], res['x3.x'], res['x3.y'], res['x4.x'], res['x4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0, 0, 0

# Check if your conference key is correct
def BonusChecker(stuID, Kx, Ky):
    mes = {'ID': stuID, 'K.x': Kx, 'K.y': Ky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "BonusChecker"), json=mes)
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
    # Request Pseudo-Client to send 5 messages to my inbox via server 
    PseudoSendMsgPH3(h, s)
    numMSG, numOTK, StatusMSG = Status(stuID, h, s)
    print(StatusMSG)
    if numMSG > 0 and numOTK < 10:
        print("There are some new messages, we first need to receive them then generate new OTKS to reach a total of 10 keys\n")
    if numMSG == 0 and numOTK < 10:
        print("There are no new messages so we can generate new OTKs to reach total of 10 keys\n")
    if numMSG == 0 and numOTK == 10:
        print("We don't have new messages and we have 10 OTKs no need to generate more\n")

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

def EncMsg(plain_text, nonce_, KENC):
    cipher = AES.new(KENC, AES.MODE_CTR, nonce=nonce_)
    cipher_text = cipher.encrypt(plain_text)
    return cipher_text

# Function to Decrypt and Check Messages from Pseudo-Client
def DecAndCheckMsg(messages, stuIDA, stuIDB, IKA_pr, SPKA_pr, OTKs):   
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

        print(f"\nI got this from client {stuIDB}: {receviedMsg}")

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

        # Send the result to the server
        Checker(stuIDA, stuIDB, msgID, decmsg)

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

# display the messages sent to a student
def DisplayFinalMessages(decMsgs):
    print("\nSent Messages\n==========================================")
    # Display the messages
    for msg in decMsgs:
        if msg[1] != "INVALIDHMAC":
            print(f"Message {msg[0]} - {msg[1]}")

def getKeyBundle(stuID, stuIDB, h, s):
    keyID, iKX, iKY, spkX, spkY, spkH, spkS, otkX, otkY = reqKeyBundle(stuID, stuIDB, h, s)
    keyBundle = {
        'KEYID': keyID,
        'IK.X': iKX,
        'IK.Y': iKY,
        'SPK.X': spkX,
        'SPK.Y': spkY,
        'SPK.H': spkH,
        'SPK.s': spkS,
        'OTK.X': otkX,
        'OTK.Y': otkY
    }
    return keyBundle

def SendingMsg(decMsgs, keyBundle, IKA_Pub, IKA_pr ,SPKA_pub):
    keyID = keyBundle['KEYID']
    iKX = keyBundle['IK.X']
    iKY = keyBundle['IK.Y']
    spkX = keyBundle['SPK.X']
    spkY = keyBundle['SPK.Y']
    spkH = keyBundle['SPK.H']
    spkS = keyBundle['SPK.s']
    otkX = keyBundle['OTK.X']
    otkY = keyBundle['OTK.Y']
    
    # define the keys of the receiver on the curve
    IKB = Point(iKX, iKY, curve)
    SPKB = Point(spkX, spkY, curve)
    OTKB = Point(otkX, otkY, curve)    

    print("\nVerifying the SPK...") 
    signature_tuple_SPK = (spkH, spkS)
    message = SPKB.x.to_bytes((SPKB.x.bit_length() + 7) // 8, byteorder='big') + SPKB.y.to_bytes((SPKB.y.bit_length() + 7) // 8, byteorder='big')
    isVerified = signature_verification(int.from_bytes(message, byteorder='big'), signature_tuple_SPK, IKB)
    print("\nSPK verified? True" if isVerified else "SPK verified? False")

    if isVerified:
        print("\nThe other party's OTK public key is acquired from the server...")
        EKey_Pr, EKey_Pub = key_generation()
        KENC = 0
        KHMAC = 0
        KKDF_Next = 0
        for msg in decMsgs:
            if msg[1] != "INVALIDHMAC":
                if msg[0] == 1:
                    print("\nGenerating session key / Phase 3...")
                    KS = KSGen(EKey_Pr, IKA_pr ,IKB, SPKB, OTKB)
                    print("\nGenerating the KDF chain for the encryption and the MAC value generation")
                    KENC, KHMAC, KKDF_Next  = KDFChainGen(KS)
                else: 
                    print("\nGenerating the KDF chain for the encryption and the MAC value generation")
                    KENC, KHMAC, KKDF_Next  = KDFChainGen(KKDF_Next)

                nonce = Random.get_random_bytes(8)
                cipher_text = EncMsg(msg[1],nonce,KENC)                
                MAC = HMAC.new(KHMAC, cipher_text, SHA256).digest()
                msg_to_send = nonce + cipher_text + MAC # nonce∥ciphertext∥MAC
                print(msg_to_send)
                msg_to_send = int.from_bytes(msg_to_send, byteorder='big')
                print("\nSending the message to the server, so it would deliver it to pseudo-client/user whenever it is active...\n")
                # A refers to the receiver and B refers to the sender in phase 2 but here named as otherwise
                SendMsg(stuID, stuIDB, keyID, msg[0], msg_to_send, IKA_Pub.x, IKA_Pub.y, EKey_Pub.x, EKey_Pub.y)
                print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

############## The new functions of BONUS ###############

# Exchange partial keys with users 2 and 4
def ExchangePartialKeys(stuID, z1x, z1y, h, s):
    request_msg = {'ID': stuID, 'z1.x': z1x, 'z1.y': z1y, 'H': h, 'S': s}
    print("Sending your PK (z) and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangePartialKeys"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['z2.x'], res['z2.y'], res['z4.x'], res['z4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0


# Exchange partial keys with user 3
def ExchangeXs(stuID, x1x, x1y, h, s):
    request_msg = {'ID': stuID, 'x1.x': x1x, 'x1.y': x1y, 'H': h, 'S': s}
    print("Sending your x and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangeXs"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['x2.x'], res['x2.y'], res['x3.x'], res['x3.y'], res['x4.x'], res['x4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0, 0, 0

# Check if your conference key is correct
def BonusChecker(stuID, Kx, Ky):
    mes = {'ID': stuID, 'K.x': Kx, 'K.y': Ky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "BonusChecker"), json=mes)
    print(response.json())

def signature_generation_bonus(z1, sA):
    k = randint(1, curve.order - 2) 
    R = k * curve.generator
    r = R.x % curve.order
    
    # Convert z1.x and z1.y to bytes
    z1_x_bytes = z1.x.to_bytes((z1.x.bit_length() + 7) // 8, byteorder='big')
    z1_y_bytes = z1.y.to_bytes((z1.y.bit_length() + 7) // 8, byteorder='big')
    z1_bytes = z1_x_bytes + z1_y_bytes
    
    # Create the message to hash
    rm = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big') + z1_bytes
    hashVal = SHA3_256.new(rm)
    h = int(hashVal.hexdigest(), 16) % curve.order
    
    s = (k - sA * h) % curve.order
    return h, s

############################################### Main ########################################
            
print("\nGenerating Identity Key Pair, Signed Pre-Key Pair and One-time Pre-key for Phase-3")

#Generate Identity Key Pair
print("\nGenerating Identity Key Pair")
IKey_Pr, IKey_Pub = key_generation()
print("Identitiy Key is created")
print(f"Identity Private Key: {IKey_Pr}")
print(f"Identity Public Key : {IKey_Pub}")

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

# Sign Student ID
print(f"Signing my stuID with my private IK")
signature_tuple_ID = signature_generation(stuID, IKey_Pr)

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

print("Signature of my ID number is:")
print(f"Signature (h): {signature_tuple_ID[0]}")
print(f"Signature (s): {signature_tuple_ID[1]}")

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

# Send Registration Message to Server, IKRegReq(h, s, x, y)
print("Sending signature and my IKEY to server via IKRegReq() function in json format")
IKRegReq(signature_tuple_ID[0], signature_tuple_ID[1], IKey_Pub.x, IKey_Pub.y)

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

# Get Authentication from Server
code = int(input("Enter the code received from the email: "))

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

print("Sending the verification code to server via IKRegVerify() function in json format")
IKRegVerify(code) 

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

# Registration of SPK
print("Generating SPK...")
SPKey_Pr, SPKey_Pub = key_generation()  # Generate Signed Pre-key Pair
print(f"Signed Pre-key Private Key : {SPKey_Pr}")
print(f"Signed Pre-key Public Key : {SPKey_Pub}")

xy_bytes = SPKey_Pub.x.to_bytes((SPKey_Pub.x.bit_length() + 7) // 8, byteorder='big') + SPKey_Pub.y.to_bytes((SPKey_Pub.y.bit_length() + 7) // 8, byteorder='big')

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

signature_tuple_SPK = signature_generation(int.from_bytes(xy_bytes, byteorder='big'), IKey_Pr)
print("Signature of SPK is:")
print(f"Signature (h): {signature_tuple_SPK[0]}")
print(f"Signature (s): {signature_tuple_SPK[1]}")

# Sending signed pre-key to the server to get verification
print("Sending SPK and the signatures to the server via SPKReg() function in json format...")

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

SPKReg(signature_tuple_SPK[0], signature_tuple_SPK[1], SPKey_Pub.x, SPKey_Pub.y)

# generate OTKs
OTKs = []
for i in range(0,10):
    OTK_Pr, OTK_Pub = genOTK(i, IKey_Ser, SPKey_Pr) 
    OTKs.append([i,OTK_Pub,OTK_Pr])

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

print("Checking the inbox for incoming messages")

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

print("Before starting a communication we make a status control...")
print("If there are no OTKs left we first check if there are any new messages waiting")
print("If there exits any we first receive from the server them then regenerate new OTKs\n")
numMSG, numOTK, StatusMSG = Status(stuID, signature_tuple_ID[0], signature_tuple_ID[1])
print(StatusMSG)
if numMSG > 0 and numOTK < 10:
    print("There are some new messages, we first need to receive them then generate new OTKS to reach a total of 10 keys\n")
if numMSG == 0 and numOTK < 10:
    print("There are no new messages so we can generate new OTKs to reach total of 10 keys\n")
if numMSG == 0 and numOTK == 10:
    print("We don't have new messages and we have 10 OTKs no need to generate more\n")

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

# dowload the messages and save them into an array
Messages = DownloadMsg(signature_tuple_ID[0], signature_tuple_ID[1])

# A refers to the receiver and B refers to the sender
decMsgs = DecAndCheckMsg(Messages, stuID, stuIDB, IKey_Pr, SPKey_Pr,OTKs)

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

DisplayFinalMessageBlock(signature_tuple_ID[0], signature_tuple_ID[1] , decMsgs)

numMSG, numOTK, StatusMSG = Status(stuID, signature_tuple_ID[0], signature_tuple_ID[1])
print("\n",StatusMSG)
if numMSG > 0 and numOTK < 10:
    print("There are some new messages, we first need to receive them then generate new OTKS to reach a total of 10 keys\n")
if numMSG == 0 and numOTK < 10:
    print("There are no new messages so we can generate new OTKs to reach total of 10 keys\n")
    for i in range(0, 10 - numOTK):
        OTK_Pr, OTK_Pub = genOTK(i, IKey_Ser, SPKey_Pr) 
        OTKs[i] = [i,OTK_Pub,OTK_Pr]
if numMSG == 0 and numOTK == 10:
    print("We don't have new messages and we have 10 OTKs no need to generate more\n")

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

print("Signing The stuIDB of party B with my private IK...")
stuIDB = int(input("\nEnter the student ID of the new receiver: "))  #29554 #18007
print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
signature_tuple_IDB = signature_generation(stuIDB, IKey_Pr) 

keyBundle = getKeyBundle(stuID, stuIDB, signature_tuple_IDB[0], signature_tuple_IDB[1])
print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
print("\nSending the received messages back to the pseudo-client..")
SendingMsg(decMsgs, keyBundle, IKey_Pub, IKey_Pr,SPKey_Pub)
DisplayFinalMessages(decMsgs)

################################ BONUS  #############################


print("\n########## BONUS ###################\n")

z1 = IKey_Pub
r1 = IKey_Pr

print("Generating my partial conference key")
print("Signing my pratial conference key")
h, s = signature_generation_bonus(z1, r1)

#IKRegReq(h, s, z1.x, z1.y)

z2x, z2y, z4x, z4y = ExchangePartialKeys(stuID, z1.x, z1.y, h, s)
print("Exchanging partial keys\n")
z2 = Point(curve=curve, x=z2x, y=z2y)
z4 = Point(curve=curve, x=z4x, y=z4y)

# Calculate x1
x1 = z1 + z2 + z4
print("calculated x1:", x1)

# Sign x1 using your identity key IKA
print("Signing x1")
h, s = signature_generation_bonus(x1, r1)

# Send x1 to the server using the ExchangeXs function
x2x, x2y, x3x, x3y, x4x, x4y = ExchangeXs(stuID, x1.x, x1.y, h, s)
x2= Point(curve=curve, x=x2x, y=x2y)
x3 = Point(curve=curve, x=x3x, y=x3y)
x4 = Point(curve=curve, x=x4x, y=x4y)
print("exchanging X's\n")

K = z4*r1 + x1*3 + x2*2 + x3
BonusChecker(stuID, K.x, K.y)

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