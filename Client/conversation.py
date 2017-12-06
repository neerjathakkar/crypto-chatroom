import datetime
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA, MD5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import PKCS1_PSS
from Crypto.Util import Counter

from message import Message
import base64
from time import sleep
from threading import Thread


# add constants for whether we have a setup or normal message
NORMAL = "00"
SETUP = "11"

class Conversation:
    '''
    Represents a conversation between participants
    '''
    def __init__(self, c_id, manager):
        '''
        Constructor
        :param c_id: ID of the conversation (integer)
        :param manager: instance of the ChatManager class
        :return: None
        '''
        self.id = c_id  # ID of the conversation
        self.all_messages = []  # all retrieved messages of the conversation
        self.key_messages = []
        self.printed_messages = []
        self.last_processed_msg_id = 0  # ID of the last processed message
        from chat_manager import ChatManager
        assert isinstance(manager, ChatManager)
        self.manager = manager # chat manager for sending messages
        self.run_infinite_loop = True
        self.msg_process_loop = Thread(
            target=self.process_all_messages
        ) # message processing loop
        self.msg_process_loop.start()
        self.msg_process_loop_started = True
        self.recent_msg_ids = {}
        self.public_keys = {}
        self.conversation_key = ""
        self.my_login_time = datetime.datetime.now()
        self.curr_time = self.my_login_time

    def append_msg_to_process(self, msg_json):
        '''
        Append a message to the list of all retrieved messages

        :param msg_json: the message in JSON encoding
        :return:
        '''
        self.all_messages.append(msg_json)

    def append_msg_to_printed_msgs(self, msg):
        '''
        Append a message to the list of printed messages

        :param msg: an instance of the Message class
        :return:
        '''
        assert isinstance(msg, Message)
        self.printed_messages.append(msg)

    def exit(self):
        '''
        Called when the application exists, breaks the infinite loop of message processing

        :return:
        '''
        self.run_infinite_loop = False
        if self.msg_process_loop_started == True:
            self.msg_process_loop.join()

    def process_all_messages(self):
        '''
        An (almost) infinite loop, that iterates over all the messages received from the server
        and passes them for processing

        The loop is broken when the application is exiting
        :return:
        '''
        while self.run_infinite_loop:
            for i in range(0, len(self.all_messages)):
                current_msg = self.all_messages[i]
                msg_raw = ""
                msg_id = 0
                owner_str = ""
                try:
                    # Get raw data of the message from JSON document representing the message
                    msg_raw = base64.decodestring(current_msg["content"])
                    # Base64 decode message
                    msg_id = int(current_msg["message_id"])
                    # Get the name of the user who sent the message
                    owner_str = current_msg["owner"]
                except KeyError as e:
                    print "Received JSON does not hold a message"
                    continue
                except ValueError as e:
                    print "Message ID is not a valid number:", current_msg["message_id"]
                    continue
                if msg_id > self.last_processed_msg_id:
                    # If the message has not been processed before, process it
                    self.process_incoming_message(msg_raw=msg_raw,
                                                  msg_id=msg_id,
                                                  owner_str=owner_str)
                    # Update the ID of the last processed message to the current
                    self.last_processed_msg_id = msg_id



                sleep(0.01)

    def setup_conversation(self):
        '''
        Prepares the conversation for usage
        :return:
        '''


        # generate a random key for this conversation
        conversation_key = get_random_bytes(32)
        self.conversation_key = conversation_key

        my_name = str(self.manager.user_name)

        my_key_file = open("priv_key_" + my_name, "r")
        my_private_key = RSA.importKey(my_key_file.read())

        user_list = self.manager.get_other_users()

        # import public keys of all users
        # public keys will now be stored in self.public_keys[]

        self.get_pub_keys_from_files(user_list)

        # timestamp for key generation is the time of this user's login
        timestamp = str(self.my_login_time)

        for user in user_list:

                # Alice = current user
                # Bob = user for which Alice is creating key protocol message

                # encrypt Alice's username and session key with Bob's public key
                total_message = my_name + conversation_key

                # get public key of Bob
                curr_pub_key = self.public_keys[user]

                # create cipher with Bob's public key
                cipher = PKCS1_OAEP.new(curr_pub_key)
                encrypted_msg = base64.b64encode(cipher.encrypt(total_message))

                # sign (B | Ta | PubEncKb(A | K) )

                # sign the message
                signer = PKCS1_PSS.new(my_private_key)
                h = SHA.new()

                msg_to_sign = str(user) + timestamp + encrypted_msg
                # sign
                new_data = self.md5(msg_to_sign)
                h.update(new_data)
                signature = signer.sign(h)


                # Send to Bob: (Ta | EncKb(A | K) | SigKa(B|Ta|PubEncKb(A|K)) )
                final_msg = timestamp + encrypted_msg + signature

                self.process_outgoing_message(final_msg, setup_message=True)

    def get_pub_keys_from_files(self, user_list):
        for user in user_list:
            public_key_file = open("pub_key_" + user, "r")
            pub_key = RSA.importKey(public_key_file.read())
            self.public_keys[user] = pub_key

    def process_incoming_message(self, msg_raw, msg_id, owner_str):

        if msg_id in self.key_messages:
            return

        '''
        Process incoming messages
        :param msg_raw: the raw message
        :param msg_id: ID of the message
        :param owner_str: user name of the user who posted the message
        :param user_name: name of the current user
        :param print_all: is the message part of the conversation history?
        :return: None
        '''

        keystring = self.conversation_key

        chars = msg_raw[:2]
        msg_raw = msg_raw[2:]


        if chars != SETUP:
            # Process a normal message

            # Length of the message
            len_msg = msg_raw[:16]
            int_len_msg = int(len_msg)

            # Get timestamp
            timestamp = msg_raw[16:42]

            # Get message id
            msg_id = msg_raw[42:53]

            # Check for replay:
            if msg_id in self.recent_msg_ids:
                # message rejected, it is replayed
                return
            else:
                # add message id to list of accepted message ids
                self.recent_msg_ids[msg_id] = timestamp

            header = timestamp + msg_id

            # Get nonce
            nonce = msg_raw[53: 53+ 8]

            # Obtain encrypted message
            enc_msg = msg_raw[53+ 8: 53+ 8 + int_len_msg]

            # Obtain MAC value
            rec_mac = msg_raw[53+ 8 + int_len_msg:]

            # Initialize counter with the nonce value read
            iv = "0" * AES.block_size
            ctr = Counter.new(64, prefix=nonce, initial_value=0)

            # create AES cipher object
            cipher = AES.new(keystring, AES.MODE_CTR, counter=ctr)

            # Decrypt the message
            decrypted_msg = cipher.decrypt(enc_msg)

            # generate MAC from decrypted message
            # pad msg if needed, padding scheme is x01 x00 ... x00
            total_data = header + decrypted_msg

            p_length = AES.block_size - (len(total_data)) % AES.block_size

            if p_length >= 1:
                total_data = total_data + chr(1)
                p_length -= 1
            while p_length > 0:
                total_data = total_data + chr(0)
                p_length -= 1

            # Append message blocks X1...n and compute the MAC (as last block of CBC encryption of A|X)

            # create AES CBC cipher object
            cbc_cipher = AES.new(keystring, AES.MODE_CBC, iv)
            total_encrypted_data = cbc_cipher.encrypt(total_data)

            mac = total_encrypted_data[-1 * AES.block_size:]

            # Further encrypt MAC by XORing E_K(N|Ctr0) to it, (where E_K() is ECB encryption of the single block N|ctr(0)
            ecb_cipher = AES.new(keystring, AES.MODE_ECB)

            # Pad the nonce a with block of 0s
            enc_nonce = ecb_cipher.encrypt(nonce + (chr(0) * 8))

            mac = self.xor_two_str(mac, enc_nonce)

            accepted = True

            # check if received MAC = MAC generated
            i = 0
            while i < len(rec_mac) - 1:
                if mac[i] != rec_mac[i]:
                    accepted = False
                i = i + 1

            if accepted:
                # Print message and add it to the list of printed messages
                self.print_message (
                    msg_raw=decrypted_msg,
                    owner_str=owner_str
                )

            else:
                # MAC was rejected
                return

        elif chars == SETUP:
            # Process a key exchange message

            timestamp = msg_raw[:26]

            # Don't process a key message that was sent before we logged in
            if self.is_time_earlier(timestamp, str(self.my_login_time)):
                return

            # Add message id to list of key setup messages already processed,
            # so we don't process it again during this conversation
            self.key_messages.append(msg_id)


            # Don't process key setup message that we generated
            if (str(owner_str) != str(self.manager.user_name)):

                timestamp = msg_raw[:26]
                msg_raw = msg_raw[26:]
                enc_msg = msg_raw[:172]
                signed_data = msg_raw[172:]
                pubkey = self.public_keys[str(owner_str)]
                verifier = PKCS1_PSS.new(pubkey)

                # Data to sign: (B | Ta | Enc(A|K))
                cert_data = str(self.manager.user_name) + timestamp + enc_msg

                h = SHA.new()
                h.update(self.md5(cert_data))

                # Check that received signature is valid and timestamp is valid
                if verifier.verify(h, signed_data):
                    valid_sig = True
                else:
                    valid_sig = False

                if valid_sig and self.is_time_earlier(str(self.curr_time), str(timestamp)):
                    # This is a valid key exchange, we can decrypt and obtain session key

                    # Update this timestamp as most recent timestamp received
                    self.curr_time = timestamp

                    # Encrypted message = (sender's name + session key) encrypted with my public key

                    my_key_file = open("priv_key_" + str(self.manager.user_name), "r")
                    my_private_key = RSA.importKey(my_key_file.read())

                    cipher = PKCS1_OAEP.new(my_private_key)
                    decoded_msg = base64.b64decode(enc_msg)
                    decrypted_message = cipher.decrypt(decoded_msg)


                    # Check if first part of decrypted message contains sender's name
                    # If it is, the rest of the message contains the session key
                    if decrypted_message[:len(str(owner_str))] == str(owner_str):
                        self.conversation_key = decrypted_message[len(str(owner_str)):]

                    return
                else:
                    # This is an invalid key exchange
                    return


    def process_outgoing_message(self, msg_raw, originates_from_console=False, setup_message=False):

        if not setup_message:
            '''
             Process an outgoing message before Base64 encoding
                :param msg_raw: raw message
                :return: message to be sent to the server
                
            '''
            # first initialize N = random and ctr = 0
            # then put timestamp and associated data we don't want to encrypt in blocks A1...m

            nonce = get_random_bytes(8)
            keystring = self.conversation_key

            # if the message has been typed into the console, record it, so it is never printed again during chatting
            if originates_from_console == True:
                # message is already seen on the console
                m = Message(
                    owner_name=self.manager.user_name,
                    content=msg_raw
                )
                self.printed_messages.append(m)


            msg = msg_raw

            # Generate random message id
            msg_id = get_random_bytes(11)

            # Get current timestamp
            timestamp = str(datetime.datetime.now())

            header = str(timestamp) + msg_id

            # Data being encrypted: (A|X)
            total_data = header + msg

            # Pad the information being encyrpted in CBC mode for the MAC

            p_length = AES.block_size - (len(total_data)) % AES.block_size

            if p_length >= 1:
                total_data = total_data + chr(1)
                p_length -= 1
            while p_length > 0:
                total_data = total_data + chr(0)
                p_length -= 1

            # append message blocks X1...n and compute the MAC (as last block of CBC encryption of A|X)

            # create AES CBC cipher object
            cbc_cipher = AES.new(keystring, AES.MODE_CBC, "0" * AES.block_size)

            # Encrypt (A|X) in AEC CBC mode
            total_encrypted_data = cbc_cipher.encrypt(total_data)

            # Obtain the MAC from the last block of the encrypted data
            mac = total_encrypted_data[-1 * AES.block_size:]

            # this should be further encrypted by XORing E_K(N|Ctr0) to it
            # (where E_K() is ECB encryption of the single block N|ctr(0)
            ecb_cipher = AES.new(keystring, AES.MODE_ECB)
            enc_nonce = ecb_cipher.encrypt(nonce + chr(0)*8)
            mac = self.xor_two_str(mac, enc_nonce)

            # Pad length of message into a 16 bit block
            len_msg = str(len(msg))
            while len(len_msg) < 16:
                len_msg = "0" + len_msg

            # Finally encrypt in CTR mode the blocks X1...n and append the encrypted MAC to get the final output

            # initialize CTR mode, encrypt message
            ctr = Counter.new(64, prefix=nonce, initial_value=0)
            ctr_cipher = AES.new(keystring, AES.MODE_CTR, counter=ctr)

            # Encrypt the message blocks
            encrypted = ctr_cipher.encrypt(msg)

            # Get final message (00 | length of message | nonce | Enc(msg) | MAC)
            encoded_msg = NORMAL + len_msg + header + nonce + encrypted + mac

            msg_to_send = encoded_msg

        else:
            # append "11" to setup messages
            msg_to_send = SETUP + msg_raw


        # post the message to the conversation
        self.manager.post_message_to_conversation(msg_to_send)

        return msg_to_send

    def print_message(self, msg_raw, owner_str):
        '''
        Prints the message if necessary

        :param msg_raw: the raw message
        :param owner_str: name of the user who posted the message
        :return: None
        '''
        # Create an object out of the message parts
        msg = Message(content=msg_raw,
                      owner_name=owner_str)
        # If it does not originate from the current user or it is part of conversation history, print it
        if msg not in self.printed_messages:
            print msg
            # Append it to the list of printed messages
            self.printed_messages.append(msg)

    def __str__(self):
        '''
        Called when the conversation is printed with the print or str() instructions
        :return: string
        '''
        for msg in self.printed_messages:
            print msg

    def get_id(self):
        '''
        Returns the ID of the conversation
        :return: string
        '''
        return self.id

    def get_last_message_id(self):
        '''
        Returns the ID of the most recent message
        :return: number
        '''
        return len(self.all_messages)

    def xor_two_str(self, a, b):
        return ''.join([hex(ord(a[i % len(a)]) ^ ord(b[i % (len(b))]))[2:] for i in range(max(len(a), len(b)))])

    def md5(self, data):
        h = MD5.new()
        h.update(data)
        #  return data
        return h.digest()


    # returns True if t1 is earlier than t2
    # returns False otherwise
    def is_time_earlier(self, t1, t2):
        timestamp1 = datetime.datetime.strptime(t1, "%Y-%m-%d %H:%M:%S.%f")
        timestamp2 = datetime.datetime.strptime(t2, "%Y-%m-%d %H:%M:%S.%f")

        # max = most recent
        return max(timestamp1, timestamp2) == timestamp2

