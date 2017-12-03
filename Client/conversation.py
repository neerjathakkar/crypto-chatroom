import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
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
        # You can use this function to initiate your key exchange
        # Useful stuff that you may need:
        # - name of the current user: self.manager.user_name
        # - list of other users in the converstaion: list_of_users = self.manager.get_other_users()
        # You may need to send some init message from this point of your code
        # you can do that with self.process_outgoing_message("...") or whatever you may want to send here...

        # Since there is no crypto in the current version, no preparation is needed, so do nothing
        # replace this with anything needed for your key exchange

        # random 256 bit key
        # master_key = get_random_bytes(32)
        # list_of_users = self.manager.get_other_users()
        # for user in list_of_users:
        #     self.process_outgoing_message("FIRST" + master_key, False)
        #

        # generate key pairs for each member

        #for each other member
        # generate public/private key pair
        #
        # send message containing K encrypted with their public key
        # print "SETTING UP CONVERSATION"




        pass


    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        '''
        Process incoming messages
        :param msg_raw: the raw message
        :param msg_id: ID of the message
        :param owner_str: user name of the user who posted the message
        :param user_name: name of the current user
        :param print_all: is the message part of the conversation history?
        :return: None
        '''

        # print msg_id

        keystring = "abcdefghijklmnop"

        chars = msg_raw[:2]
        msg_raw = msg_raw[2:]


        if chars != SETUP:


            # # process message here
            # # example is base64 decoding, extend this with any crypto processing of your protocol
            #
            # len_msg + header + ("0" * AES.block_size) + encrypted + mac
            len_msg = msg_raw[:16]
            int_len_msg = int(len_msg)
            # print "len message = " + len_msg
            timestamp = msg_raw[16:42]
            # print "timestamp: " + timestamp
            msg_id = msg_raw[42:53]
            # print "msg id: " + msg_id
            iv = msg_raw[53: 53+ AES.block_size]
            # print "counter: " + iv
            # print str(self.recent_msg_ids)
            if msg_id in self.recent_msg_ids:

                timestamp1 = datetime.datetime.strptime(self.recent_msg_ids[msg_id], "%Y-%m-%d %H:%M:%S.%f")
                timestamp2 = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")

                # max = most recent
                if max(timestamp1, timestamp2) == timestamp1:
                    pass
                else:
                    print "message rejected, it is replayed"

            else:
                self.recent_msg_ids[msg_id] = timestamp


            enc_msg = msg_raw[53+ AES.block_size: 53+ AES.block_size + int_len_msg]
            # print "encrypted msg : " + enc_msg
            rec_mac = msg_raw[53+ AES.block_size + int_len_msg:]
            # print "mac: " + rec_mac

            # intialize counter with the value read
            ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))

            # create AES cipher object
            cipher = AES.new(keystring, AES.MODE_CTR, counter=ctr)

            decrypted_msg = cipher.decrypt(enc_msg)
            # print "decrypted: " + decrypted_msg

            # generate mac from message

            #pad msg if needed, padding sheme is x01 x00 ... x00

            header = timestamp + msg_id

            total_data = header + decrypted_msg

            p_length = AES.block_size - (len(total_data)) % AES.block_size

            if p_length >= 1:
                total_data = total_data + chr(1)
                p_length -= 1
            while p_length > 0:
                total_data = total_data + chr(0)
                p_length -= 1

            # append message blocks X1...n and compute the MAC (as last block of CBC encryption of A|X)

            # create AES CBC cipher object
            cbc_cipher = AES.new(keystring, AES.MODE_CBC, iv)
            total_encrypted_data = cbc_cipher.encrypt(total_data)

            mac = total_encrypted_data[-1 * AES.block_size:]
            # print "mac should be last block: "
            # print mac
            # this should be further encrypted by XORing E_K(N|Ctr0) to it
            # (where E_K() is ECB encryption of the single block N|ctr(0)
            ecb_cipher = AES.new(keystring, AES.MODE_ECB)

            enc_nonce = ecb_cipher.encrypt(iv)

            mac = self.xor_two_str(mac, enc_nonce)

            # print "xored mac: " + mac

            accepted = True

            # check if received mac = mac generated
            i = 0
            while i < len(rec_mac) - 1:
                # print "checking mac"
                if mac[i] != rec_mac[i]:
                    accepted = False
                i = i + 1

            if accepted:
                # print message and add it to the list of printed messages
                self.print_message (
                    msg_raw=decrypted_msg,
                    owner_str=owner_str
                )

            else:
                print "mac was rejected for message: " + decrypted_msg

        elif chars == SETUP:
            print "processing setup message"
            print msg_raw


    def process_outgoing_message(self, msg_raw, originates_from_console=False, setup_message=False):


        # first initialize N = random and ctr = 0
        # then put timestamp and other stuff we dont want to encrypt in blocks A1...m


        nonce = get_random_bytes(AES.block_size)
        ctr = 0
        #iv = str(nonce) + str(ctr)
        iv = "0" * AES.block_size



        '''
        Process an outgoing message before Base64 encoding

        :param msg_raw: raw message
        :return: message to be sent to the server
        '''
        keystring = "abcdefghijklmnop"

        # if the message has been typed into the console, record it, so it is never printed again during chatting
        if originates_from_console == True:
            # message is already seen on the console
            m = Message(
                owner_name=self.manager.user_name,
                content=msg_raw
            )
            self.printed_messages.append(m)

        # process outgoing message here
		# example is base64 encoding, extend this with any crypto processing of your protocol
        # pad msg if needed, padding sheme is x01 x00 ... x00

        msg = msg_raw
        msg_id = get_random_bytes(11)
        # print "msg id: " + msg_id
        timestamp = datetime.datetime.now()
        # print "timestamp: " + str(timestamp)
        header = str(timestamp) + msg_id

        total_data = header + msg

        # print "header: " + header

        p_length = AES.block_size - (len(total_data)) % AES.block_size

        if p_length >= 1:
            total_data = total_data + chr(1)
            p_length -= 1
        while p_length > 0:
            total_data = total_data + chr(0)
            p_length -= 1


        # append message blocks X1...n and compute the MAC (as last block of CBC encryption of A|X)



        # print "A|X: " + total_data

        # create AES CBC cipher object
        cbc_cipher = AES.new(keystring, AES.MODE_CBC, "0" * AES.block_size)
        total_encrypted_data = cbc_cipher.encrypt(total_data)
        # print "Enc(A|X): "
        # print total_encrypted_data
        mac = total_encrypted_data[-1 * AES.block_size:]
        # print "mac should be last block: "
        # print mac
        # this should be further encrypted by XORing E_K(N|Ctr0) to it
        # (where E_K() is ECB encryption of the single block N|ctr(0)
        ecb_cipher = AES.new(keystring, AES.MODE_ECB)

        enc_nonce = ecb_cipher.encrypt("0" * AES.block_size)

        mac = self.xor_two_str(mac, enc_nonce)

        # print "xored mac: " + mac
        # print "mac created: " + mac
        # print "length of mac: " + str(len(mac))

        len_msg = str(len(msg))
        while len(len_msg) < 16:
            len_msg = "0" + len_msg

        # print "len msg = " + len_msg

        # Finally encrypt in CTR mode the blocks X1...n and append the encrypted MAC to get the final output

        # initialize CTR mode, encrypt message
        ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
        ctr_cipher = AES.new(keystring, AES.MODE_CTR, counter=ctr)
        total_msg = header + msg + mac

        encrypted = ctr_cipher.encrypt(msg)

        # print "encrypted message: " + encrypted
        #
        # print "length of msg enc: " + str(len(encrypted))

        # format message header


        # get final message
        encoded_msg = "00" + len_msg + header + ("0" * AES.block_size) + encrypted + mac

        # print "message to send: " + encoded_msg

        # post the message to the conversation
        self.manager.post_message_to_conversation(encoded_msg)

        return encoded_msg

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
