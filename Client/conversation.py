import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

from message import Message
import base64
from time import sleep
from threading import Thread

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

        keystring = "abcdefghijklmnop"

        # process message here
		# example is base64 decoding, extend this with any crypto processing of your protocol


        len_mac = msg_raw[:2]
        iv = msg_raw[2:18]

        # intialize counter with the value read
        ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))

        # create AES cipher object
        cipher = AES.new(keystring, AES.MODE_CTR, counter=ctr)

        decrypted = cipher.decrypt(msg_raw[18:])

        # time stamp is 26 characters
        timestamp = decrypted[0:26]
        print timestamp
        # message id is 11 characters
        msg_id = decrypted[26:37]
        print msg_id
        # mac is the last 16 characters
        # msg is everything in between

        msg = decrypted[37:-16]
        print msg
        rec_mac = decrypted[-16:]



        # generate mac from message

        # pad msg if needed, padding sheme is x01 x00 ... x00

        p_length = AES.block_size - (len(msg)) % AES.block_size

        if p_length >= 1:
            msg = msg + chr(1)
            p_length -= 1
        while p_length > 0:
            msg = msg + chr(0)
            p_length -= 1

        # initialize iv as full block of x00s

        iv = ""
        while len(iv) < AES.block_size:
            iv = iv + chr(0)

        # create AES cipher object
        cipher = AES.new(keystring, AES.MODE_CBC, iv)

        # compute CBC MAC value
        mac = cipher.encrypt(msg)

        accepted = True
        print "length of mac received: " + str(len(rec_mac))
        print rec_mac
        print "length of mac generated: " + str(len(mac))
        print mac
        # check if received mac = mac generated
        i = 0
        while i < len(rec_mac) - 1:
            print "checking mac"
            if mac[i] != rec_mac[i]:
                accepted = False
            i = i + 1
        print "done checking mac"
        print accepted

        if accepted:
            # print message and add it to the list of printed messages
            self.print_message (
                msg_raw=msg,
                owner_str=owner_str
            )

        else:
            print "mac was rejected for message: " + msg


    def process_outgoing_message(self, msg_raw, originates_from_console=False):
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
        timestamp = datetime.datetime.now()
        header = str(timestamp) + msg_id

        p_length = AES.block_size - (len(msg)) % AES.block_size

        if p_length >= 1:
            msg = msg + chr(1)
            p_length -= 1
        while p_length > 0:
            msg = msg + chr(0)
            p_length -= 1

        # initialize iv as full block of x00s

        iv = ""
        while len(iv) < AES.block_size:
            iv = iv + chr(0)

        # create AES cipher object
        cipher = AES.new(keystring, AES.MODE_CBC, iv)

        # compute CBC MAC value
        mac = cipher.encrypt(msg)

        len_mac = str(len(mac))
        print len_mac
        # initialize CTR mode, encrypt everything
        ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
        ctr_cipher = AES.new(keystring, AES.MODE_CTR, counter=ctr)
        total_msg = header+ msg + mac
        encrypted = ctr_cipher.encrypt(total_msg)

        # format message header


        # get final message
        encoded_msg = len_mac + iv + encrypted

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
