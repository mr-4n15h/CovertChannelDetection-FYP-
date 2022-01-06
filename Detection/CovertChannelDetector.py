from scapy.layers.inet import TCP
from scapy.layers.inet import IP
from scapy.all import *
from time import sleep
from scapy.all import sniff
from sklearn.externals.joblib import load
import pickle
import os

#############################################################################################
# The TCP flags
flags = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}
#############################################################################################

#############################################################################################
# The list below will store all packets that were predicted to have a covert storage channel
communications = []
#############################################################################################

#############################################################################################
# The constant below specifies the number of packets to sniff
total_packets_to_sniff = 1000


#############################################################################################

#############################################################################################
# The helper functions that will be used to print messages to the screen and read inputs from the user

def print_technique_to_detect_banner():
    print('Enter 1 to detect Covert_TCP IP ID technique')
    print('Enter 2 to detect Covert_TCP TCP SEQ technique')
    print('Enter 3 to detect Covert_TCP ACK Bounce technique')
    print('Enter 4 to detect NCovert TCP SEQ technique')
    print('Enter 5 to detect NCovert TCP ACK Bounce technique')


def print_banner():
    sleep(.5)
    print('Covert Storage Channel Detection Tool')


def read_choice():
    print('Enter 1 to check for covert storage channels in real-time using a packet sniffer, or 2 to check for '
          'covert storage channels in a WireShark capture file')
    choices = ['Real Time Detection', 'WireShark Capture File Detection']
    detection_choice = -1
    while detection_choice not in [1, 2]:
        print('Enter detection technique: ', end='')
        try:
            detection_choice = int(input())
            if detection_choice < 1 or detection_choice > 2:
                print('Invalid choice entered! Please enter 1 or 2!')
            else:
                print(f'Selected choice: {choices[detection_choice - 1]}')
                return detection_choice
        except ValueError:
            print('Please enter an integer value!')


def read_technique_to_detect(low_bound=0, upper_bound=0):
    detection_choice = -1
    while detection_choice not in list(range(low_bound, upper_bound + 1)):
        print('Enter detection technique: ', end='')
        try:
            detection_choice = int(input())
            if detection_choice < low_bound or detection_choice > upper_bound:
                print(f'Invalid choice entered! Please enter an integer between {low_bound} and {upper_bound}!')
            else:
                return detection_choice
        except ValueError:
            print('Please enter an integer value!')


#############################################################################################

#############################################################################################
# The Trained Models
def load_ip_id_model():
    return pickle.load(open('Models//Covert_tcp IP ID//covert_tcp_ip_id_svm_model', 'rb'))


def load_covert_tcp_seq_model():
    return pickle.load(open('Models/Covert_tcp TCP SEQ//covert_tcp_seq_nb_model', 'rb'))


def load_covert_tcp_ack_bounce_model():
    return pickle.load(open('Models//Covert_tcp ACK Bounce//covert_tcp_ack_bounce_lr_model', 'rb'))


def load_ncovert_tcp_seq_model():
    return pickle.load(open('Models//NCovert TCP SEQ//ncovert_tcp_seq_lr_model', 'rb'))


def load_ncovert_tcp_ack_bounce_model():
    return pickle.load(open('Models//NCovert ACK Bounce//ncovert_ack_bounce_nb_model', 'rb'))


#############################################################################################

#############################################################################################
# The trained models for the different detection techniques

# Use the SVM model with RBF kernel to detect IP ID covert storage channels
# This model has a very high accuracy and can pick up covert packets
def process_ip_id(packet):
    # Load the scaler used to train the SVM model
    ip_id_scaler = load('Scalers//Covert_tcp IP ID//scaler_covert_tcp_ip_id_svm_model.bin')
    # Load the IP ID SVM model
    ip_id_model = load_ip_id_model()
    # Extract the necessary features from the passed packet
    packet_id = packet['IP'].id
    packet_checksum = packet['IP'].chksum
    packet_df_flag = packet['IP'].flags.DF
    source = packet['IP'].src
    destination = packet['IP'].dst
    # Build a list containing the features
    features = [[packet_id, packet_df_flag, packet_checksum]]
    # Scale the features and predict whether the packet has a covert channel or not
    # If result is not 0, then it is predicted to have a covert channel
    result = ip_id_model.predict(ip_id_scaler.transform(features))
    if result:
        print('Covert channel detected in ', end=' ')
        print(features, end='; ')
        # Extract the hidden data inside the IP ID field
        hidden_data = chr(packet_id // 256)
        print(f'Hidden data was \'{hidden_data}\'; Sent by {source} to {destination}')
        return [source, destination, hidden_data]
    else:
        print('No covert channel detected in ', end=' ')
        print(features, end='\n')


# Use the Naive Bayes model here to detect TCP Sequence field covert storage channels
# Voting Classifier was used but it did not work due to incompatible data-types
def process_covert_tcp_seq(packet):
    # Load the scaler used to train the Naive Bayes model
    tcp_seq_scaler = load('Scalers//Covert_tcp TCP SEQ//scaler_covert_tcp_seq_nb_model.bin')
    # Load the Naive Bayes trained model
    tcp_seq_model = load_covert_tcp_seq_model()
    # Extract the necessary features from the packet that has been passed as an argument
    datagram = packet[IP]
    segment = packet[TCP]
    source = datagram.src
    destination = datagram.dst
    sequence = segment.seq
    acknowledgement = segment.ack
    segment_checksum = segment.chksum
    # The tshark library cannot extract the next sequence field in the TCP segment
    # Therefore, it needs to be computed using other fields in the packet
    datagram_len = datagram.len
    datagram_hlen = datagram.ihl
    segment_offset = segment.dataofs
    segment_len = datagram_len - ((datagram_hlen + segment_offset) * 4)
    next_sequence = sequence + segment_len
    # Check which flags were set in the TCP segment
    flags_set = [flags[x] for x in packet.sprintf('%TCP.flags%')]
    syn_flag = 'SYN' in flags_set
    # Build a list containing the features
    features = [[sequence, next_sequence, acknowledgement, segment_checksum, syn_flag]]
    # Scale the features and predict whether the segment has a covert channel or not
    scaled_features = tcp_seq_scaler.transform(features)
    result = tcp_seq_model.predict(scaled_features)
    if result:
        print('Covert channel detected in ', end=' ')
        print(features, end='; ')
        # Extract the hidden data inside the TCP sequence field
        hidden_data = chr(sequence // 16777216)
        print(f'Hidden data was \'{hidden_data}\'; Sent by {source} to {destination}')
        return [source, destination, hidden_data]
    else:
        print('No covert channel detected in ', end=' ')
        print(features, end='\n')


# Use the Logistic Regression model to detect covert storage channels in the TCP ACK field
def process_covert_tcp_ack(packet):
    # Load the scaler used to train the Logistic Regression model
    scaler = load('Scalers//Covert_tcp ACK Bounce//scaler_covert_tcp_ack_bounce_lr_model.bin')
    # Load the Logistic Regression model
    ack_model = load_covert_tcp_ack_bounce_model()
    # Extract the necessary features
    datagram = packet[IP]
    segment = packet[TCP]
    source = datagram.src
    destination = datagram.dst
    sequence = segment.seq
    acknowledgement = segment.ack
    segment_checksum = segment.chksum
    # Scapy does not have the next sequence number and len fields so calculate it using the different PDU fields
    datagram_len = datagram.len
    datagram_hlen = datagram.ihl
    segment_offset = segment.dataofs
    segment_len = datagram_len - ((datagram_hlen + segment_offset) * 4)
    next_sequence = sequence + segment_len
    # Check which flags have been set in the TCP segment
    flags_set = [flags[x] for x in packet.sprintf('%TCP.flags%')]
    syn_flag = 'SYN' in flags_set
    reset_flag = 'RST' in flags_set
    ack_flag = 'ACK' in flags_set
    # Build a list containing the features (required for prediction)
    features = [[sequence, next_sequence, acknowledgement, syn_flag, ack_flag, reset_flag, segment_checksum]]
    # Predict whether the TCP segment has a covert channel or not
    result = ack_model.predict(scaler.transform(features))
    if result:
        print('Covert channel detected in ', end=' ')
        print(features, end='; ')
        # Extract and decode the hidden data in the acknowledgement field
        hidden_data = chr(acknowledgement // 16777216)
        print(f'Hidden data was \'{hidden_data}\'; Sent by {destination} to {source}')
        return [source, destination, hidden_data]
    else:
        print('No covert channel detected in ', end=' ')
        print(features, end='\n')


# Use the Logistic Regression model to detect TCP sequence covert storage channels
def process_ncovert_tcp_seq(packet):
    # Load the scaler used to train the Logistic Regression model
    tcp_seq_scaler = load('Scalers//NCovert TCP SEQ//scaler_ncovert_tcp_seq_lr_model.bin')
    # Load the Logistic Regression Model
    tcp_seq_model = load_ncovert_tcp_seq_model()
    # Extract the necessary features required for prediction
    datagram = packet[IP]
    segment = packet[TCP]
    source = datagram.src
    destination = datagram.dst
    sequence = segment.seq
    acknowledgement = segment.ack
    segment_checksum = segment.chksum
    # Scapy does not have the next sequence number and len fields so calculate it using the different PDU fields
    datagram_len = datagram.len
    datagram_hlen = datagram.ihl
    segment_offset = segment.dataofs
    segment_len = datagram_len - ((datagram_hlen + segment_offset) * 4)
    next_sequence = sequence + segment_len
    # Check which flags have been set in the TCP datagram
    flags_set = [flags[x] for x in packet.sprintf('%TCP.flags%')]
    syn_flag = 'SYN' in flags_set
    # Build a list containing the features for prediction
    features = [[sequence, next_sequence, acknowledgement, segment_checksum, syn_flag]]
    # Scale the features before prediction
    scaled_features = tcp_seq_scaler.transform(features)
    # Predict whether or not the segment has a covert storage channel
    result = tcp_seq_model.predict(scaled_features)
    if result:
        print('Covert channel detected in ', end=' ')
        print(features, end='; ')
        # Extract and decode the hidden data in the sequence field
        # The code below builds four characters from the sequence number
        hidden_message = "".join([chr(c) for c in sequence.to_bytes(4, "big")])
        print(
            f'Hidden data was \'{hidden_message}\'; Sent by {source} to {destination}')
        return [source, destination, hidden_message]
    else:
        print('No covert channel detected in ', end=' ')
        print(features, end='\n')


# Use the Naive Bayes model to detect covert storage channels in the TCP ACK field
def process_ncovert_tcp_ack(packet):
    # Load the scaler that was used to train the Naive Bayes model
    tcp_ack_scaler = load('Scalers//NCovert ACK Bounce//scaler_ncovert_ack_bounce_nb_model.bin')
    # Load the trained Naive Bayes model
    tcp_ack_model = load_ncovert_tcp_ack_bounce_model()
    # Extract the features required for prediction from the different PDUs
    datagram = packet[IP]
    segment = packet[TCP]
    source = datagram.src
    destination = datagram.dst
    sequence = segment.seq
    acknowledgement = segment.ack
    segment_checksum = segment.chksum
    # Feature engineering step to build the next_sequence feature
    datagram_len = datagram.len
    datagram_hlen = datagram.ihl
    segment_offset = segment.dataofs
    segment_len = datagram_len - ((datagram_hlen + segment_offset) * 4)
    next_sequence = sequence + segment_len
    # Check which flags have been set in the TCP segment
    flags_set = [flags[x] for x in packet.sprintf('%TCP.flags%')]
    syn_flag = 'SYN' in flags_set
    ack_flag = 'ACK' in flags_set
    reset_flag = 'RST' in flags_set
    # Build a list containing the features required for prediction
    features = [[sequence, next_sequence, acknowledgement, syn_flag, ack_flag, reset_flag, segment_checksum]]
    # Scale the features using the scaler that was used to train the Naive Bayes model
    scaled_features = tcp_ack_scaler.transform(features)
    # Predict whether the segment has a covert channel or not
    result = tcp_ack_model.predict(scaled_features)
    if result:
        print('Covert channel detected in ', end=' ')
        print(features, end='; ')
        # The receiver must subtract 1 from the acknowledgement field
        # in order to receive the truly hidden data
        acknowledgement = acknowledgement - 1
        # Extract and decode the hidden data inside the acknowledgement field
        hidden_message = "".join([chr(c) for c in acknowledgement.to_bytes(4, "big")])
        print(
            f'Hidden data was \'{hidden_message}\'; Sent by {source} to {destination}')
        return [source, destination, hidden_message]
    else:
        print('No covert channel detected in ', end=' ')
        print(features, end='\n')


#############################################################################################

#############################################################################################
# The main class that is responsible for detecting covert storage channels

class CovertChannelDetector(object):
    def __init__(self):
        self.run()
        self.technique_detection_choice = -1
        self.packets_source_choice = -1

    def initialise_sniffer(self):
        # The number of packets to sniff is controlled by the constant at the beginning of the file
        print(f'Sniffing the first {total_packets_to_sniff} packets only')
        sleep(1)
        # No iface (interface) has been set here; therefore, it will capture packets from every interface
        # However, iface can be initialised to listen to a specific interface (e.g. lo for loopback address)
        sniff(prn=self.sniff_packet, count=total_packets_to_sniff)

    def open_capture_file(self, name):
        file_exists = os.path.exists(name)
        if file_exists:
            # Read the Wireshark capture file and the packets inside it
            return rdpcap(name)
        print(f'File \'{name}\' does not exist')
        print('Terminating program now')
        exit(0)

    def sniff_packet(self, packet):
        self.process_packet(packet)

    def process_packet(self, packet):
        details = None
        if self.technique_detection_choice == 1:
            if IP in packet:
                details = process_ip_id(packet)
        else:
            if IP in packet and TCP in packet:
                if self.technique_detection_choice == 2:
                    details = process_covert_tcp_seq(packet)
                if self.technique_detection_choice == 3:
                    details = process_covert_tcp_ack(packet)
                if self.technique_detection_choice == 4:
                    details = process_ncovert_tcp_seq(packet)
                if self.technique_detection_choice == 5:
                    details = process_ncovert_tcp_ack(packet)
        # If the function returned that there was a covert packet
        if details:
            communications.append(details)

    def initialise_capture_file(self):
        file_name = str(input('Enter WireShark file name to open: '))
        self.packets_captured_file = self.open_capture_file(file_name)
        print('Running detection now')

    def run(self):
        print_banner()
        print_technique_to_detect_banner()
        self.technique_detection_choice = read_technique_to_detect(1, 5)
        self.packets_source_choice = read_choice()
        self.print_detection_banner(self.packets_source_choice)

    def print_detection_banner(self, choice):
        if choice == 1:
            print('Sniffing packets now')
            self.initialise_sniffer()
        if choice == 2:
            self.initialise_capture_file()
            sleep(1)
            print("[Source File Read]")
            print(
                f"[{len(set(packet[IP].src for packet in self.packets_captured_file if IP in packet and TCP in packet))} Source IPs Detected]")
            print(f"[{len(self.packets_captured_file)} Packets Detected]")
            print()
            self.process_captured_packets()
        if len(communications) != 0:
            self.print_all_hidden_messages()

    def process_captured_packets(self):
        for packet in self.packets_captured_file:
            self.process_packet(packet)

    def print_all_hidden_messages(self):
        print('-' * 100)
        print('\t\t\t Grouping All Possible Covert Packets Together')
        print('[+] The model likely flagged normal traffic as a covert traffic multiple times (no models are perfect)')
        # print('[+] Newline characters will be replaced by a space character to format output')
        all_source_addresses = set([packet[0] for packet in communications])
        all_unique_communications = dict()

        # Get all the unique communications between the hosts (only pick up packets predicted with covert channels)
        for host in all_source_addresses:
            all_destination_hosts = set([packet[1] for packet in communications if packet[0] == host])
            all_unique_communications[host] = all_destination_hosts

        # Print all the message the user has sent in a covert manner
        for source in all_unique_communications:
            destination_hosts = all_unique_communications[source]
            for destination_host in destination_hosts:
                print(f'=================={source} to {destination_host}===================')
                message = ''.join(
                    [packet[2] for packet in communications if packet[0] == source and packet[1] == destination_host])
                print(message)
                print(f'=' * 60)


#############################################################################################


# Main
detect = CovertChannelDetector()
