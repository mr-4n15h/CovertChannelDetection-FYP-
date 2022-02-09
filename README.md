# Covert Storage Channels Detection
Covert channel detection using Python and ML

<img src="https://user-images.githubusercontent.com/33122280/153201881-4568d298-451e-41df-b342-59f0b872084a.png" width="90%"></img> 

In the picture above, we see a covert storage channel in a TCP segment which is hiding data inside the sequence number field. 
The sequence number field hides the data 'Hi :)' to communicate in secret. So what you maybe thinking? Two scenarios have been provided below:

>Scenario 1: An Insider Threat. 
Suppose Edward is a system-administrator at a company and is dissatisfied about his pay deductions.
He seeks revenge by stealing and selling company data to a third party. Edward and the third party
come to agreement to use covert channels to exfiltrate data by using the Exfiltration Over
Alternative Protocol technique by utilising Protocol Switching Covert Channels – where the data
is exfiltrated in different protocols, instead of just one. Before the data is exfiltrated, Edward uses the
Data Encrypted technique by encrypting the data to hide the information that is being exfiltrated,
thus making the exfiltration unnoticeable and preventing detection. To make the detection even more
difficult, Edward uses the Scheduled Transfer technique so that data exfiltration is only performed
at certain intervals or at certain times of day to blend data exfiltration traffic with regular traffic.


> Scenario 2: Controlling Compromised Systems. 
Suppose Bob is a computer programming expert and his goal is to build a DDoS network to control the systems he has compromised to do the work for him. He wants to work on the three stages in a DDoS
network: Recruitment, Infection/Exploitation, and Use phases. To recruit agent machines, he uses
the Spearphising Attachment technique by sending the malware attached to an email which
requires user execution of the attached malware. He knows that direct communication with his agent
machines will expose his IP address and his whole DDoS network; therefore, he looks into using an
indirect communication method through the use of covert channels and IRC services to hide his
identity. This will allow Bob and his agent machines to communicate indirectly without being detected; therefore, he can now use covert channels to issue commands to coordinate the DDoS attacks.


My supervisor, who is a Cybersecurity expert, presented me this idea during our first meeting; therefore, I wanted to solve it. This idea was presented to me by my supervisor since this problem still exists to this day! The current Internet design weaknesses enables this attack methodology. This project focuses on Cybersecurity, Software Engineering, Computer Networking, and other important topics in Computer Science.

Python and Machine Learning were used to detect covert storage channels in network packets. This project was voted as the best AI project at Made in Brunel Software Innovation Event 2020; therefore, it achieved the 'AI Innovation' award. I have also attached my dissertation paper, which is called '1618834.pdf' if you're further interested in my project. The dissertation paper contains information on how I tackled this project. 
