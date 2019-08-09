Author: Blake McCollough
Contact: blakemccollough@yahoo.com
Description:
	BugAnalyzeConvert.exe takes a Wireshark log (saved as a K12 .txt file) as input and outputs the same data but in a format
	acceptable for CDBugAnalyzer. The output is stored as CDBug.log in the path as the .exe. A client and server socket is required to specify which
	is outgoing or incoming packets, this means that only packets with the specified TCP/IP are stored.
	
	NOTE: The application takes a while for larger files. The program may not respond for as long as 10 minutes.