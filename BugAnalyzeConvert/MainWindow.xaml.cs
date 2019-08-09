using System;
using System.Windows;
using Microsoft.Win32;
using System.IO;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Controls;

namespace BugAnalyzeConvert
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        private string _megaText; //all the output will be written here first
        private string[] _delimiters; //delimiters used to seperate each packet's bytes
        private bool _problems; //is set true if a bad line is read
        private int _packetCount; //iterates when a new packet is formatted
        private List<string> _reservedData; //sometimes data is used across multiple packets, in this situation, reservedData is stored to keep track of it all (first item is total length)
        private DateTime _prevTime; //store the previous packet date so an elapsed time can be calculated
        private HeaderByteLocations _byteLocations;

        public MainWindow()
        {
            InitializeComponent();
            _megaText = "\r\n ******* Log Started: qs1com\r\n";
            _packetCount = 0;
            _prevTime = new DateTime(0);
            _delimiters = new string[] { "|", "0   " }; //things we want to split the string by
            _byteLocations = new HeaderByteLocations();
            _problems = false;
            _reservedData = new List<string>();
        }

        private void FileButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog newWindow = new OpenFileDialog();
            if(newWindow.ShowDialog() == true)
            {
                if(string.Compare(Path.GetExtension(newWindow.FileName).ToLower(), ".txt") != 0)
                {
                    MessageBox.Show("File needs to be saved as a K12 text file");
                    return;
                }
                ReadThroughFile(newWindow.FileName);
                if(_packetCount <= 0)
                {
                    MessageBox.Show("Nothing was read");
                }
                else
                {
                    DumpContentsToFile();
                }
                //Console.WriteLine(_megaText);
                Close();
            }
        }

        private void DumpContentsToFile()
        {
            if (String.IsNullOrWhiteSpace(_megaText) == true) //no contents to dump
            {
                return;
            }
            else if(_problems == true)
            {
                MessageBox.Show("Bad line was detected, data in output may be missing or corrupted");
            }

            string outputPath = "CDBug.log";
            int i = 1;
            while (File.Exists(outputPath) == true)
            {
                i = i + 1;
                outputPath = $"CDBug ({i}).log";
            }
            StreamWriter outfile = new StreamWriter(outputPath);
            outfile.WriteLine(_megaText);
            outfile.Close();
            MessageBox.Show($"Saved to {outputPath}");
        }

        //responsible for reading through given file using StreamReader
        private void ReadThroughFile(string file)
        {
            DateTime time = DateTime.Now;
            StreamReader infile = new StreamReader(file);
            string line = infile.ReadLine();
            while (line != null)
            {
                if (Regex.IsMatch(line, @"^\|0   \|(\w\w\|)*$") == true) //line MUST be in format of |0   |34|17|3b| ... |02|
                {
                    ParseHexData(line, time);
                }
                else if(Regex.IsMatch(line, @"^\d\d:\d\d:\d\d,\d\d\d,\d\d\d") == true) //checks for time as hh:mm:ss,fff,fff
                {
                    string timeLine = line.Substring(0, 16); //saves JUST time info
                    timeLine = timeLine.Remove(timeLine.LastIndexOf(','), 1); //gets rid of that pesky ','
                    time = DateTime.ParseExact(timeLine, "HH:mm:ss,ffffff", System.Globalization.CultureInfo.InvariantCulture);
                }

                line = infile.ReadLine();
            }
            infile.Close();
        }

        //first IP header byte (45) is the length of the total IP header; so 45 = 4 * 5 = 20 = 20 bytes long QUESTION: is it 20 because it's 45 or because it's 5 * 4
        //IP header protocol byte = 06 means TCP header follows after IP header; anything other than 06 is to be omitted
        //TCP head length (first digit of TCP byte 12) represents the TCP header length; so 50 = 4 * 5 = 20 = 20 bytes long
        //if the source IP matches client, add at 53 to start of byte; otherwise remove first two bytes
        private List<string> InterpretPacketHeader(string line)
        {
            int startOfData = _byteLocations.LeadingByteCount; //there are some leading bytes before the ip header is reached; fixing it to 14

            List<string> data = new List<string>(line.Split(_delimiters, StringSplitOptions.RemoveEmptyEntries));
            if(string.Compare(data[startOfData+_byteLocations.ProtocolByte], "06") != 0) //protocol 06 corresponds to TCP
            {
                data.Clear();
                return data; //data does NOT have tcp layer
            }
            int totalLength = int.Parse(string.Concat(data[startOfData + _byteLocations.TotalLengthByte], data[startOfData + _byteLocations.TotalLengthByte + 1]), System.Globalization.NumberStyles.HexNumber) + startOfData;


            startOfData = startOfData + int.Parse(data[startOfData][1].ToString()) * 4; //goes to the end of IP header, ie 4*5=20

            startOfData = startOfData + int.Parse(data[startOfData + _byteLocations.TcpLengthByte][0].ToString()) * 4; //why is this 4? because 5 * 4 = 20?

            int ipResult = AcceptableIp(data);
            List<string> rawData = data.GetRange(startOfData, totalLength - startOfData);
            if(rawData.Count <= 0)
            {
                return rawData;
            }
            else if(ipResult == 1)
            {
                rawData = CheckReserveData(rawData, true);
            }
            else if(ipResult == 2)
            {
                rawData = CheckReserveData(rawData, false);
            }
            else
            {
                rawData.Clear();
            }
            return rawData;
        }

        //is data is being stored to keep track of multi-package payloads, this method will return empty list if more is stored, or the entire reserve if data is finished
        private List<string> CheckReserveData(List<string> rawData, bool isClient)
        {
            if (_reservedData.Count > 0)
            {
                _reservedData = _reservedData.Concat(rawData).ToList();
                rawData.Clear();
                if (_reservedData.Count > int.Parse(_reservedData[0]))
                {
                    rawData = rawData.Concat(_reservedData).ToList();
                    _reservedData.Clear();
                    rawData.RemoveAt(0);
                }
            }
            else if (rawData.Count <= 2) //there's barely any data! just kill it
            {
                rawData.Clear();
            }
            else
            {
                int rawDataLength = int.Parse(string.Concat(rawData[1], rawData[0]), System.Globalization.NumberStyles.HexNumber); //is the total size of raw data going to be sent; INCLUDES data from following packets
                if(isClient == true)
                {
                    rawData.Insert(0, "53");
                }
                else
                {
                    rawData.RemoveRange(0, 2);
                }
                
                if (rawDataLength >= 1460)
                {
                    _reservedData.Add(rawDataLength.ToString());
                    _reservedData = _reservedData.Concat(rawData).ToList();
                    rawData.Clear();
                }
            }

            return rawData;
        }

        //very obvious what this does
        private string HexToDec(string val)
        {
            try
            {
                return int.Parse(val, System.Globalization.NumberStyles.HexNumber).ToString();
            }
            catch
            {
                return string.Empty;
            }
        }

        //checks if the given textbox stuff matches in the specific packet
        private int AcceptableIp(List<string> data) //returns 1 if client is source, 2 if server is source, 0 if no match
        {
            (string, string) desiredClient = (ClientIp.Text, ClientPort.Text);
            (string, string) desiredServer = (ServerIp.Text, ServerPort.Text);
            (string, string) source;
            (string, string) destination;

            int index = _byteLocations.LeadingByteCount + _byteLocations.IpSource; //stores start of source|des bytes, index+byteoffset
            source.Item1 = $"{HexToDec(data[index])}.{HexToDec(data[index+1])}.{HexToDec(data[index+2])}.{HexToDec(data[index+3])}";
            destination.Item1 = $"{HexToDec(data[index+4])}.{HexToDec(data[index+5])}.{HexToDec(data[index+6])}.{HexToDec(data[index+7])}";

            index = _byteLocations.LeadingByteCount + int.Parse(data[_byteLocations.LeadingByteCount][1].ToString()) * 4;
            source.Item2 = HexToDec(string.Concat(data[index], data[index + 1]));
            destination.Item2 = HexToDec(string.Concat(data[index + 2], data[index + 3]));
            

            if (source == desiredClient && destination == desiredServer)
            {
                return 1;
            }
            else if (source == desiredServer && destination == desiredClient)
            {
                return 2;
            }
            return 0;
        }

        //writes properly formatted text info to megaText, is called AFTER filtering
        private void ParseHexData(string line, DateTime time)
        {//:D
            const int bytesPerLine = 20;

            List<string> rawData;
            try
            {
                rawData = InterpretPacketHeader(line); //exception thrown if we try reading data from a bad packet. May be a result of misaligned byte locations or extra/missing leading bytes
            }
            catch
            {
                _problems = true;
                Console.WriteLine($"Bad line detected: {line}");
                return;
            }
            
            if(rawData.Count <= 0)
            {
                return;
            }

            string dataLine = "";
            _packetCount = _packetCount + 1;
            int i = 0;
            if(_prevTime.Ticks == 0) //broken up so the first time value is set to 0 seconds, instead of trying to do math on prevTime (that doesn't exist yet)
            {
                _megaText = $"{_megaText}[{_packetCount.ToString("D4")}] {DateTime.Now.ToString("yyyy/MM/dd")} {time.ToString("HH:mm:ss:fff")} Elapsed:   0.000000 Seconds\r\n";
            }
            else
            {
                _megaText = $"{_megaText}[{_packetCount.ToString("D4")}] {DateTime.Now.ToString("yyyy/MM/dd")} {time.ToString("HH:mm:ss:fff")} Elapsed: {time.Subtract(_prevTime).TotalSeconds.ToString().PadLeft(10).Substring(0,10)} Seconds\r\n";
            }
            
            _prevTime = time;
            foreach(string bite in rawData)
            {
                dataLine = dataLine + bite.ToUpper() + " ";
                i = i + 1;
                if (i % bytesPerLine == 0)
                {
                    dataLine = dataLine.PadRight(81); //81 is the total allotted char limit for each line
                    _megaText = _megaText + dataLine + "\r\n";
                    dataLine = "";
                }
            }
            if(i % bytesPerLine != 0)
            {
                dataLine = dataLine.PadRight(81);
                _megaText = _megaText + dataLine + "\r\n";
            }
            _megaText = _megaText + "--------------------------------------------------------------------------------\r\n";
        }

        private void TextBox_GotFocus(object sender, RoutedEventArgs e)
        {
            TextBox tb = sender as TextBox;
            if(tb != null && tb.Opacity != 1)
            {
                tb.Text = "";
                tb.Opacity = 1;
                tb.FontStyle = FontStyles.Normal;
            }
        }

        private void TheGrid_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            TheGrid.Focus();
        }
    }
}
