/*
Final Project CSC4024
Author: Professor Craig Peltier
Compile Command: g++ -o FinalProject FinalProject.cpp
Run Command: ./FinalProject
*/
#include <iostream>
#include <thread>
#include <mutex>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <unistd.h>
#include <stdarg.h> 
#include <cstdio> 

using namespace std;

extern "C" void clearTerminalWindow(void);
extern "C" void assignmentInstructions(void);
extern "C" void viewVulnerabilityData(void);

enum dataType {rawData,analyticData};
enum processingType {automated,manual};

string directoryPathDataFeed;
string directoryPathAnalyticReport;

/* FIX (Vulnerability 5: Data race on cvssAnalysis)
   Remove the shared global CVSS analysis string*/


mutex threadAccessController;

/* FIX (Vulnerability 12: Unsafe system("clear"))
   Escape codes to clear screen. */
void clearTerminalWindow(void)
{
    cout << "\033[2J\033[H";   
    cout.flush();
}


void assignmentInstructions(void)
{
    clearTerminalWindow();
    printf("Welcome to the final project! Congratulations on making it to the sprint to the finish line!\n\n"); 
    printf("\n(1) Download the following to a folder of your choosing:\n\n");
    printf("\ti. FinalProject.cpp\n");  
    printf("\tii. nistVulnData.csv\n");  
    printf("\tiii. cisaVulnData.csv\n"); 
    printf("\n(2) Compile the code using the following command:\n\n");
    printf("\ti. g++ -o FinalProject FinalProject.cpp\n");  
    printf("\n(3) You are required to review the code and write a report similar to your Juice Shop report\n\n");
    printf("\ti. You must include an assessor biograph that discloses the skills that you have that make you qualified to perform the assessment.\n");  
    printf("\tii. You must include an executive summary of the assessment effort.\n");  
    printf("\t\ta) Include dates of the assessment\n"); 
    printf("\t\tb) Include what was the intent behind the assessment\n");     
    printf("\tiii. You must include the defined scope of the assessment effort.\n");
    printf("\t\ta) Include all technologies needed for the assessment (code languages, build out, etc.)\n"); 
    printf("\t\tb) Include a summary of what was actually assessed\n");  
    printf("\tiv. You must include a high-level overview of the results of the effort.\n");
    printf("\t\ta) Include a wholistic risk rating for the entire application\n"); 
    printf("\t\tb) Include a concise table providing only the vulnerability title and risk rating\n");  
    printf("\tv. You must include a detailed breakdown of all vulnerabilities found\n");   
    printf("\t\ta) Include a vulnerability title\n"); 
    printf("\t\tb) Include a vulnerability risk rating\n");     
    printf("\t\tc) Include a vulnerability description\n");
    printf("\t\td) Include a vulnerability mitigation recommendation\n"); 
    printf("\t\te) Include vulnerability evidence\n"); 
    printf("\t\t\tI. line numbers where the vulnerability exists\n"); 
    printf("\t\t\tII. screen captures showing the vulnerable code identified\n");   
    printf("\t\t\tIII. screen captures showing the vulnerable being exploited (if possible)\n"); 
    printf("\n(4) You are required to write a mitigated version of the code fixing the vulnerabilities that you found.\n\n");
    printf("\ti. You must use C-style comments to identify all code you created to mitigate the vulnerabilities\n");  
    printf("\n(5) You are required identify all concepts in this code that were covered in the course\n\n");
    printf("\ti. If the concept exists, you must use C-style comments to identify these concepts (including but not limited to the concepts below)\n");
    printf("\t\ta) Memory Management\n");
    printf("\t\tb) Variadic Functions\n");
    printf("\t\tc) Concurrency\n");
    printf("\t\t\tI. Task Parallelism\n"); 
    printf("\t\t\tII. Data Parallelism\n"); 
    printf("\t\td) File I/O\n");
    printf("\t\te) Privilege Management\n");   
    printf("\t\tf) POSIX\n");  
    printf("\t\tg) File Permissions\n\n"); 
    printf("Click any key to continue\n\n");
    getchar();
}

void viewVulnerabilityData(int clearTerminal,string directoryPathDataFeed)
{
    if(clearTerminal == 1)
    {
        clearTerminalWindow();
    }
    
    /* FIX: (vulnerability 1: uninitialized variable ) I set result to 0 so the loop starts with a real value */ 
    int result = 0;
    int count = 0;
    char str[1024];
    char cve[4] = "CVE";
    char firstThreeChars[4];
    FILE *fileHandle; 

    fileHandle = fopen(directoryPathDataFeed.c_str(),"r");

    if(fileHandle != NULL)
    {
        printf("*****************************************\n\n");
        printf(" Viewing File %s \n\n",directoryPathDataFeed.c_str());
        printf("*****************************************\n\n\n");
        printf("*****************************************\n\n");
        printf("        Vulnerability Data Start        \n\n");
        printf("*****************************************\n\n\n");
            while(result != EOF)
    {
        result = fscanf(fileHandle, "%1023[^,\n]", str);

        /* FIX (Vulnerability 13: Missing input validation)
           Make sure fscanf errors are handled right. */
        if (result == EOF)
        {
            
            break;
        }
        else if (result == 0)
        {
            
            int skip = fgetc(fileHandle);
            if (skip == EOF)
            {
                
                break;
            }
        }
        else if (result == 1)
        {
            

            strncpy(firstThreeChars, str, 3);

            /* FIX:Vulnerability (2): unsafe string handling
               Make sure the string ends */
            firstThreeChars[3] = '\0';

            if(strcmp(cve, firstThreeChars) == 0)
            {
                count++;
                printf("*********  Vulnerability # %d ***********\n\n", count);
            }

            printf("%s\n\n", str);
            str[0] = '\0';
        }
        else
        {
            
            fprintf(stderr, "Warning: malformed CSV input detected.\n");
        }
    }

        
        /* FIX (Vulnerability 3: file not closed)
   Close the file when we are done reading it. */
        fclose(fileHandle);

        
        printf("*****************************************\n\n");
        printf("        Vulnerability Data End          \n\n");
        printf("*****************************************\n\n");
    }
    else
    {
        printf("*****************************************\n\n");
        printf("         !!File Read Error!!            \n\n");
        printf("*****************************************\n\n");
    }
    printf("Click any key to continue\n");
    getchar();
}

string analyzeRiskRating(string line)
{
    string risk_rating = "Risk Rating: Low\n";
    if(line.find("AV:N") != string::npos)
    {
        if(line.find("AC:L") != string::npos)
        {
            if(line.find("PR:N") != string::npos)
            {
                if(line.find("UI:N") != string::npos)
                {
                    risk_rating="Risk Rating: Medium\n";  
                    if(line.find("C:H") != string::npos)
                    {
                        if(line.find("I:H") != string::npos)
                        {
                            if(line.find("A:H") != string::npos)
                            {
                                risk_rating="Risk Rating: High\n";   
                                if(line.find("S:C") != string::npos)
                                {
                                    risk_rating="Risk Rating: Critical\n";    
                                } 
                            }      
                        }                             
                    }                           
                }                           
            }
        }
    }
    return risk_rating;
}

/* FIX (Vulnerability 5: Data race on cvssAnalysis)
   return it instead of appending */

string analyzeAccessVector(const string &line)
{
    string result;
    if(line.find("AV:N") != string::npos)
    {
        result += "This is network exploitable,";
    }
    else if(line.find("AV:L") != string::npos)
    {
        result += "This is locally exploitable,";
    }
    else if(line.find("AV:A") != string::npos)
    {
        result += "This is exploitable from adjacent networks,";
    }
    else if(line.find("AV:P") != string::npos)
    {
        result += "This is exploitable only from physically being on the asset being exploited,";
    }
    return result;
}


string analyzeAttackComplexity(const string &line)
{
    string result;
    if(line.find("AC:L") != string::npos)
    {
        result += "This is easy to exploit,";
    }
    else if(line.find("AC:H") != string::npos)
    {
        result += "This is complex to exploit,";
    }
    return result;
}


string analyzePrivilegesRequired(const string &line)
{
    string result;
    if(line.find("PR:N") != string::npos)
    {
        result += "No form of authentication is needed to exploit this,"; 
    }
    else if (line.find("PR:L") != string::npos)
    {
        result += "Low level of authentication is needed to exploit this,"; 
    }
    else if (line.find("PR:H") != string::npos)
    {
        result += "High level of authentication is needed to exploit this,"; 
    }
    return result;
}


string analyzeUserInteraction(const string &line)
{
    string result;
    if(line.find("UI:N") != string::npos)
    {
        result += "No user interaction is needed to exploit this,"; 
    }
    else if (line.find("UI:R") != string::npos)
    {
        result += "User interaction is needed to exploit this,"; 
    }
    return result;
}


string analyzeScopeChange(const string &line)
{
    string result;
    if(line.find("S:U") != string::npos)
    {
        result += "Scope of impact doesn't change on exploit,"; 
    }
    else if (line.find("S:C") != string::npos)
    {
        result += "Scope of impact does change on exploit,"; 
    }
    return result;
}


string analyzeConfidentiality(const string &line)
{
    string result;
    if(line.find("C:N") != string::npos)
    {
        result += "No breach of confidentiality on exploit,"; 
    }
    else if (line.find("C:L") != string::npos)
    {
        result += "Low level breach of confidentiality on exploit,"; 
    }
    else if (line.find("C:H") != string::npos)
    {
        result += "High level breach of confidentiality on exploit,"; 
    }
    return result;
}


string analyzeIntegrity(const string &line)
{
    string result;
    if(line.find("I:N") != string::npos)
    {
        result += "No breach of integrity on exploit,"; 
    }
    else if (line.find("I:L") != string::npos)
    {
        result += "Low level breach of integrity on exploit,"; 
    }
    else if (line.find("I:H") != string::npos)
    {
        result += "High level breach of integrity on exploit,"; 
    }
    return result;
}


string analyzeAvailability(const string &line)
{
    string result;
    if(line.find("A:N") != string::npos)
    {
        result += "No breach of availability on exploit,"; 
    }
    else if (line.find("A:L") != string::npos)
    {
        result += "Low level breach of availability on exploit,"; 
    }
    else if (line.find("A:H") != string::npos)
    {
        result += "High level breach of availability on exploit,"; 
    }
    return result;
}


/* FIX (Vulnerability 5: data race on cvssAnalysis)
    local string and return it. */
string analyzeCVSS(const string &line)
{
    string cvssAnalysisText = "Analysis:\n";
    cvssAnalysisText += analyzeAccessVector(line);
    cvssAnalysisText += analyzeAttackComplexity(line);
    cvssAnalysisText += analyzePrivilegesRequired(line);
    cvssAnalysisText += analyzeUserInteraction(line);
    cvssAnalysisText += analyzeScopeChange(line);
    cvssAnalysisText += analyzeConfidentiality(line);
    cvssAnalysisText += analyzeIntegrity(line);
    cvssAnalysisText += analyzeAvailability(line);
    return cvssAnalysisText;
}


/* FIX (Vulnerability 7: variadic function misuse)
  read up to two messages and call va_end(). */
void progressBar(int sleepDelay, ...)
{
    const char * startMessage = nullptr;
    const char * endMessage   = nullptr;
    string progressBar = "*";

    va_list args;
    va_start(args, sleepDelay);
    startMessage = va_arg(args, const char*);
    endMessage = va_arg(args, const char*);
    va_end(args);

    for(int index = 0; index < 10; index++)
    {
        clearTerminalWindow();
        if(startMessage != nullptr)
        {
            cout << startMessage << endl;
        }
        cout << "Progress: " << progressBar << endl;
        progressBar += "***";
        sleep(sleepDelay);
    }
    if(endMessage != nullptr)
    {
        cout << endMessage << endl;
    }
}


void setAlternateDataFeed(void)
{
    clearTerminalWindow();
    cout<<"Please provide absolute path to new data feed to import:";
    getline(cin, directoryPathDataFeed);
}


void createVulnerabilityAnalaysis(string directoryPathDataFeed)
{
    
    int vulnCount=0;
    size_t position;
    ifstream rawVulnData;
    ofstream analyticVulnData;  
    string line; 
    string riskRating;         
    string token;
    string delimiter = ",";
    if(directoryPathAnalyticReport=="")
    {
        directoryPathAnalyticReport="./analyticVulnData.csv";
    }
    
        int previousEUID = geteuid();

    /* FIX (Vulnerability 8: weak privilege management)
       Check the return value of seteuid() */
    if (seteuid(getuid()) != 0)
    {
        perror("failed to drop privileges with seteuid");
        return;  
    }

    rawVulnData.open(directoryPathDataFeed);
    analyticVulnData.open(directoryPathAnalyticReport, ios_base::app);

    if (seteuid(previousEUID) != 0)
    {
        perror("failed to restore previous privileges with seteuid");
      
    }

    
    
    
    while(getline(rawVulnData,line))
    {
        vulnCount++;   

        analyticVulnData<<endl<<endl<<"****Feed "<<directoryPathDataFeed<<"****Vulnerability # "<<vulnCount<<"*******"<<endl;

        int tokenCount=0;
        while(tokenCount<6)
        {
            position=line.find(delimiter);
            token = line.substr(0,position);
            tokenCount++;
            if(token.find("CVE") != string::npos)
            {
                analyticVulnData<<"ID: "<<token<<",";
            }
            else if (tokenCount==4)
            {
                analyticVulnData<<"Title: "<<token<<",";
            }        
            line.erase(0, position+ delimiter.length());
        }
        riskRating = analyzeRiskRating(line);
        

         // FIX (Vulnerability 5: Data race on cvssAnalysis)
        // Get a local CVSS analysis string from analyzeCVSS
        string cvssAnalysis = analyzeCVSS(line);

        analyticVulnData<<riskRating<<cvssAnalysis<<endl;
    }
        /* FIX (Vulnerability 6: threading design flaw)
       lock around progress bar and console I/O  */
    threadAccessController.lock();
    string startMessage = "Analytics Started on ";
    string directoryMessage = startMessage + directoryPathDataFeed;

    /* FIX (Vulnerability 7: variadic function misuse)
       pass start message first, end message second. */
    progressBar(1, directoryMessage.c_str(), "Analytics Completed");

    cout << "Click any key to continue\n";
    getchar();
    threadAccessController.unlock();
}



void setAlternateAnalyticReport(void)
{
    clearTerminalWindow();
    cout<<"Please provide absolute path to new analytic report output location and file name:";
    getline(cin, directoryPathAnalyticReport);
    cout<<"New path is set to "<<directoryPathAnalyticReport.c_str()<<endl;
    cout<<"Click any key to continue\n";
    getchar();
}

/* FIX (Vulnerability 9: command injection)
   Use remove() instead of passing user controlled strings into system(). */
  /* FIX (Vulnerability 10: overly permissive file permissions)
   Removed 'chmod 777' call and stopped using system() */

   
void purgeAnalyticReport(int purgeType)
{
    /* FIX (Vulnerability 11: Uninitialized variable)
       Initialize status */
    int status = 0;
    
    string confirmation;

    if(purgeType == manual)
    {
        cout<<"About to purge file: "<<directoryPathAnalyticReport<<endl;
        cout<<"Click Y to confirm purge or any other key to abort."<<endl;
        getline(cin, confirmation);
    }
    else
    {
        confirmation="Y";
    }

    if(confirmation=="Y")
    {
        if(directoryPathAnalyticReport=="")
        {
            directoryPathAnalyticReport="./analyticVulnData.csv";
        }

        status = remove(directoryPathAnalyticReport.c_str());
        
        if(status != 0)
        {
            perror("Failed to delete analytic report");
        }

        if(purgeType == manual)
        {
            progressBar(1, nullptr,"File Purge Completed");
            if(status==-1)
            {
                cout<<"Purge Attempt Failed."<<endl;
            }
            cout<<"Click any key to continue"<<endl;
            getchar();
        }
    }
    else
    {
        clearTerminalWindow();
        cout<<"Purge Process Canceled!"<<endl;
        cout<<"Click any key to continue"<<endl;
        getchar();
    }
}


int programMenu(void)
{
    clearTerminalWindow();
    char menuOptionAsChar[2];
    int menuOptionAsInt;
    cout<<"Welcome to the vulnerability analysis tool."<<endl<<endl;
    cout<<"Please select your option from the available options below."<<endl;
    cout<<"0 >> View your final project assignment instructions"<<endl;
    cout<<"1 >> View Raw Vulnerability Data from NIST and CISA feed"<<endl;
    cout<<"2 >> Create Vulnerability Analaysis from NIST and CISA data feed"<<endl;
    cout<<"3 >> View Vulnerability Analaysis"<<endl;
    cout<<"4 >> Perform vulnerability analysis on new data feed"<<endl;
    cout<<"5 >> Set custom output file name and location (defaulted to ./analyticVulnData.csv)"<<endl;
    cout<<"6 >> Purge analytic report."<<endl;   
    cout<<"x >> Exit Program"<<endl<<endl;
    cout<<"Enter Option: ";
    
    
        /* FIX (Vulnerability 4: buffer overflow in menu input)
       read one character so the input cannot overflow. */
    cin >> ws;                    
    cin.get(menuOptionAsChar[0]); 
    menuOptionAsChar[1] = '\0';   
    
    

    if(*menuOptionAsChar=='x')
    {
        menuOptionAsInt=42;
    }
    else
    {
        menuOptionAsInt = *menuOptionAsChar - '0';
    }
    getchar();
    return menuOptionAsInt;
}

void createAnalysisThreaded(void)
{
    string cisaDirectoryPath = "./cisaVulnData.csv";
    string nistDirectoryPath="./nistVulnData.csv";
    const size_t analysis_thread_size = 2;
    thread createAnalysis[analysis_thread_size];
    createAnalysis[0]=thread(createVulnerabilityAnalaysis,cisaDirectoryPath);
    createAnalysis[1]=thread(createVulnerabilityAnalaysis,nistDirectoryPath);
    createAnalysis[0].join(); 
    createAnalysis[1].join();
}

void takeActionOnMenuOption(int menuOption)
{

    clearTerminalWindow();
    switch(menuOption)
    {
        case 0:
            assignmentInstructions();
            break;
        case 1:
            if(directoryPathDataFeed.empty())
            {
                viewVulnerabilityData(1,"./cisaVulnData.csv");
                viewVulnerabilityData(0,"./nistVulnData.csv");
            }
            else
            {
                viewVulnerabilityData(1,directoryPathDataFeed);
            }
            break;
        case 2:
            if(directoryPathDataFeed=="")
            {
                purgeAnalyticReport(automated);
                createAnalysisThreaded();
            }
            break;
        case 3:
            if(directoryPathAnalyticReport=="")
                {
                    viewVulnerabilityData(1,"./analyticVulnData.csv");
                }
                else
                {
                    viewVulnerabilityData(1,directoryPathAnalyticReport);
                }
            break;
        case 4:
            purgeAnalyticReport(automated);
            setAlternateDataFeed();
            createVulnerabilityAnalaysis(directoryPathDataFeed);
            break;
        case 5:
            setAlternateAnalyticReport();
            break;
        case 6:
            purgeAnalyticReport(manual);
            break;
        case 42:
            break;     
        default:
            cout<<"Invalid Menu Option. Please try again";
    }
}

int main() 
{
    bool menuLoopExit = false;
    int menuOption;
    do
    {
        clearTerminalWindow();
        menuOption = programMenu();
        takeActionOnMenuOption(menuOption);
        if (menuOption==42)
        {
            menuLoopExit = true;
        }
    } while (! menuLoopExit);      

	return 0;
}
