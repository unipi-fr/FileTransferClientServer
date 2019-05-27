#include <string>

#define RED     "\033[31m"
#define CYAN    "\033[36m"
#define YELLOW  "\033[33m"
#define RESET   "\033[0m"
#define MAGENTA "\033[35m"
#define GREEN   "\033[32m"

class Printer 
{
    public:
        static void printInfo(char* info);
        static void printWaring(char* warning);
        static void printError(char* error);
        static void printErrorWithReason(char* error, char* reason);
        static void printMsg(char* msg);
        static void printPrompt(char* prompt);
};