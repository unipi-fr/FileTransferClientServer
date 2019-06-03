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
        static void printInfo(const char* info);
        static void printWaring(const char* warning);
        static void printError(const char* error);
        static void printErrorWithReason(const char* error, const char* reason);
        static void printMsg(const char* msg);
        static void printPrompt(const char* prompt);
        static void printLoadBar(double current, double end, bool error);
        static void printNormal(const char* msg);
        static void printTag(const char* TAG, const char* msg, const char* color);
};