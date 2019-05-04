#include "IClientServerTCP.h"
#include "SecureMessageCreator.h"
#include <exception>
#include <fstream>

#define BUFF_SIZE 128

class SecureConnectionException : public std::exception
{
    virtual const char *what() const throw() = 0;
};

class HashNotValidException : public SecureConnectionException
{
    const char *what() const throw()
    {
        return "Not valid hash during checking";
    }
};

class ErrorOnOtherPartException : public SecureConnectionException
{
    const char *what() const throw()
    {
        return "Error on other part exception";
    }
};

class FileNotOpenException : public SecureConnectionException
{
    const char *what() const throw()
    {
        return "file is not open";
    }
};

class SecureConnection
{
private:
    IClientServerTCP *_csTCP;
    SecureMessageCreator *_sMsgCreator;

public:
    SecureConnection(IClientServerTCP *csTCP);
    void sendSecureMsg(void *buffer, size_t bufferSize);
    int recvSecureMsg(void **plainText);
    void sendSecureMsgWithAck(void *buffer, size_t bufferSize);
    int recvSecureMsgWithAck(void **plainText);

    /**
     * sendFile send a file.
     *
     * @file need an open filestream.
     * @stars if true prints 80 * on the screen
     * @return the fileSize on success.
     * 
     * In case of error Exceptions will be throwed
     * (all right, then. Keep your secret)
     * 
     * ####@###@@@@@@@@@@@@@@@@@@@@#@#@@#####+#++#+#'++######################@@@@@@@#####@@@@@@@@#######@@@##@@@@@@@
     * #+######@@@@@@@@@@@@@@@@@@@@@###@#@#@+'#######'+#########+##########@@@@@@@@@####@@@@@@@@@@@@####@@@@@@@@@@@@
     * +++######@@@@@@@@@##@@@@@@@@@#@##+@##++'++###+'#####'####'###@#####@#@@@@@@@@@@@@@@@@@@@@@@@@@@##@@@@@@@@@@@@
     * #++########@@@@#@#@#@@@@@@@@@@#@''###+;''++#+''#+'::'+##+#+''+;+;##@#@@@##+#@@#@@@@@@@@@@@@###@@#@@@@@@@@@@@@
     * ###########@@@@####@@@@@@@@#@@##+##++'',++;++;+::,,';+;';;::;;:;###'####+##@@#@@@@@@@@@@@@@#@@@@##@@@@@@@@@@@
     * ###+########@@@####@@@@@@@######+++#+:':++';;;:::;+++':::::;;;;:''':;'##@@@#@#@@@@@@@@@@@@@@@@@@#@#@@@@@@@@@@
     * ##++#######@@@@########@@##+'+#'+'+;::::;:'';:,:,;;:;,,,:::,:,::;;''';##@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@##@@@@
     * #########@#@@@#########+;+;';''''',:::,:::;::,,,,,,:,,,:::,:::::;''+;:+'@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@##@@@@
     * #++###########@####+###;''+:::::,::::,:;';,:,,::,,,,,,,:,,;,:;::;'+''+++#@####@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     * #+++#######+#####++'+';:,,,:;::::::,:.,::;,,,,,:;;,,,,::::;::::::;;;;+#'+'#####@#@@@##@@@@@@@@@@@@@@@@@@@@@@@
     * #+++######+++######'':,,:::;:::,,,:.,,,,,.:::::::,';:,::::;;';;''';:'''''##@#####@@@###@@@@@@@@@@@@@@@@@@@@@@
     * ###########++#@###+:,,,;:;::,,,,:::;:,:,::,,::;;;'';':,,;;;;'';;;';::'''+###;####@@@####@@@@@@@@@@@@@@@@@@@@@
     * ###########++#####;.,:':;:,,,::,,::;,:::,:;;:'++'++,;':,';'+'+;;::,::';;+++;+#############@@@@@@@@@@@@@@@@@@@
     * ######'''+##++###',,::::::::,::;:,:;;';.';:;+'+:+++'';+.;+++';;::,,:;:::;':,++;+##+#######@@@@@@@@@@@@@@@@@@@
     * #####+';'++######,,:,,:,,.,:;::;:;';'+,,;+''':;+';##++'.;+++++:::,,,;:':'::,+##+':@@######@@@@@@@@@@@@@@@@@@@
     * ######++########+,,,,,,,,,;;:,,;;:;'':,++',::;,+++;+;;'::+#'+':,,,,:;:':;;:;'++:;+#@@@@@#@@@@@@@@@@@@@@@@@@@@
     * ############+:,,;::,,:,,;;:,.,,;'#+;,+#++#':'+;:,:'':',:;+#+;;,,,::','':::,;'::'#@@#@@@@@@@@@@@@@@@@@@@@@@@@@
     * ###########:'+'';;:::,::,:,::;'++'::++++#;++'+:++:::+::'####'::,,:::;;;'::,:::''++#@#@@@@@@@@@@#@@@@@@@@@@@@@
     * ###++#########+';:,::::::;;,;'''+'###+#+;'++':+#::;++';#+##+;:';:';;;'',;;;';'''''##'#@@##@@@@@@@@@@@@@@@@@@@
     * ###+++######++:,:,,::,;,'';'';':++++#;#:;+'';##:;;#+,:+####'+:+#'+;+'+++#++'''''''''+####@@@@@@@@@@@@@@@@@@@@
     * ++##++#@##@#'::,,,:':::'''++;;''++'+##'##:++##';###;:+####+'+++++++;++####++'#+++'++'++#@##,+#@@@@@@@@@@@@@@@
     * +##@######;;;;::::;:,++++;;:;++#'##@@##;:'++'#++'#';+###@@#++#@##++#'##@@#'++##++++++''##','#@@@@@@@@@@@@@@@@
     * #########'#,;,,,,:','+++;++'+'+##+####''+'+#@######+++###@##+@######+##@##+##+'#++'';++;',++@:#@@@@@@@@@@@@@@
     * @##+#####++';:::;+,:;++#+##++++#####+##+#######@@#@@@@##@@@####@####++###++:######+++'';;###;+##@@@@@@@@@@@@@
     * #########+'',+::;;,';+###+#++##@###############@@#@@@@##@@@@########+#+######++###'+:+''++''+@#@@@@@@@@@@@@@@
     * ########+':;;;,;;';#:++###############@########@@@@@@@##@@@@#@@######+#########@#+''#';+'''##+#@@#@@@@@@@@@@@
     * #########+:;;;:;';;###;##############@#########@##@@@@#@@@@@#@@@@##@############@@#'#+''+;+#+'##@##@@@@@@@@@@
     * #########+:;:.;;;;;+##'+##########################@@@@#@@@@@@@@@@@@@###########@@#####+++;'''##@@##@@@@@@@@@@
     * #########+':,;;;''''+##+######@#####@#############@@@##@@@@@@@@@@@@@@####@@#@####@#@@#+'+';;;+#####@###@@@@@@
     * ++###+++';,:;';';;''''#++########@##@############@@@####@@@@@@@@@@@@@@#####@@@@#@@@@@@+';''''''#@#####@@@@@@@
     * '+++####+::;+::;;'+'';+#+##########@@#####@#############@@@@@@@@@@@@@@@@@#####@@@##@@@##++++;###+@@####@@@@@@
     * ########::;''::;'++'''+############@@###################@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@####+#######@###@@@@@@
     * #######':''++:;;'++#'#+'##########@@#@##################@@@@@@#@@@@@@@@@@@@@@@@@@@@@@@@###':+####@@#+@@@@@@@@
     * #######:+';+',;;''###+;++#########@@@################+##@@@@@@@#@@@@@@@@@@@@@@@@@@@@@@@###+'######'#@@@@@@@@@
     * #++'##;'#';+::,:;'##+;'''##########@###############++######@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#@#++###++#@@@@@@@@@@
     * ++++#'+'',':;::;''+#':'';+##########@#########@##+######@####@@@@@@@@##@@@@@@@@@@@@@@@@##@#++###++@@@@@@@@@@@
     * ++##+'';::';;;:';;+':'''++########+##############+++++########@@#@@@##@@@@@@@@@@@@@@@@@@##@#+++++@@##+#@@@@@@
     * +###+'':;:;:;':';+;;#+''+##++#####++##############++++############@@@@@@@@@@@@@@@@@@@@@###@#+++++'#'#@@@@@@@@
     * +++#+';;::;:';::;;'#''''+##++#####++##############+++++###########@@@@#@@@@@@@@@@@@@@@@######+#+++##+#@@@@@@@
     * +++#+';;:::'+;,,:;';+''+#++'+####++++#+##########@##+++#@##########@#@@##@@@@@@@@@@@@@@@#######';'++##@@@@@@@
     * ##+''+;:,,;+:'';;''';';+'+'+#####++++##+###@######@####@#++#+#######@#@@#####@@@@@@@@@@@#@#######'+#####@@@@@
     * #@#'';;.,;+++;,;''+:;;'''++####++++'''##++###@##########++++++##############@@@@@@@@@@@@@@#####;;#'+;+@@##@@@
     * ####';:;;'''+:,;+++'''''+++''###++''''+###+##########+++++++++##+############@@@@@@@@@@@@@@####';#+'#####@@@@
     * #+'';;;;':;;;:''+++++'''''''''''''''''''++##+######++++++++++++++++#######@@#@@@@@@@@@@@@@@####+'+#+######@@#
     * #+''''+;;:::,,:''+'++'''''''''''''''''''''''''''++++++'++++++++++++#######@@#@@@@@@@@@@@@@@@####+'####@@;#@#@
     * +++''';::,,,,,:'+'';;''';''';''''''''''''''''''''''+'+''''++++++++++#######@@@@@@@@@@@@@@@@#@###+;+###@@#@@#@
     * #+'''';:,,,,,,.:':;;;''';';;''''''''''''''''''''''''''''''++++++++++####@##@@@@@@@@@@@@@@@@@@#@@+++#@###+##@@
     * ++++';:,,,,,,,;:+::'''''';;;'''''''''''''''''''''''''''++'+++++++++++###@##@@@@@@@@@@@@@@#@@##@@#+###@@@#@#;@
     * ;;''';,::,:::,+'++;'''';;;;''';'''''''''''''''''''''''+++++++++++++++######@@@@@@@@@@@@@@@@@@@@@#######@@@###
     * ';''',::;':;;+++++''''''';'''''''''''''''''''''''''+++++++++#++++++++######@@@@@@@@@@@@@@@@@@@@@#######@@@@#@
     * +'':;;:;;;:'+#++#+'''''''''''''';''''''''''''''++++++##########+++++++#####@@@@@@@@@@@@@@@@@@#@@#######@@@@@@
     * ++:''';;::''+#++++';'''''''''''''''''''''''''+++#########++++++#++++++#####@@@@@@@@@@@@@@##@@@@@@#####@@@@@@@
     * +,#+'';;:;''+##+#+';'''''''''''''''''''''''++++#####++++++++++++++++++#####@@@@@@@@@@@@@@@#####@@###+++'+#@@@
     * ;+++'';;;:''+#+##+;;''++++++++''''''''''''+++++++++++++++++++++++++++++####@@@@@@@@@@@@@@@#######@##++;;####@
     * '+#+'':';:''+++#++;++++######++'''''''''''+++++++++++++++++++++++++++++####@@@@@@@@@@@@@@@@@#######@#########
     * '+##';:;;:;;'+#+#';+++++###+++++''''''''''+++++++++++++++++++++++++++++####@@@@@@@@@@@@@@@@#########@####@#@@
     * +##+';:::;,,'####;''++++++++++++''''''''''++++++++++++++++++##+++++++++#####@@@@@@@@@@@@@@@#############@@###
     * +#+'+':::;:,'++##:;'''''++++++++''''''''''+++++++++++++++++++++++++++++#####@@@@@@@@@@@@@@@####@@@#########@@
     * +#+'+',:;:;:;'###;'''''++++++++++'''''''''++++++++++++####++++++++++++++####@@@@@@@@@@@@@@@@#####@########+#@
     * ++''';;;:,,';'###+'+++++++++++++++''''''''++++++++++++##@####+++++++++++####@@@@@@@@@@@@@@@@############++'##
     * ++'++''';::';'####'+++''''+++###++'';''''+++++++#+';';#######++++''''+++#####@@@@@@@@@@@@@@@@#@@@############
     * +++++'+'''+'::+###''++''+########+'';''''++++'++++++++##++++++++'''''+++#####@@@@@@@@@@@@@@@@@@@@@@######+###
     * ####:#+#'';;::++##;'+'+##+'#+@###+'';'''''++++''+''''++++++++++''''''++++#####@@@@@@@@@@@#@@@@@@@@#######++##
     * +#####+';''':;'+##;'''##'''##++++'';;'''''+++++++++'''+++++++++'''''+++++#######@@@@@@@@@###@@@@@@@@######+++
     * +++####++''':;'+##;;:;++++++''++''';;''''''++++++++++++++++++''''''''++++#######@@@@@@@@@####@@@@@@@######+++
     * +++####+''++::'+##;';;'''''''+++''';;''''''+++'''''''''''''''''''''++++++#######@@@@@@@@@####@@@@@@@#######+#
     * ##+###';';;:;''+##;';;'''''''++'''';;'''''''++''''''''''''''''''''+++++++########@@@@@@@@####@@@@@@@#########
     * #####+''+;;#;''###;;;;''''''''''''';;'''''''''''''''''''''''''''''++++++++#######@@@@@@@#####@@@@@@@#######+#
     * #########+;;'''###;;;;;'''''''''''';'''''''''''''''''''''''''''''''+++++++########@#@@@@#####@@@@@@@######+++
     * +#####+#++''+;'++#;;;;;;''''''''''';'''''''''''''''''''''''''''''''+++++++########@###@@#####@@@@@@@######'''
     * ++++++++++'''+'''+:::;;;;;'''''''';;''''''''''''''''''''''''''''''''+++++++#######@#@@@#######@@@@@@@#+###'''
     * +++++++++'';;+'''+:::;;;;;'''''''';;'''''''+++''''''''''''''''''''''+++++++#######@###@#+#####@@@@@@@#####++'
     * ++++++##++;;:'+''':;:;;;'''''''''';;'''''''+++++''''''''''''''''+++'+++++++###########@++#####@@@@@@@@####++#
     * '+++####++';;;++++::::;;''''''''';;;'''''''''++++'''''''''''''''++++++++++++##########@+#####@@@@@@#@#####++#
     * '++++++++';';;+++#::;;;''''''''';;;;''''''''''+++'''''''''''''''++'+++++++++############++##@@@@@@##########+
     * ##+';'+##+'++,:+++::;;'''''''''';;'''''''''''++++'''''''''''''''''''++++++++###########+++#@@@@@@@##+####'+##
     * ##+''#######'':;##;:;'''''''''''''''''''''''+++++''''''''''''''+'++++++++++++###########+#@@@@@@@###+++#+####
     * ###+########+';:'#;:;'''''''''''++''''++###+++++''''''''''''''''++++'++++++++############@@@@@@@@###++##+####
     * ############+;:::#':''''''''''''''''+'++++'++++'''''''''''''''''++++''++++++++###########@@@@@@@@@#+#########
     * ############+:,::+#:'''''''''''''''''+++++'+++''''''''''''''''''++++'+'++++++++#########@#@@@@@@@@#####+#####
     * ############';:::'+;''''''''''''''''''++'''+++''''''''''''''''''''''''''+++++++##########@@@@@@@@@@@#########
     * ############''+:;:'+''''''''''''''''''''''''''''''''''''''''''''''''''''+++++++###########@@@@@@@@#@@#'#####'
     * ###########+'+#'::;+;'''''''''''''''''''''''''''''''''''+'''''''''''''''++++++++###########@@@@@##@@@#+'#+###
     * ###########+++#+::;''''''''''''''''''''''''''''''''''''''''''''''''''''+++++++++########@@@@@@@@####@@#;;###@
     * ############;'#':;';;''''''''''''''''''''''''''''''+''''+''''''''''''''+++++++++#####@@@@@@@@@@@#####@#+'####
     * @@##+####+'+#++;:::;:'''''''''''''''''''''''++++++++++++'''''''++''''''++++++++++++##@@@@@@@##@@@#######+'@##
     * #############'';;:;;'''''''''''''''''++++++++++#####+++++''''''''''''''++++++++++++##@@@@@@@@@@@@@@#@#+###@@@
     * ###############',;;':+'''''''''''+++#++++++#+#+##++++++++'''''+''''''''++++++++++++#@@@@@@@@@@@@@@@###+###@#@
     * ############@##';:,:;''''''''''++++####+######++++++++''''''''+'''''''+++++++++++++#@@@@@@@@@@@@@@#@##+++#@#@
     * ######++++##@##+;',:;+'''''''''''''++++++++#++++++++++'''''''++'''''+++++++++++++++##@@@@@@@@@@@@@##@##+####@
     * ######++#######+++'++''''''''''''''''+++++++++++++++''''''''+++'''''+'+++++++++++++##@@@@@@@@@@@@@###@######@
     * ################++'+#++''''''''''''''''''''++++++++'''''''''++''''''++++++++++++++++#@@@@@@@@@@@@@@@@@#+#+###
     * #####+##++++####'+'+#++'''''''''''''''''''+++++++''''''''''++++'''''+''+++++++++++++#@@@@@@@@##@@@@###'+#####
     * ########+++++++##''+#+++''''''''''''''''++++++'''''''''''''+++'''+''++++++++++++++++#@@@@@@@@####@@@@#++#####
     * #####+##++'++++#+''#+''';'''''''''''''''''+''''''''''''''''+++''''''++++++++++++++++#@@@@@@@@######@#;'+#####
     * #####''##++++++'#+''';:,:'''''''''''''''''''''''''''''''''+++++'''++++++++++++++++++#@@@@@@@@@@#+###@#+######
     * ######+#####++;+##';;::;::''''''''''''''''''''''''''''''''++++++'+++++++++++++++++++#@@@@@@@@@@@####+########
     * ######+######+++''::,:;,,:''''''''''''''''''''''''''''''''++++++++++++++++++++++++++#@@@@@@#@@@@@##+;######++
     * ######++#####;#;++::;::,,::''''''''''''''''''''''''''''''+++++++++++++++++++++++++++#@@@@@@##@@@@#'#+##+##+#;
     * ++#####+######'#+,,:::,:::'#'''''''''''''''''''''''''''''+++++++++++++++++++++++++++#@@@@@@@@+#@@#########+#@
     * #+##############',':,;:,:+#'''''''''''''''''''''''''''''++++++++++++++++++++++++++++#@#@@@@@@@####++#####++@@
     * ################''';:;,:++::'+''''''''''''''''''''''''''++++++++++++++++++++++++++++#@@@@@@@#@@#@#+++#+##'#@@
     * #####@@@########+;',;:;+':;;;+#'''''''''''''''''''''''''++++++++++++++++++++++++++++##@@@@@@#'#@@######'+'##@
     * #################+;::;+'::;;'''+'''''''''''''''''''''''+++++++++++++++++++++++++++++###@@@@@@@#@@@#####++'###
     * ##+###############+;:'';,;;#'''++''''''''''''''''''''++++++++++++++++++++++++++++++++##@@@@@@@@@@@@@#'++'####
     * @##################''+;:;;+#;'+#+;'''''''''''''''''+++++++++++++++++++++++++++++++++++##@@@@@@@@@@@@#';:;;;'#
     * #############+####+#+#';;:#''##+::;'''''''''''''''++++++++++++++++++++++++++++++++++++##@@@@@@@@@@@@@#+'+,,,:
     * ##@@@############++#+++;;+''###;;;'''''''''''''''+++++++++++++++++++++'++++++++++++++++##@@@@@@@@@@@@++##;,,:
     * ###@@@@##############++';+#'##;';;''''''''''''++++++++++++++++++++++++''++++++++++++++++#@@@@@@@#@@@####@#,''
     * ####@@###############+++''#++@'';+''++''++++++++++++++++++++++++++'+'+''+++++++++++++++++#@@@@@@@@@@####@#;++
     * ################+###++++'++#'##'++;+''''''''''++++++++++++++++''''''''''++++++++++++++++++#@@@@@@@@@#@@@##+++
     * #####################++'''+###@#''':'+;'''''''''''++++'++'++''''''''''''''+++++++++++++++++#@@@@@@@@#@##+++++
     * ######+''+#######+##+++';'+######+'++'''''''''''''++''''''''''''''''''''+++++++++++++++++++#@@@@@@@@@#+###+++
     * ##@@##+''++++++++'++++'++#+++#####+#+'''''''''''''''''''''''''''''''''''++++++++++++++++++++#@@@@@@@#+####+++
     * '#####++'';''++++++++++++###+'+#####++'+''''''''''''''''''''''''''''''''+++++++++++++++++++++#@@@@##+####++++
     * #+'+####+''''+++##++#+++++@#+++'#####++#''''''''''''''''''''''''''''''''++++++++++++++++++++++@@#+##########+
     * '##+;'###+'''+########+##';:,,,,,,'+##'++'''''''''''''''''''''''''''''''+++++++++++++++++++++++++############
     * '''###+'++';'######++##;,..,,,,;;;;:;;,::''''''''''''''''''''''''''''''''++'+++++++++++++++++#####+##########
     * #';;'+##'...'+###+++',..,:::'+';+'+;,,:;''''''''''''''''''''''''''''''''''++++++++++++++++++#################
     * +:++++;.,:++++####;,.:;++###++++':,,;+#++'''''''''''''''''''''''''''''''''+++++++++++++++++##################
     * +##+:,,,+###++##+,,,:'++++++#';,,:;++##'#+''''''''''''''''''''''''''''''''+++++++++++++++####################
     * ###+:::####+##+:,,.:;;'++#+':,,,;+####:+#+'''''''''''''''''''''''''''''''''++++++++++++######################
     * #@##::+###++++,.,,;'+##+',.,,,;+####+,:+#+;''''''''''''''''''''''''''''''''+++++++++++#####################++
     * ####;##@#+'+',.:''####+,,,,,,;++###+,.:###'''''''''''''''''''''''''''''''''++++++++++###################+++++
     * @@######+++'.:+####@#;.,,,,:'#####+,.,;+##+''''''''''''''''''''''''''''''''+++++++++################+++++++++
     * @###@##+++;.'#####@#;,,,,,:'+#####,.,:'####'''''''''''''''''''''''''''''''+++++++++################++++++++++
     * ####@#+++',+###@@@#:..,,,:+######:.,,;+####'''''''''''''''''''''''''''''''++++++++##############++#++++#+++++
     * ######+++''###@@#+'.,,,,:+######'..,,;+####'''''''''''''''''''''''''''''''++++++###############+####+++++++++
     * #############@####,,;+:,'######+;,..:'#####+'''''''''''''''''''''''''''''++++++#################+####++++++++
     * ############@####','#+;:+#####++'::.:+#+####''''''''''''''''''''''''''''++++++###################++++++++++++
     * #####@#####@####+::+#+;;#####++;:::,;+++####''''''''''''''''''''''''''''+'+++############+#######+++#+++#++++
     * ####@@@####@###++,+##+;+#####+':::,,,'''+###''''''''''''''''''''''''''''''++#########+##############+++++++++
     * ####@@####@#####;;###++######+;::.::;,'+####+''''''''''''''''''''''''''''+++########++#######+###+###+#++++++
     * #@@@#####@@##+##,+###+#######;::,,'+,;'+#####;''''''''''''''''''''''''''+++#########+###+####+#++###+####++++
    */
    int sendFile(std::ifstream &file, bool stars);
    int receiveFile(const char *filename);
    int reciveAndPrintBigMessage();
};