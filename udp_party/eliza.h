#ifndef ELIZA_H
#define ELIZA_H

#include <string>

class Eliza
{
public:
	Eliza();
	std::string start();
	std::string getResponse(const char* request, bool& finishSession);

private:
	std::string lastinput;
	std::string canonicalizeInput(const char* input);
	
	static constexpr size_t NUMKEYWORDS = 37;
	static constexpr size_t NUMSWAPS = 14;
	static constexpr size_t MAX_INPUT_LENGTH_BYTES = 80;
	unsigned int whichReply[NUMKEYWORDS];
	static const char* keywords[NUMKEYWORDS];
	static const char* SWAPS[NUMSWAPS][2];
	static unsigned int ResponsesPerKeyword[NUMKEYWORDS];
	static const char* responses[NUMKEYWORDS][9];

};

#endif // ifndef ELIZA_H
