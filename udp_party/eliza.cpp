/* 
* Original code by Weizenbaum, 1966
* This rendition based on https://github.com/mottosso/cs50x/blob/master/eliza.c under The MIT License (MIT)

Copyright (c) 2016 Marcus Ottosson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


#include <string.h>
#include "eliza.h"
#include "utils.h"


const char* Eliza::keywords[] = {
       "CAN YOU","CAN I","YOU ARE","YOURE","I DONT","I FEEL",
       "WHY DONT YOU","WHY CANT I","ARE YOU","I CANT","I AM","IM ",
       "YOU ","I WANT","WHAT","HOW","WHO","WHERE",
       "WHEN","WHY",
       "NAME","CAUSE","SORRY","DREAM","HELLO","HI ","MAYBE",
       " NO","YOUR","ALWAYS","THINK","ALIKE","YES","FRIEND",
       "COMPUTER","CAR","NOKEYFOUND" };

const char* Eliza::SWAPS[NUMSWAPS][2] = {
    {"ARE","AM"},
    {"WERE", "WAS"},
    {"YOU","I"},
    {"YOUR", "MY"},
    {"IVE", "YOU'VE"},
    {"IM", "YOU'RE"},
    {"YOU", "ME"},
    {"ME", "YOU"},
    {"AM","ARE"},
    {"WAS", "WERE"},
    {"I","YOU"},
    {"MY", "YOUR"},
    {"YOUVE", "I'VE"},
    {"YOURE", "I'M"}
};

unsigned int Eliza::ResponsesPerKeyword[NUMKEYWORDS] = {
       3,2,4,4,4,3,
       3,2,3,3,4,4,
       3,5,9,9,9,9,
       9,9,
       2,4,4,4,1,1,5,
       5,2,4,3,7,3,6,
       7,5,6 };

const char* Eliza::responses[NUMKEYWORDS][9] = {
    {   "DON'T YOU BELIEVE THAT I CAN*",
        "PERHAPS YOU WOULD LIKE TO BE ABLE TO*",
        "YOU WANT ME TO BE ABLE TO*"},
    {   "PERHAPS YOU DON'T WANT TO*",
        "DO YOU WANT TO BE ABLE TO*"},
    {   "WHAT MAKES YOU THINK I AM*",
        "DOES IT PLEASE YOU TO BELIEVE I AM*",
        "PERHAPS YOU WOULD LIKE TO BE*",
        "DO YOU SOMETIMES WISH YOU WERE*"},
    {   "WHAT MAKES YOU THINK I AM*",
        "DOES IT PLEASE YOU TO BELIEVE I AM*",
        "PERHAPS YOU WOULD LIKE TO BE*",
        "DO YOU SOMETIMES WISH YOU WERE*"},
    {   "DON'T YOU REALLY*",
        "WHY DON'T YOU*",
        "DO YOU WISH TO BE ABLE TO*",
        "DOES THAT TROUBLE YOU?"},
    {   "TELL ME MORE ABOUT SUCH FEELINGS.",
        "DO YOU OFTEN FEEL*",
        "DO YOU ENJOY FEELING*"},
    {   "DO YOU REALLY BELIEVE I DON'T*",
        "PERHAPS IN GOOD TIME I WILL*",
        "DO YOU WANT ME TO*"},
    {   "DO YOU THINK YOU SHOULD BE ABLE TO*",
        "WHY CAN'T YOU*"},
    {   "WHY ARE YOU INTERESTED IN WHETHER OR NOT I AM*",
        "WOULD YOU PREFER IF I WERE NOT*",
        "PERHAPS IN YOUR FANTASIES I AM*"},
    {   "HOW DO YOU KNOW YOU CAN'T*",
        "HAVE YOU TRIED?",
        "PERHAPS YOU CAN NOW*"},
    {   "DID YOU COME TO ME BECAUSE YOU ARE*",
        "HOW LONG HAVE YOU BEEN*",
        "DO YOU BELIEVE IT IS NORMAL TO BE*",
        "DO YOU ENJOY BEING*"},
    {   "DID YOU COME TO ME BECAUSE YOU ARE*",
        "HOW LONG HAVE YOU BEEN*",
        "DO YOU BELIEVE IT IS NORMAL TO BE*",
        "DO YOU ENJOY BEING*"},
    {   "WE WERE DISCUSSING YOU-- NOT ME.",
        "OH, I*",
        "YOU'RE NOT REALLY TALKING ABOUT ME, ARE YOU?"},
    {   "WHAT WOULD IT MEAN TO YOU IF YOU GOT*",
        "WHY DO YOU WANT*",
        "SUPPOSE YOU SOON GOT*",
        "WHAT IF YOU NEVER GOT*",
        "I SOMETIMES ALSO WANT*"},
    {   "WHY DO YOU ASK?",
        "DOES THAT QUESTION INTEREST YOU?",
        "WHAT ANSWER WOULD PLEASE YOU THE MOST?",
        "WHAT DO YOU THINK?",
        "ARE SUCH QUESTIONS ON YOUR MIND OFTEN?",
        "WHAT IS IT THAT YOU REALLY WANT TO KNOW?",
        "HAVE YOU ASKED ANYONE ELSE?",
        "HAVE YOU ASKED SUCH QUESTIONS BEFORE?",
        "WHAT ELSE COMES TO MIND WHEN YOU ASK THAT?"},
    {   "WHY DO YOU ASK?",
        "DOES THAT QUESTION INTEREST YOU?",
        "WHAT ANSWER WOULD PLEASE YOU THE MOST?",
        "WHAT DO YOU THINK?",
        "ARE SUCH QUESTIONS ON YOUR MIND OFTEN?",
        "WHAT IS IT THAT YOU REALLY WANT TO KNOW?",
        "HAVE YOU ASKED ANYONE ELSE?",
        "HAVE YOU ASKED SUCH QUESTIONS BEFORE?",
        "WHAT ELSE COMES TO MIND WHEN YOU ASK THAT?"},
    {   "WHY DO YOU ASK?",
        "DOES THAT QUESTION INTEREST YOU?",
        "WHAT ANSWER WOULD PLEASE YOU THE MOST?",
        "WHAT DO YOU THINK?",
        "ARE SUCH QUESTIONS ON YOUR MIND OFTEN?",
        "WHAT IS IT THAT YOU REALLY WANT TO KNOW?",
        "HAVE YOU ASKED ANYONE ELSE?",
        "HAVE YOU ASKED SUCH QUESTIONS BEFORE?",
        "WHAT ELSE COMES TO MIND WHEN YOU ASK THAT?"},
    {   "WHY DO YOU ASK?",
        "DOES THAT QUESTION INTEREST YOU?",
        "WHAT ANSWER WOULD PLEASE YOU THE MOST?",
        "WHAT DO YOU THINK?",
        "ARE SUCH QUESTIONS ON YOUR MIND OFTEN?",
        "WHAT IS IT THAT YOU REALLY WANT TO KNOW?",
        "HAVE YOU ASKED ANYONE ELSE?",
        "HAVE YOU ASKED SUCH QUESTIONS BEFORE?",
        "WHAT ELSE COMES TO MIND WHEN YOU ASK THAT?"},
    {   "WHY DO YOU ASK?",
        "DOES THAT QUESTION INTEREST YOU?",
        "WHAT ANSWER WOULD PLEASE YOU THE MOST?",
        "WHAT DO YOU THINK?",
        "ARE SUCH QUESTIONS ON YOUR MIND OFTEN?",
        "WHAT IS IT THAT YOU REALLY WANT TO KNOW?",
        "HAVE YOU ASKED ANYONE ELSE?",
        "HAVE YOU ASKED SUCH QUESTIONS BEFORE?",
        "WHAT ELSE COMES TO MIND WHEN YOU ASK THAT?"},
    {   "WHY DO YOU ASK?",
        "DOES THAT QUESTION INTEREST YOU?",
        "WHAT ANSWER WOULD PLEASE YOU THE MOST?",
        "WHAT DO YOU THINK?",
        "ARE SUCH QUESTIONS ON YOUR MIND OFTEN?",
        "WHAT IS IT THAT YOU REALLY WANT TO KNOW?",
        "HAVE YOU ASKED ANYONE ELSE?",
        "HAVE YOU ASKED SUCH QUESTIONS BEFORE?",
        "WHAT ELSE COMES TO MIND WHEN YOU ASK THAT?"},
    {   "NAMES DON'T INTEREST ME.",
        "I DON'T CARE ABOUT NAMES-- PLEASE GO ON."},
    {   "IS THAT THE REAL REASON?",
        "DON'T ANY OTHER REASONS COME TO MIND?",
        "DOES THAT REASON EXPLAIN ANY THING ELSE?",
        "WHAT OTHER REASONS MIGHT THERE BE?"},
    {   "PLEASE DON'T APOLOGIZE.",
        "APOLOGIES ARE NOT NECESSARY.",
        "WHAT FEELINGS DO YOU HAVE WHEN YOU APOLOGIZE?",
        "DON'T BE SO DEFENSIVE!"},
    {   "WHAT DOES THAT DREAM SUGGEST TO YOU?",
        "DO YOU DREAM OFTEN?",
        "WHAT PERSONS APPEAR IN YOUR DREAMS?",
        "ARE YOU DISTURBED BY YOUR DREAMS?"},
    {   "HOW DO YOU DO--PLEASE STATE YOUR PROBLEM."},
    {   "HOW DO YOU DO--PLEASE STATE YOUR PROBLEM."},
    {   "YOU DON'T SEEM QUITE CERTAIN.",
        "WHY THE UNCERTAIN TONE?",
        "CAN'T YOU BE MORE POSITIVE?",
        "YOU AREN'T SURE?",
        "DON'T YOU KNOW?"},
    {   "ARE YOU SAYING NO JUST TO BE NEGATIVE?",
        "YOU ARE BEING A BIT NEGATIVE.",
        "WHY NOT?",
        "ARE YOU SURE?",
        "WHY NO?"},
    {   "WHY ARE YOU CONCERNED ABOUT MY*",
        "WHAT ABOUT YOUR OWN*"},
    {   "CAN YOU THINK OF A SPECIFIC EXAMPLE?",
        "WHEN?",
        "WHAT ARE YOU THINKING OF?",
        "REALLY, ALWAYS?"},
    {   "DO YOU REALLY THINK SO?",
        "BUT YOU ARE NOT SURE YOU*",
        "DO YOU DOUBT YOU*"},
    {   "IN WHAT WAY?",
        "WHAT RESEMBLANCE DO YOU SEE?",
        "WHAT DOES THE SIMILARITY SUGGEST TO YOU?",
        "WHAT OTHER CONNECTIONS DO YOU SEE?",
        "COULD THERE REALLY BE SOME CONNECTION?",
        "HOW?"},
    {   "YOU SEEM QUITE POSITIVE.",
        "ARE YOU SURE?",
        "I SEE.",
        "I UNDERSTAND."},
    {   "WHY DO YOU BRING UP THE TOPIC OF FRIENDS?",
        "DO YOUR FRIENDS WORRY YOU?",
        "DO YOUR FRIENDS PICK ON YOU?",
        "ARE YOU SURE YOU HAVE ANY FRIENDS?",
        "DO YOU IMPOSE ON YOUR FRIENDS?",
        "PERHAPS YOUR LOVE FOR FRIENDS WORRIES YOU?"},
    {   "DO COMPUTERS WORRY YOU?",
        "ARE YOU TALKING ABOUT ME IN PARTICULAR?",
        "ARE YOU FRIGHTENED BY MACHINES?",
        "WHY DO YOU MENTION COMPUTERS?",
        "WHAT DO YOU THINK MACHINES HAVE TO DO WITH YOUR PROBLEM?",
        "DON'T YOU THINK COMPUTERS CAN HELP PEOPLE?",
        "WHAT IS IT ABOUT MACHINES THAT WORRIES YOU?"},
    {   "OH, DO YOU LIKE CARS?",
        "MY FAVORITE CAR IS A LAMBORGINI COUNTACH. WHAT IS YOUR FAVORITE     CAR?",
        "MY FAVORITE CAR COMPANY IS FERRARI.  WHAT IS YOURS?",
        "DO YOU LIKE PORSCHES?",
        "DO YOU LIKE PORSCHE TURBO CARRERAS?"},
    {   "SAY, DO YOU HAVE ANY PSYCHOLOGICAL PROBLEMS?",
        "WHAT DOES THAT SUGGEST TO YOU?",
        "I SEE.",
        "I'M NOT SURE I UNDERSTAND YOU FULLY.",
        "COME, COME ELUCIDATE YOUR THOUGHTS.",
        "CAN YOU ELABORATE ON THAT?",
        "THAT IS QUITE INTERESTING."}


};


Eliza::Eliza()
{
    for (unsigned int x = 0; x < NUMKEYWORDS; x++) 
    {
        whichReply[x] = 0;
    }

    lastinput = "";
}


std::string Eliza::start()
{
    return "HI!  I'M ELIZA.  WHAT'S YOUR PROBLEM?";
};


std::string Eliza::getResponse(const char* request, bool& finishSession)
{
    std::string reply = "";
    finishSession = false;
    std::string inputstr = canonicalizeInput(request);
    
    // check for termination 
    if (inputstr == "BYE")
    {
        finishSession = true;
        return "GOODBYE!THANKS FOR VISITING ME ...";
    }

    // check for repeated entries 
    if (lastinput == inputstr)
    {
        return "PLEASE DON'T REPEAT YOURSELF!";
    }
    lastinput = inputstr;


    // see if any of the keywords is contained in the input 
    // if not, we use the last element of keywords as our default response 
    size_t k;
    size_t index;
    
    for (k = 0; k < NUMKEYWORDS - 1; k++)
    {
        index = inputstr.find(keywords[k]);
        if (index != std::string::npos)
        {
            break;
        }
    }

    // Build Eliza's response 
    // start with Eliza's canned response, based on the keyword match
    std::string baseResponse = (char*)responses[k][whichReply[k]];
    size_t baseLength = baseResponse.length();

    if (baseResponse[baseLength - 1] != '*')
    {
        // if we have a baseResponse without an asterix, just use it as-is
        reply = baseResponse;
    }
    else
    {
        // if we do have an asterix, fill in the remaining with the user input
        // use all but the last character of the base response
        reply = baseResponse.substr(0, baseLength - 1);

        // now add in the rest of the user's input, starting at <location>
        // but skip over the keyword itself
        index = index + strnlen_s(keywords[k], MAX_INPUT_LENGTH_BYTES);
        std::string location = inputstr.substr(index);
        // take them one word at a time, so that we can substitute pronouns
        size_t workingPos = 0;
        size_t pos = location.find_first_of(" ", workingPos);
        while (workingPos < location.length())
        {
            std::string token = location.substr(workingPos, pos - workingPos);
            workingPos = pos + 1;
            if (token != "")
            {

                for (int s = 0; s < NUMSWAPS; s++)
                {
                    if (strncmp(SWAPS[s][0], token.c_str(), MAX_INPUT_LENGTH_BYTES) == 0)
                    {
                        token = (char*)SWAPS[s][1];
                        break;
                    }
                }
                reply = reply + " " + token;
            }
            pos = location.find_first_of(" ", workingPos);
            if (pos == std::string::npos)
                pos = location.length();
        };
        reply = reply + "?";
    }

    // next time, use the next appropriate reply for that keyword
    whichReply[k]++;
    if (whichReply[k] >= ResponsesPerKeyword[k])
        whichReply[k] = 0;

    return reply;
}

std::string Eliza::canonicalizeInput(const char* input)
{
    std::string result = "";
    size_t length = strnlen_s(input, MAX_INPUT_LENGTH_BYTES);
    for (unsigned int i = 0; i < length; i++)
    {
        char c = input[i];
        // removes punctuation and sets to uppercase
        if (isalpha(c) || isspace(c))
            result.append(1, toupper(c));
    }
    return result;
}


