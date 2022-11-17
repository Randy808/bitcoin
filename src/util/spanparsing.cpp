// Copyright (c) 2018-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/spanparsing.h>

#include <span.h>

#include <algorithm>
#include <cstddef>
#include <string>

namespace spanparsing {

//RANDY_CIMMENTED
//Returns true if 'str' is in sp then sets the sp to substring after the 'str' size
bool Const(const std::string& str, Span<const char>& sp)
{
    //If the 2 str in params are the same and they're equal to each other
    if ((size_t)sp.size() >= str.size() && std::equal(str.begin(), str.end(), sp.begin())) {
        //Set the span equal to the subspan in span from where str leaves off
        sp = sp.subspan(str.size());
        //return true
        return true;
    }

    //othetwise false
    return false;
}

//RANDY_COMMENTED
//Tries to parse the outermost paret of 'sp' as a function with the same name as the 'str' arg
bool Func(const std::string& str, Span<const char>& sp)
{
    //If the size of the span is equal to the str size (and 2 more for the parethesis)
    //and a '(' is after the str (possibly with some stuff in between) and the ')' is the last char
    //And the str can be found at the beginning
    if ((size_t)sp.size() >= str.size() + 2 && sp[str.size()] == '(' && sp[sp.size() - 1] == ')' && std::equal(str.begin(), str.end(), sp.begin())) {
        //Mofidy the argument to be in 'sp'
        sp = sp.subspan(str.size() + 1, sp.size() - str.size() - 2);
        //Return true
        return true;
    }

    //Return false
    return false;
}

//RANDY_COMMENTED
//Has an iterator that looks for end of valid span or until span is invalid (has unmatched closing chars '}', ')', etc)
//Then returns the valid part of the span using that iterator as a marker, and deletes the returned part from the original span
Span<const char> Expr(Span<const char>& sp)
{
    //Set lvel to 0
    int level = 0;

    //Create an iterator for the span
    auto it = sp.begin();

    //While the iterator isn't at the end
    while (it != sp.end()) {
        //If the iterator is at a position that is an opening char
        if (*it == '(' || *it == '{') {
            //Add 1 to level
            ++level;
        }
        //If it's a closing char, subtract 1 to level
        else if (level && (*it == ')' || *it == '}')) {
            --level;
        }
        //If level is 0 and has a closing then break
        else if (level == 0 && (*it == ')' || *it == '}' || *it == ',')) {
            break;
        }

        //increment iterator
        ++it;
    }

    //Return the part of the span with respect to the beginning (ret is 'x' from beginning)
    Span<const char> ret = sp.first(it - sp.begin());

    //Remove the part we're going to return fromt he span
    sp = sp.subspan(it - sp.begin());

    //return the return value
    return ret;
}

} // namespace spanparsing
