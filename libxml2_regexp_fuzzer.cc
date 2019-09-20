// Copyright 2019 Bhargava Shastry
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <cassert>
#include <cstddef>
#include <cstdint>

#include <functional>
#include <limits>
#include <string>
#include <fstream>

#include "libxml/xmlregexp.h"

using namespace std;

namespace {
	string printable(string const& _str, bool _isPattern) {
		string printStr{_str};
		printStr.erase(remove_if(printStr.begin(), printStr.end(), [=](char c) -> bool {
			return !isprint(c);
		}), printStr.end());

		if (printStr.empty()) {
			if (_isPattern)
				return ".*";
			else
				return "fuzz";
		}
		return printStr;
	}
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size <= 50)
		return 0;

	// First forty characters comprise pattern, rest value
	string pattern(reinterpret_cast<const char*>(data), 40);
	pattern = printable(pattern, true);
	string value(reinterpret_cast<const char*>(data + 40), size - 40);
	value = printable(value, false);

	if (const char* dump_path = getenv("DUMP_PATH"))
	{
		ofstream of(dump_path);
		of << "---- expression -----";
		of << pattern;
		of << "---- value -----";
		of << value;
		return 0;
	}

	if (auto compile = xmlRegexpCompile(reinterpret_cast<const unsigned char*>(pattern.c_str()))) {
		xmlRegexpExec(compile, reinterpret_cast<const unsigned char*>(value.c_str()));
		xmlRegFreeRegexp(compile);
	}

	// Test the bare bones parser
	if (auto ctxt = xmlExpNewCtxt(0, NULL)) {
		if (auto expr = xmlExpParse(ctxt, pattern.c_str())) {
			if (auto buf = xmlBufferCreate()) {
				xmlExpDump(buf, expr);
				xmlBufferFree(buf);
			}
			xmlExpFree(ctxt, expr);
		}
		xmlExpFreeCtxt(ctxt);
	}

	return 0;
}
