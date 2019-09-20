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
#include <vector>

#include "libxml/HTMLparser.h"
#include "libxml/parser.h"
#include "libxml/xmlsave.h"

static std::vector<std::string> s_enc = {
	"ASCII",
	"HTML",
	"ISO-8859-1",
	"US-ASCII",
	"UTF-16",
	"UTF-16BE",
	"UTF-16LE",
	"UTF-8"
};

void ignore (void* ctx, const char* msg, ...) {
	// Error handler to avoid spam of error messages from libxml parser.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	xmlSetGenericErrorFunc(NULL, &ignore);

	if (size == 0)
		return 0;

	// Test default empty options value and some random combination.
	std::string data_string(reinterpret_cast<const char*>(data), size);
	const std::size_t data_hash = std::hash<std::string>()(data_string);
	const int max_option_value = std::numeric_limits<int>::max();
	int random_option_value = data_hash % max_option_value;
	const int options[] = {0, random_option_value};
	unsigned encIdx = data_hash % (s_enc.size() + 1);
	// Last index -> encoding ignored
	const char* encoding = NULL;
	if (encIdx < s_enc.size())
		encoding = s_enc[encIdx].c_str();

	for (const auto option_value : options) {
		if (auto doc = htmlReadDoc(
				reinterpret_cast<unsigned const char*>(data_string.c_str()),
				"index.html",
				encoding,
				option_value
			)
		) {
			auto buf = xmlBufferCreate();
			assert(buf);
			auto ctxt = xmlSaveToBuffer(buf, NULL, 0);
			xmlSaveDoc(ctxt, doc);
			xmlSaveClose(ctxt);
			xmlFreeDoc(doc);
			xmlBufferFree(buf);
		}
	}

	return 0;
}
