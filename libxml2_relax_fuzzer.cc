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

#include <libxml/xmlversion.h>
#include <libxml/parser.h>
#include <libxml/relaxng.h>

void ignore (void* ctx, const char* msg, ...) {
	// Error handler to avoid spam of error messages from libxml parser.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	xmlSetGenericErrorFunc(NULL, &ignore);

	if (size == 0)
		return 0;

	std::string schemaString(data, data + size - 1);

	xmlRelaxNGParserCtxtPtr ctxt = xmlRelaxNGNewMemParserCtxt(schemaString.c_str(), schemaString.size());

	xmlRelaxNGSetParserErrors(
		ctxt,
		xmlGenericError,
		xmlGenericError,
		NULL
	);
	xmlRelaxNGPtr schema = xmlRelaxNGParse(ctxt);
	xmlRelaxNGFreeParserCtxt(ctxt);
	if (schema != NULL)
		xmlRelaxNGFree(schema);
	xmlRelaxNGCleanupTypes();
	xmlCleanupParser();
	xmlMemoryDump();
	return 0;
}