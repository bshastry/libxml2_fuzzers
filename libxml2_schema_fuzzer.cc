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
#include <stdexcept>

#include "libxml/parser.h"
#include <libxml/xmlmemory.h>
#include <libxml/xmlschemas.h>
#include <libxml/xmlschemastypes.h>

/// Error handler to avoid spam of error messages from libxml parser.
void ignore (void* ctx, const char* msg, ...) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	xmlSetGenericErrorFunc(NULL, &ignore);

	if (size == 0)
		return 0;

	std::string schemaString(data, data + size - 1);

	if (const char* dump_path = getenv("DUMP_PATH"))
	{
		std::ofstream of(dump_path);
		of << schemaString;
		return 0;
	}

	xmlSchemaParserCtxtPtr ctxt = xmlSchemaNewMemParserCtxt(
		schemaString.c_str(),
		schemaString.size()
	);
	xmlSchemaSetParserErrors(
		ctxt,
		xmlGenericError,
		xmlGenericError,
		NULL
	);
	xmlSchemaPtr schema = xmlSchemaParse(ctxt);
	xmlSchemaFreeParserCtxt(ctxt);
	if (schema != NULL)
		xmlSchemaFree(schema);
	// Common clean up
	xmlSchemaCleanupTypes();
	xmlCleanupParser();
	xmlMemoryDump();
	return 0;
}