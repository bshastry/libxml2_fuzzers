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
#include <stdexcept>
#include <fstream>

#include "libxml/parser.h"
#include <libxml/xmlmemory.h>
#include <libxml/xmlschemas.h>
#include <libxml/xmlschemastypes.h>

static std::string xmlString = R"(<?xml version="1.0" encoding="UTF-8"?>
<shiporder orderid="889923"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:noNamespaceSchemaLocation="shiporder.xsd">
<orderperson>John Smith</orderperson>
<shipto>
<name>Ola Nordmann</name>
<address>Langgt 23</address>
<city>4000 Stavanger</city>
<country>Norway</country>
</shipto>
<item>
<title>Empire Burlesque</title>
<note>Special Edition</note>
<quantity>1</quantity>
<price>10.90</price>
</item>
<item>
<title>Hide your heart</title>
<quantity>1</quantity>
<price>9.90</price>
</item>
</shiporder>
)";

/// Error handler to avoid spam of error messages from libxml parser.
void ignore (void* ctx, const char* msg, ...) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	xmlSetGenericErrorFunc(NULL, &ignore);

	if (size == 0)
		return 0;

	// Fuzz schema
	std::string schemaString(data, data + size - 1);

	if (const char* dump_path = getenv("DUMP_PATH"))
	{
		std::ofstream of(dump_path + std::string{".xsd"});
		of << schemaString;
		return 0;
	}

	// Parse schema
	xmlSchemaParserCtxtPtr ctxt = xmlSchemaNewMemParserCtxt(
		schemaString.data(),
		schemaString.size()
	);
	xmlSchemaSetParserErrors(
		ctxt,
		xmlGenericError,
		xmlGenericError,
		NULL
	);
	xmlSchemaPtr schema = xmlSchemaParse(ctxt);

	xmlDocPtr doc = xmlReadMemory(xmlString.data(), xmlString.size(),
	                              "noname.xml", NULL, 0);

	assert(doc != NULL);
	// Validate doc
	if (schema != NULL)
	{
		xmlSchemaValidCtxtPtr validateCtxt;
		validateCtxt = xmlSchemaNewValidCtxt(schema);
		xmlSchemaSetValidErrors(validateCtxt,
		                        xmlGenericError, xmlGenericError, NULL);
		xmlSchemaValidateDoc(validateCtxt, doc);
		xmlSchemaFreeValidCtxt(validateCtxt);
		xmlSchemaFree(schema);
	}
	xmlFreeDoc(doc);

	xmlSchemaFreeParserCtxt(ctxt);
	// Common clean up
	xmlSchemaCleanupTypes();
	xmlCleanupParser();
	xmlMemoryDump();
	return 0;
}