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

/// XML document to validate against Relax NG schema
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

void ignore (void* ctx, const char* msg, ...) {
	// Error handler to avoid spam of error messages from libxml parser.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	xmlSetGenericErrorFunc(NULL, &ignore);

	if (size == 0)
		return 0;

	std::string schemaString(data, data + size - 1);

	xmlRelaxNGParserCtxtPtr ctxt = xmlRelaxNGNewMemParserCtxt(schemaString.data(), schemaString.size());

	xmlRelaxNGSetParserErrors(
		ctxt,
		xmlGenericError,
		xmlGenericError,
		NULL
	);

	// Parse schema
	xmlRelaxNGPtr schema = xmlRelaxNGParse(ctxt);

	// Parse static document
	xmlDocPtr doc = xmlReadMemory(xmlString.data(), xmlString.size(),
	                              "noname.xml", NULL, 0);

	assert(doc != NULL);
	// Validate doc
	if (schema != NULL)
	{
		xmlRelaxNGValidCtxtPtr validateCtxt;
		validateCtxt = xmlRelaxNGNewValidCtxt(schema);
		xmlRelaxNGSetValidErrors(validateCtxt,
		                        xmlGenericError, xmlGenericError, NULL);
		xmlRelaxNGValidateDoc(validateCtxt, doc);
		xmlRelaxNGFreeValidCtxt(validateCtxt);
		xmlRelaxNGFree(schema);
	}
	xmlFreeDoc(doc);
	xmlRelaxNGFreeParserCtxt(ctxt);
	xmlRelaxNGCleanupTypes();
	xmlCleanupParser();
	xmlMemoryDump();
	return 0;
}