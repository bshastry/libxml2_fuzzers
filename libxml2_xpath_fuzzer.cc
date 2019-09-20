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

#include <libxml/xpath.h>
#include <libxml/parser.h>
#include <libxml/xpointer.h>

void ignore (void* ctx, const char* msg, ...) {
	// Error handler to avoid spam of error messages from libxml parser.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	if (size == 0)
		return 0;

	xmlSetGenericErrorFunc(NULL, &ignore);

	// Split fuzz data equally between xml document and
	// xptr expression
	std::string xmlDocString(data, data + size/2);
	std::string xptr(data + size/2, data + size - 1);

	xmlDocPtr doc = xmlReadMemory(xmlDocString.c_str(), xmlDocString.size(),
	                             "noname.xml", NULL, XML_PARSE_COMPACT);

	xmlXPathContextPtr ctxt;
	xmlXPathObjectPtr res;

	switch (size % 3) {
		// testXPath --xptr : expressions are XPointer expressions
		case 0:
			ctxt = xmlXPtrNewContext(doc, NULL, NULL);
			res = xmlXPtrEval(
				reinterpret_cast<const unsigned char*>(xptr.c_str()),
				ctxt
			);
			break;
		// --expr : debug XPath expressions only
		case 1:
			ctxt = xmlXPathNewContext(doc);
			ctxt->node = xmlDocGetRootElement(doc);
			res = xmlXPathEvalExpression(
				reinterpret_cast<const unsigned char*>(xptr.c_str()),
				ctxt
			);
			break;
		//
		case 2: {
			ctxt = xmlXPathNewContext(doc);
			ctxt->node = xmlDocGetRootElement(doc);
			xmlXPathCompExprPtr comp = xmlXPathCompile(
				reinterpret_cast<const unsigned char*>(xptr.c_str())
			);
			if (comp != NULL) {
				res = xmlXPathCompiledEval(comp, ctxt);
				xmlXPathFreeCompExpr(comp);
			} else
				res = NULL;
		}
	}
	xmlXPathFreeObject(res);
	xmlXPathFreeContext(ctxt);
	if (doc != NULL)
		xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlMemoryDump();
	return 0;
}