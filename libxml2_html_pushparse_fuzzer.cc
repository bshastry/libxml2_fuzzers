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

static xmlSAXHandler emptySAXHandlerStruct = {
	NULL, /* internalSubset */
	NULL, /* isStandalone */
	NULL, /* hasInternalSubset */
	NULL, /* hasExternalSubset */
	NULL, /* resolveEntity */
	NULL, /* getEntity */
	NULL, /* entityDecl */
	NULL, /* notationDecl */
	NULL, /* attributeDecl */
	NULL, /* elementDecl */
	NULL, /* unparsedEntityDecl */
	NULL, /* setDocumentLocator */
	NULL, /* startDocument */
	NULL, /* endDocument */
	NULL, /* startElement */
	NULL, /* endElement */
	NULL, /* reference */
	NULL, /* characters */
	NULL, /* ignorableWhitespace */
	NULL, /* processingInstruction */
	NULL, /* comment */
	NULL, /* xmlParserWarning */
	NULL, /* xmlParserError */
	NULL, /* xmlParserError */
	NULL, /* getParameterEntity */
	NULL, /* cdataBlock */
	NULL, /* externalSubset */
	1,    /* initialized */
	NULL, /* private */
	NULL, /* startElementNsSAX2Func */
	NULL, /* endElementNsSAX2Func */
	NULL  /* xmlStructuredErrorFunc */
};

static xmlSAXHandlerPtr emptySAXHandler = &emptySAXHandlerStruct;

struct Reader {
	char* ptr;
	char* startPtr;
	char* endPtr;
	size_t totalSize;
	size_t bytesRead;

	Reader(const uint8_t* source, size_t size)
	{
		ptr = reinterpret_cast<char *>(malloc(size));
		if (!ptr)
			throw std::runtime_error("Malloc failure");

		memcpy(reinterpret_cast<void *>(ptr), reinterpret_cast<const void*>(source), size);
		startPtr = endPtr = ptr;
		totalSize = size;
		bytesRead = 0;
	}

	~Reader()
	{
		if (ptr)
			free(ptr);
	}

	int read(size_t numBytes) {
		startPtr = endPtr;
		size_t remainingData = totalSize - bytesRead;
		if (remainingData == 0)
			return 0;

		bool enoughData = remainingData > numBytes;
		if (enoughData)
		{
			endPtr += numBytes;
			bytesRead += numBytes;
			return numBytes;
		}
		else
		{
			endPtr += remainingData;
			bytesRead += remainingData;
			assert(bytesRead == totalSize);
			return remainingData;
		}
	}

	char* get() { return startPtr; }
};

void ignore (void* ctx, const char* msg, ...) {
	// Error handler to avoid spam of error messages from libxml parser.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size == 0)
		return 0;

	xmlSetGenericErrorFunc(NULL, &ignore);

	Reader r(data, size);

	// Detect encoding by reading the first four bytes
	size_t bytesRead = r.read(4);
	assert(bytesRead > 0);

	htmlParserCtxtPtr ctxt = htmlCreatePushParserCtxt(
		emptySAXHandler,
		NULL,
		r.get(),
		bytesRead,
		"index.html",
		XML_CHAR_ENCODING_NONE
	);

	while ((bytesRead = r.read(1024)) > 0)
		htmlParseChunk(ctxt, r.get(), bytesRead, 0);

	assert(bytesRead == 0);
	htmlParseChunk(ctxt, r.get(), 0, 1);
	auto doc = ctxt->myDoc;
	htmlFreeParserCtxt(ctxt);
	if (doc != NULL)
		xmlFreeDoc(doc);
	xmlCleanupParser();
	return 0;
}