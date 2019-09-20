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

#include "libxml/parser.h"
#include "libxml/tree.h"
#include "libxml/xmlsave.h"

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

/// Error handler to avoid spam of error messages from libxml parser.
void ignore (void* ctx, const char* msg, ...) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size == 0)
		return 0;

	xmlSetGenericErrorFunc(NULL, &ignore);

	Reader r(data, size);

	// Detect encoding by reading the first four bytes
	size_t bytesRead = r.read(4);
	assert(bytesRead > 0);

	xmlParserCtxtPtr ctxt;
	ctxt = xmlCreatePushParserCtxt(NULL, NULL, r.get(), bytesRead, "test.xml");

	if (ctxt == NULL)
		return 0;

	while ((bytesRead = r.read(1024)) > 0)
		xmlParseChunk(ctxt, r.get(), bytesRead, 0);

	assert(bytesRead == 0);
	xmlParseChunk(ctxt, r.get(), 0, 1);
	auto doc = ctxt->myDoc;
	xmlFreeParserCtxt(ctxt);
	if (doc != NULL)
		xmlFreeDoc(doc);
	xmlCleanupParser();
	return 0;
}
