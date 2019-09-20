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

#include <libxml/xmlmemory.h>
#include <libxml/uri.h>
#include <libxml/globals.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	if (size == 0)
		return 0;

	// Split fuzz data equally between xpath expression
	// and base string.
	std::string str(data, data + size/2);
	std::string base(data + size/2, data + size - 1);

	xmlURIPtr uri = xmlCreateURI();
	xmlChar* res = NULL;
	xmlChar* parsed = NULL;
	switch (size % 7)
	{
		case 0: {
			int ret = xmlParseURIReference(uri, str.c_str());
			if (ret == 0) {
				xmlNormalizeURIPath(uri->path);
				parsed = xmlSaveUri(uri);
				res = xmlURIEscape(parsed);
			}
			break;
		}
		case 1:
			res = xmlBuildRelativeURI(
				reinterpret_cast<const unsigned char*>(str.c_str()),
				reinterpret_cast<const unsigned char*>(base.c_str())
			);
			break;
		case 2:
			res = xmlBuildURI(
				reinterpret_cast<const unsigned char*>(str.c_str()),
				reinterpret_cast<const unsigned char*>(base.c_str())
			);
			break;
		case 3:
		{
			std::string uriString(data, data + size - 1);
			if (auto parsedUri = xmlParseURI(uriString.c_str()))
				xmlFreeURI(parsedUri);
			break;
		}
		case 4:
		{
			std::string path(data, data + size - 1);
			if (auto cPath = xmlCanonicPath(
				reinterpret_cast<const unsigned char*>(path.c_str())
				))
				free(cPath);
			break;
		}
		case 5:
		{
			// Path to uri
			std::string path(data, data + size - 1);
			if (auto pUri = xmlPathToURI(
				reinterpret_cast<const unsigned char*>(path.c_str())
				))
				free(pUri);
			break;
		}
		case 6:
		{
			// Parse raw uri
			std::string uriString(data, data + size - 1);
			if (auto rUri = xmlParseURIRaw(uriString.c_str(), /*raw=*/size % 2))
				xmlFreeURI(rUri);
		}
	}

	if (res != NULL)
		xmlFree(res);
	if (parsed != NULL)
		xmlFree(parsed);
	xmlFreeURI(uri);
	xmlMemoryDump();
	return 0;
}