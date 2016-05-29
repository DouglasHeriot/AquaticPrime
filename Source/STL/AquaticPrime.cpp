//
// AquaticPrime.cpp
// AquaticPrime STL Implementation
//
// Copyright (c) 2005, Lucas Newman
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//	*Redistributions of source code must retain the above copyright notice,
//	 this list of conditions and the following disclaimer.
//	*Redistributions in binary form must reproduce the above copyright notice,
//	 this list of conditions and the following disclaimer in the documentation and/or
//	 other materials provided with the distribution.
//	*Neither the name of the Aquatic nor the names of its contributors may be used to 
//	 endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
// IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
// OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "AquaticPrime.h"
#include "tinyxml2.h"
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <cctype>
#include <new>

extern "C" {
	#include <b64/b64.h>
}

using namespace AP;


// Utilities

static License APCreateLicenseForLicenseXMLDocument(const AquaticPrime &ap, tinyxml2::XMLDocument &licenseFile);

static inline char ToLower(char in)
{
	return (char)std::tolower((int)in);
}

static const char* CreateCString(std::string output, ...)
{
	static char text[256];
	va_list	ap;

	va_start(ap, output);								// Parses The String For Variables
		vsprintf(text, output.c_str(), ap);				// And Converts Symbols To Actual Numbers
	va_end(ap);					

	return (const char*)text;
}


License::License(std::map<std::string, std::string> dictionary, std::string hash):
dictionary(dictionary),
hash(hash)
{
}

LicenseException::LicenseException(const std::string &what):
std::runtime_error(what)
{
}

// AquaticPrime class

AquaticPrime::AquaticPrime(const std::string key):
rsaKey(RSA_new())
{
	if(rsaKey == nullptr)
	{
		throw std::bad_alloc();
	}
	
	// Public exponent is always 3
	BN_hex2bn(&rsaKey->e, "3");
	
	std::string mutableKey = key;
	
	// Determine if we have a hex or decimal key
	std::transform(key.begin(), key.end(), mutableKey.begin(), ToLower); // make mutableKey lowercase
	if(std::string(mutableKey, 0, 2) == "0x")
	{
		mutableKey = std::string(mutableKey, 2, mutableKey.length());
		BN_hex2bn(&rsaKey->n, mutableKey.c_str());
	}
	else 
	{
		BN_dec2bn(&rsaKey->n, mutableKey.c_str());
	}
}

AquaticPrime::~AquaticPrime()
{
	RSA_free(rsaKey);
}

// Set the entire blacklist array, removing any existing entries
void AquaticPrime::setBlacklist(std::vector<std::string> hashArray)
{
	blacklist = hashArray;
}

void AquaticPrime::blacklistAdd(std::string blacklistEntry)
{
	blacklist.push_back(blacklistEntry);
}

License AquaticPrime::createLicenseFromMap(std::map<std::string, std::string> data) const
{	
	if (!rsaKey->n || !rsaKey->e)
	{
		throw LicenseException("RSA key is invalid");
	}
	
	// Load the signature
	unsigned char sigBytes[128];
	std::map<std::string, std::string>::iterator signature = data.find("Signature");

	if(signature == data.end())
	{
		throw LicenseException("Invalid license data – no signature");
	}
	
	const int returnVal = b64decode(data["Signature"].c_str(), data["Signature"].length(), sigBytes, 129);
	
	if(returnVal == 0)
	{
		throw LicenseException("Signature has invalid base-64 encoding");
	}
	
	data.erase(signature);
	
	// Decrypt the signature
	unsigned char checkDigest[128] = {0};
	if (RSA_public_decrypt(128, sigBytes, checkDigest, rsaKey, RSA_PKCS1_PADDING) != SHA_DIGEST_LENGTH)
	{
		throw LicenseException("Signature is invalid");
	}

	// Get the license hash
	std::string hashCheck;
	int hashIndex;
	for (hashIndex = 0; hashIndex < SHA_DIGEST_LENGTH; hashIndex++)
		hashCheck += CreateCString("%02x", checkDigest[hashIndex]);
	
	// Check hash against blacklist
	for(const auto &blacklistEntry : blacklist)
	{
		if(hashCheck == blacklistEntry)
		{
			throw LicenseException("License is blacklisted");
		}
	}
	
	// Get the number of elements
	const size_t count = data.size();
	// Load the keys and build up the key array
//	std::list<std::string> keyArray;
//	std::string keys[count];
	std::vector<std::string> keys;
	
	for(auto d = data.begin(); d != data.end(); ++d)
	{
		keys.push_back((*d).first);
	}
	
	// Sort the array ( $$ why?  for cleanliness reasons? )
//	int context = kCFCompareCaseInsensitive;
//	CFArraySortValues(keyArray, CFRangeMake(0, count), (CFComparatorFunction)CFStringCompare, &context);
	
	// Setup up the hash context
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	// Convert into UTF8 strings
	for(int i = 0; i < count; i++)
	{
		std::string key = keys[i]; // $$ convert this to keyArray later
		std::string value = data[key];

		// Account for the null terminator
		SHA1_Update(&ctx, value.c_str(), strlen(value.c_str()));
	}
	unsigned char digest[SHA_DIGEST_LENGTH];
	SHA1_Final(digest, &ctx);
	
	// Check if the signature is a match	
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) 
	{
		if (checkDigest[i] ^ digest[i]) 
		{
			throw LicenseException("License signature does not match the license data");
		}
	}

	// If it's a match, we return the dictionary; otherwise, we never reach this
	return License(std::move(data), hashCheck);
}

License AquaticPrime::createLicenseFromFile(std::string path) const
{
	tinyxml2::XMLDocument licenseFile;
	licenseFile.LoadFile(path.c_str());
	return APCreateLicenseForLicenseXMLDocument(*this, licenseFile);
}

License AquaticPrime::createLicenseFromXMLString(std::string xmlString) const
{
	tinyxml2::XMLDocument licenseFile;
	licenseFile.Parse(xmlString.c_str(), xmlString.size());
	return APCreateLicenseForLicenseXMLDocument(*this, licenseFile); 
}

License APCreateLicenseForLicenseXMLDocument(const AquaticPrime &ap, tinyxml2::XMLDocument &licenseFile)
{
	std::map<std::string, std::string> xmlData;
	tinyxml2::XMLNode *node = 0;
	
	node = licenseFile.FirstChildElement("plist");
	
	if(node == nullptr)
		throw LicenseException("XML does not contain <plist> root node");
	
	node = node->FirstChildElement("dict");
	
	if(node == nullptr)
		throw LicenseException("XML does not contain <dict> node");
	
	do
	{
		// <dict>
		if(std::string(node->ToElement()->Value()) == std::string("dict"))
		{
			std::string key, data;
			tinyxml2::XMLNode *innerNode = node->FirstChild();
			while(innerNode != NULL)
			{				
				// <key>
				if(std::string(innerNode->ToElement()->Value()) == std::string("key"))
				{
					key = innerNode->ToElement()->FirstChild()->Value();
//					printf("key %s\n", key.c_str());
				}
				// <string>
				else if(std::string(innerNode->ToElement()->Value()) == std::string("string"))
				{
					data = innerNode->ToElement()->FirstChild()->Value();
					xmlData[key] = data;
//					printf("string %s %s\n", key.c_str(), data.c_str());
				}
				// <data>
				else if(std::string(innerNode->ToElement()->Value()) == std::string("data"))
				{
					data = innerNode->ToElement()->FirstChild()->Value();
					
					if(key == "Signature") // get rid of any spaces
					{
						std::vector<std::string::iterator> spaces;
						for(std::string::iterator d = data.begin(); d != data.end(); ++d)
						{
							if((*d) == ' ')
								spaces.push_back(d);
						}

						for(size_t s = 0; s < spaces.size(); ++s)
							data.erase(spaces[s] - (s));
					}
					
					xmlData[key] = data;
//					printf("data %s %s\n", key.c_str(), data.c_str());
				}
				
				innerNode = innerNode->NextSibling();
			}
		}
		
		node = node->NextSibling();
	} while(node != NULL);

	return ap.createLicenseFromMap(xmlData);
}

bool AquaticPrime::verifyLicenseMap(std::map<std::string, std::string> data) const noexcept
{
	try
	{
		const auto license = createLicenseFromMap(data);
		return true;
	}
	catch(const LicenseException &e)
	{
		return false;
	}
}

bool AquaticPrime::verifyLicenseFile(std::string path) const noexcept
{
	try
	{
		const auto license = createLicenseFromFile(path);
		return true;
	}
	catch(const LicenseException &e)
	{
		return false;
	}
}

bool AquaticPrime::verifyLicenseXMLString(std::string data) const noexcept
{
	try
	{
		const auto license = createLicenseFromXMLString(data);
		return true;
	}
	catch(const LicenseException &e)
	{
		return false;
	}
}
