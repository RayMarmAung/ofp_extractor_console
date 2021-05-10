#include <iostream>
#include <sys/stat.h>
#include <sys/types.h>
#include <direct.h>
#include <fstream>
#include <map>
#include <inttypes.h>
#include <algorithm>
#include <Windows.h>

#include "openssl/aes.h"
#include "openssl/pem.h"
#include "openssl/opensslv.h"
#include "pugixml.hpp"

using namespace std;
using namespace pugi;

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")

void usage(const char *name) 
{
	fprintf(stderr, "Usage: %s -i <input_ofp_file> -o <output_dir>\n", name);
	fprintf(stderr, "Usage: %s -i <input_ofp_file> -o <output_dir> -k <aes_key> -s <aes_salt>\n", name);
	fprintf(stderr, "Usage: %s -i <input_ofp_file> -o <output_dir> -m <mc_key> -u <user_key> -v <salt_key>\n", name);
}

bool is_dir_exist(const string &path) 
{
	struct stat info;
	if (stat(path.c_str(), &info) != 0)
		return false;
	return (info.st_mode & S_IFDIR) != 0;
}
bool make_path(const string &path) 
{
	int ret = _mkdir(path.c_str());
	if (ret == 0)
		return true;
	switch(errno) 
	{
	case ENOENT: 
	{
		int pos = path.find_last_of('/');
		if (pos == string::npos)
			pos = path.find_last_of('\\');
		if (pos == string::npos)
			return false;
		if (!make_path(path.substr(0, pos)))
			return false;
	}
	return _mkdir(path.c_str()) == 0;
	case EEXIST: 
		return is_dir_exist(path);
	default:
		return false;
	}
}

int ror(int x, int n, int bits = 32) 
{
	int mask = (int)pow(2, n) - 1;
	int maskbits = x & mask;
	return (x >> n) | (maskbits << (bits - n));
}
uint8_t rol(int x, int n, int bits = 32) 
{
	return ror(x, bits - n, bits);
}

void shuffle(char *in, char *out, uint32_t length) 
{
	const char *key = "geyixue";
	for (unsigned int i = 0; i < length; i++) 
	{
		uint8_t h = ((in[i] & 0xf0) >> 4) | (16 * (in[i] & 0xf));
		out[i] = key[i % 7] ^ h;
	}
}

map<string, string> collect_keys() 
{
	map<string, string> m{ 
		{"ab3f76d7989207f2", "2bf515b3a9737835"},
	{"d154afeeaafa958f", "2c040f5786829207"},
	{"94d62e831cf1a1a0", "7ab5e33bd50d81ca"},
	{"4a837229e6fc77d4", "00bed47b80eec9d7"},
	{"2e96d7f462591a0f", "17cc63224c208708"},
	{"3398699acebda0da", "b39a46f5cc4f0d45"},
	{"52dddab2c46aab56", "35f19b6877f9c360"},
	{"403200d7e3ccbd16", "e6a12148a4d75e7d"},
	{"264f527f9ad1ae8c", "788391d4ae2fd10c"},
	{"443ec2fc7f543de6", "f02df2210580c734"},
	{"be594eab795ccc85", "2016267766ad552b"},
	{"1c1ca204c41d4f83", "916e63a107139707"} };

	return m;
}

#pragma pack(1)
struct hdr
{
	char proj_name[48];
	uint64_t unknown;
	uint32_t reserved;
	char cpu_type[7];
	char flash_type[5];
	uint16_t entries_count;
	char proj_info[32];
	uint16_t chksum;
};
struct entry
{
	char name[32];
	uint64_t offset;
	uint64_t rlen;
	uint64_t length;
	char filename[32];
	uint64_t chksum;
};
#pragma pack()

int decrypt(char *data, int len, string key, string iv) 
{
	AES_KEY aes_key;
	int pos = 0;

	unsigned char buff[4096];
	AES_set_encrypt_key((const unsigned char*)key.c_str(), 128, &aes_key);

	size_t offset = 0;
	while (len) 
	{
		size_t rlen = min(len, 4096);
		AES_cfb128_encrypt((unsigned char*)data + offset, buff, rlen, &aes_key, (unsigned char*)iv.c_str(), &pos, 0);
		memcpy(data + offset, buff, rlen);
		len -= rlen;
		offset += rlen;
	}
	return offset;
}
int decrypt_data(ifstream *in, const char *key, const char *iv, string filename, string output_path, uint64_t offset, uint64_t len, uint64_t rlen, uint64_t dlen) 
{
	ofstream out(output_path.c_str(), ios::binary);
	uint64_t min = 0, max = max(len, rlen);
	size_t size = (size_t)min(dlen, len), tmpsize = size;
	
	char *buffer = (char*)calloc(sizeof(char), tmpsize);

	in->seekg(offset, in->beg);
	in->read(buffer, size);
	decrypt(buffer, (int)size, key, iv);
	
	if (size == dlen) 
	{
		out.write(buffer, size);
		if (rlen > size) 
		{
			rlen -= size;
			if (rlen > 0) 
			{
				uint64_t rl = 0;
				while (rlen) 
				{
					size_t blklen = (size_t)min(rlen, dlen);
					uint64_t readblk = offset + dlen + rl;

					char *buff = (char*)calloc(sizeof(char), blklen);

					in->seekg(readblk, in->beg);
					in->read(buff, blklen);
					out.write(buff, blklen);
					free(buff);
					
					rl += blklen;
					min += blklen;
					rlen -= blklen;

					fprintf(stdout, "Extracting %s: %.2f%%\r", filename.c_str(), (double)min/max*100);
				}
			}
		}
	}
	else 
	{
		out.write(buffer, rlen);
	}

	fprintf(stdout, "%c[2K", 27);
	fprintf(stdout, "Extracting %s: DONE", filename.c_str());
	fflush(stdout);
		
	free(buffer);
	out.close();

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 5) 
	{
		usage(argv[0]);
		return -1;
	}

	const char *input = 0, *output = 0, *master_key = 0, *user_key = 0, *salt_key = 0;
	char *aes_key = 0, *aes_salt = 0;

	for (int i = 1; i < (argc-1); i+=2) 
	{
		if (strncmp(argv[i], "-i", 2) == 0)
			input = argv[i + 1];
		else if (strncmp(argv[i], "-o", 2) == 0)
			output = argv[i + 1];
		else if (strncmp(argv[i], "-k", 2) == 0)
			aes_key = argv[i + 1];
		else if (strncmp(argv[i], "-s", 2) == 0)
			aes_salt = argv[i + 1];
		else if (strncmp(argv[i], "-m", 2) == 0)
			master_key = argv[i + 1];
		else if (strncmp(argv[i], "-u", 2) == 0)
			user_key = argv[i + 1];
		else if (strncmp(argv[i], "-v", 2) == 0)
			salt_key = argv[i + 1];
	}

	if (!input) 
	{
		fprintf(stderr, "Input ofp file is not defined.\n");
		usage(argv[0]);
		return -1;
	}
	if (!output) 
	{
		fprintf(stderr, "Output dir is not defined.\n");
		usage(argv[0]);
		return -1;
	}
	
	string output_path(output);
	if (!is_dir_exist(output_path)) 
	{
		if (!make_path(output_path)) 
		{
			fprintf(stderr, "Can't create output directory.\n");
			usage(argv[0]);
			return -1;
		}
	}
		
	int type = 0;
	if (master_key && user_key && salt_key)
		type = 1;
	if (aes_key && aes_salt)
		type = 2;

	enum ofp_type
	{
		UNKNOWN,
		QUALCOMM,
		MTK
	} file_type = UNKNOWN;

	int sector_size = 512;
	int64_t offset = 0; int length = 16;
	hdr h = { 0 };
	entry e = { 0 };

	ifstream is(input, ios::binary);
	is.seekg(0, is.end);
	uint64_t filesize = is.tellg();
	is.seekg(0, is.beg);

	while (true) 
	{
		uint32_t check = 0;
		is.seekg(filesize - sector_size + 16, is.beg);
		is.read((char*)&check, sizeof(uint32_t));

		if (check == 0x7cef) 
		{
			is.read((char*)&offset, sizeof(uint32_t));
			is.read((char*)&length, sizeof(uint32_t));
			offset *= sector_size;
			break;
		}
		if (sector_size == 4096)
			break;
		sector_size = 4096;
	}

	int ret = 0;
	char *buffer = (char*)malloc(length);

	switch(type) 
	{
	case 0: 
	{
		map<string, string> keys = collect_keys();
		map<string, string>::iterator it = keys.begin();
		while (it != keys.end()) 
		{	
			aes_key = new char[it->first.size() + 1];
			aes_salt = new char[it->second.size() + 1];

			copy(it->first.begin(), it->first.end(), aes_key);
			copy(it->second.begin(), it->second.end(), aes_salt);

			aes_key[it->first.size()] = '\0';
			aes_salt[it->second.size()] = '\0';
						
			is.seekg(offset, is.beg);
			is.read(buffer, length);
			
			ret = decrypt(buffer, length, aes_key, aes_salt);

			if (strncmp(buffer, "<?xml", 5) == 0) 
				file_type = QUALCOMM;
			else if (strncmp(buffer, "MMM", 3) == 0) 
				file_type = MTK;
			
			if (file_type != UNKNOWN)
				break;
			
			it++;
		}

		if (file_type == UNKNOWN) 
		{
			fprintf(stderr, "Decrypted key not found.\n");
			return -1;
		}
	} break;
	case 1: 
	{
		char *akey = new char[16];
		char *aiv = new char[16];
		for (size_t i = 0; i < strlen(user_key); i++) 
		{
			akey[i] = rol(user_key[i] ^ master_key[i], 4, 8);
			aiv[i] = rol(salt_key[i] ^ master_key[i], 4, 8);
		}

		aes_key = akey;
		aes_salt = aiv;

		is.seekg(offset, is.beg);
		is.read(buffer, length);

		ret = decrypt(buffer, length, aes_key, aes_salt);

		if (strncmp(buffer, "<?xml", 5) == 0)
			file_type = QUALCOMM;
		else if (strncmp(buffer, "MMM", 3) == 0)
			file_type = MTK;
		else
		{
			fprintf(stderr, "Wrong keys.\n");
			return -1;
		}
	} break;
	case 2: 
	{
		is.seekg(offset, is.beg);
		is.read(buffer, length);

		ret = decrypt(buffer, length, aes_key, aes_salt);

		if (strncmp(buffer, "<?xml", 5) == 0)
			file_type = QUALCOMM;
		else if (strncmp(buffer, "MMM", 3) == 0)
			file_type = MTK;
		else
		{
			fprintf(stderr, "Wrong keys.\n");
			return -1;
		}
	} break;
	}
		
	switch(file_type) 
	{
	case QUALCOMM: 
	{
		xml_document doc;
		xml_parse_result result = doc.load_buffer(buffer, (size_t)length);
		if (result.status != status_ok) 
		{
			fprintf(stderr, "Failed to read xml nodes.\n");
			return -1;
		}

		xml_node profile = doc.child("ProFile");
		for (xml_node node : profile.children()) 
		{
			if (strncmp(node.name(), "Sahara", 6) == 0) 
			{
				for (xml_node_iterator it = node.begin(); it != node.end(); ++it) 
				{
					if (strncmp(it->name(), "File", 4) == 0) 
					{
						string filename;
						uint64_t offset = 0, len = 0, rlen = 0, dlen = 0x40000;

						for (xml_attribute_iterator ait = it->attributes_begin(); ait != it->attributes_end(); ++ait) 
						{
							if (strncmp(ait->name(), "Path", 4) == 0)
								filename = ait->as_string();
							else if (strncmp(ait->name(), "FileOffsetInSrc", 15) == 0)
								offset = ait->as_ullong() * sector_size;
							else if (strncmp(ait->name(), "SizeInSectorInSrc", 17) == 0)
								len = ait->as_ullong() * sector_size;
							else if (strncmp(ait->name(), "SizeInByteInSrc", 15) == 0)
								rlen = ait->as_ullong();
						}
					
						if (filename.empty() || len == 0 || rlen == 0)
							continue;

						string save_path = output_path + "\\" + filename;
						fprintf(stdout, "\n");

						if (strncmp(filename.c_str(), "prog_", 5) == 0)
							dlen = rlen;

						ret = decrypt_data(&is, aes_key, aes_salt, filename, save_path, offset, len, rlen, dlen);
						if (ret != 0)
							return -1;
					}
				}
			}
			else
			{
				for (xml_node_iterator it = node.begin(); it != node.end(); ++it) 
				{
					if (strncmp(it->name(), "config", 6) == 0) 
					{
						string filename;
						uint64_t offset = 0, len = 0, rlen = 0, dlen = 0x40000;

						for (xml_attribute_iterator ait = it->attributes_begin(); ait != it->attributes_end(); ++ait)
						{
							if (strncmp(ait->name(), "filename", 8) == 0)
								filename = ait->as_string();
							else if (strncmp(ait->name(), "SizeInSectorInSrc", 17) == 0)
								offset = ait->as_ullong() * sector_size;
							else if (strncmp(ait->name(), "SizeInByteInSrc", 15) == 0)
							{
								rlen = ait->as_ullong();
								len = rlen;
							}
						}
					
						if (filename.empty() || len == 0 || rlen == 0)
							continue;

						string save_path = output_path + "\\" + filename;
						fprintf(stdout, "\n");

						if (strncmp(filename.c_str(), "prog_", 5) == 0)
							dlen = rlen;

						ret = decrypt_data(&is, aes_key, aes_salt, filename, save_path, offset, len, rlen, dlen);
						if (ret != 0)
							return -1;
					}
					else if (strncmp(it->name(), "allfile", 7) == 0 || strncmp(it->name(), "program", 7) == 0 || strncmp(it->name(), "data", 4) == 0) 
					{
						string filename;
						uint64_t offset = 0, len = 0, rlen = 0, dlen = 0x40000;

						for (xml_attribute_iterator ait = it->attributes_begin(); ait != it->attributes_end(); ++ait)
						{
							if (strncmp(ait->name(), "filename", 8) == 0)
								filename = ait->as_string();
							else if (strncmp(ait->name(), "FileOffsetInSrc", 15) == 0)
								offset = ait->as_ullong() * sector_size;
							else if (strncmp(ait->name(), "SizeInSectorInSrc", 17) == 0)
								len = ait->as_ullong() * sector_size;
							else if (strncmp(ait->name(), "SizeInByteInSrc", 15) == 0)
								rlen = ait->as_ullong();
						}

						if (filename.empty() || len == 0 || rlen == 0)
							continue;

						string save_path = output_path + "\\" + filename;
						fprintf(stdout, "\n");

						if (strncmp(filename.c_str(), "prog_", 5) == 0)
							dlen = rlen;

						ret = decrypt_data(&is, aes_key, aes_salt, filename, save_path, offset, len, rlen, dlen);
						if (ret != 0)
							return -1;
					}
				}
			}
		}

		fprintf(stdout, "\n\nAll done!");
	} break;
	case MTK: 
	{
		buffer = (char*)realloc(buffer, sizeof(hdr));

		is.seekg(filesize - sizeof(hdr));
		is.read(buffer, sizeof(hdr));
		
		shuffle(buffer, (char*)&h, sizeof(hdr));
		
		size_t l = h.entries_count * sizeof(entry);

		buffer = (char*)realloc(buffer, l);

		is.seekg(filesize - l - sizeof(hdr));
		is.read(buffer, l);

		shuffle(buffer, buffer, l);
				
		for (uint16_t i = 0; i < h.entries_count; i++) 
		{
			e = {};
			memcpy(&e, buffer + (i * sizeof(entry)), sizeof(entry));
						
			string lbl(e.name, strlen(e.name));
			string fn(e.filename, strlen(e.filename));
			string save_path = output_path + "\\" + fn;

			fprintf(stdout, "\n");
						
			ret = decrypt_data(&is, aes_key, aes_salt, fn, save_path, e.offset, e.length, e.rlen, 0x40000);
			if (ret != 0)
				return -1;
		}

		fprintf(stdout, "\n\nAll done!");
	} break;
	default: break;
	}

	return 0;
}

