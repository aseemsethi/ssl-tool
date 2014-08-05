/*
 *	sslv3.c
 *	Release $Name: MATRIXSSL_1_8_6_OPEN $
 *
 *	SSLv3.0 specific code per http://wp.netscape.com/eng/ssl3.
 *	Primarily dealing with secret generation, message authentication codes
 *	and handshake hashing.
 */
/*
 *	Copyright (c) PeerSec Networks, 2002-2008. All Rights Reserved.
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software 
 *	into proprietary programs.  If you are unable to comply with the GPL, a 
 *	commercial license for this software may be purchased from PeerSec Networks
 *	at http://www.peersec.com
 *	
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	See the GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/
#include "ssl.h"

/******************************************************************************/
/*
	Constants used for key generation
*/
static const unsigned char SENDER_CLIENT[5] = "CLNT";	/* 0x434C4E54 */
static const unsigned char SENDER_SERVER[5] = "SRVR";	/* 0x53525652 */

static const unsigned char pad1[48]={
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 
};

static const unsigned char pad2[48]={
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
};

static const unsigned char *salt[10]={
	(const unsigned char *)"A",
	(const unsigned char *)"BB",
	(const unsigned char *)"CCC",
	(const unsigned char *)"DDDD",
	(const unsigned char *)"EEEEE",
	(const unsigned char *)"FFFFFF",
	(const unsigned char *)"GGGGGGG",
	(const unsigned char *)"HHHHHHHH",
	(const unsigned char *)"IIIIIIIII",
	(const unsigned char *)"JJJJJJJJJJ"
};

/******************************************************************************/
/*
	Combine the running hash of the handshake mesages with some constants
	and mix them up a bit more.  Output the result to the given buffer.
	This data will be part of the Finished handshake message.
*/
int sslGenerateFinishedHash (MD5_CTX *md5, SHA_CTX *sha1, 
				unsigned char *masterSecret, unsigned char *out)
{
#define SSL_HS_MASTER_SIZE 48
#define SSL_SHA1_HASH_SIZE 20
#define SSL_MD5_HASH_SIZE 16

	MD5_CTX			omd5;
	SHA_CTX			osha1;

	unsigned char	ihash[SSL_SHA1_HASH_SIZE];

/*
	md5Hash = MD5(master_secret + pad2 + 
		MD5(handshake_messages + sender + master_secret + pad1));
*/
	MD5_Update(md5, SENDER_CLIENT, 4);
	MD5_Update(md5, masterSecret, SSL_HS_MASTER_SIZE);
	MD5_Update(md5, pad1, sizeof(pad1));
	MD5_Final(ihash, md5);

	MD5_Init(&omd5);
	MD5_Update(&omd5, masterSecret, SSL_HS_MASTER_SIZE);
	MD5_Update(&omd5, pad2, sizeof(pad2));
	MD5_Update(&omd5, ihash, SSL_MD5_HASH_SIZE);
	MD5_Final(out, &omd5);
/*
	The SHA1 hash is generated in the same way, except only 40 bytes
	of pad1 and pad2 are used.
	sha1Hash = SHA1(master_secret + pad2 + 
		SHA1(handshake_messages + sender + master_secret + pad1));
*/
	SHA1_Update(sha1, SENDER_CLIENT, 4);
	SHA1_Update(sha1, masterSecret, SSL_HS_MASTER_SIZE);
	SHA1_Update(sha1, pad1, 40);
	SHA1_Final(ihash, sha1);

	SHA1_Init(&osha1);
	SHA1_Update(&osha1, masterSecret, SSL_HS_MASTER_SIZE);
	SHA1_Update(&osha1, pad2, 40);
	SHA1_Update(&osha1, ihash, SSL_SHA1_HASH_SIZE);
	SHA1_Final(out + SSL_MD5_HASH_SIZE, &osha1);

	return SSL_MD5_HASH_SIZE + SSL_SHA1_HASH_SIZE;
}
