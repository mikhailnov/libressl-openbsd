/* $OpenBSD: gost89_params.c,v 1.2 2014/11/09 23:06:52 miod Exp $ */
/*
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdlib.h>

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST
#include <openssl/objects.h>
#include <openssl/gost.h>

#include "gost_locl.h"

/* Substitution blocks from test examples for GOST R 34.11-94*/
static const gost_subst_block GostR3411_94_TestParamSet = {
	{0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC},
	{0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC},
	{0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE},
	{0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2},
	{0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3},
	{0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB},
	{0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9},
	{0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3}
};

/* Substitution blocks for hash function 1.2.643.2.9.1.6.1  */
static const gost_subst_block GostR3411_94_CryptoProParamSet = {
	{0x1,0x3,0xA,0x9,0x5,0xB,0x4,0xF,0x8,0x6,0x7,0xE,0xD,0x0,0x2,0xC},
	{0xD,0xE,0x4,0x1,0x7,0x0,0x5,0xA,0x3,0xC,0x8,0xF,0x6,0x2,0x9,0xB},
	{0x7,0x6,0x2,0x4,0xD,0x9,0xF,0x0,0xA,0x1,0x5,0xB,0x8,0xE,0xC,0x3},
	{0x7,0x6,0x4,0xB,0x9,0xC,0x2,0xA,0x1,0x8,0x0,0xE,0xF,0xD,0x3,0x5},
	{0x4,0xA,0x7,0xC,0x0,0xF,0x2,0x8,0xE,0x1,0x6,0x5,0xD,0xB,0x9,0x3},
	{0x7,0xF,0xC,0xE,0x9,0x4,0x1,0x0,0x3,0xB,0x5,0x2,0x6,0xA,0x8,0xD},
	{0x5,0xF,0x4,0x0,0x2,0xD,0xB,0x9,0x1,0x7,0x6,0x3,0xC,0xE,0xA,0x8},
	{0xA,0x4,0x5,0x6,0x8,0x1,0x3,0x7,0xD,0xC,0xE,0x0,0x9,0x2,0xB,0xF}
};

/* Test paramset from GOST 28147 */
gost_subst_block Gost28147_TestParamSet = {
	{0xC,0x6,0x5,0x2,0xB,0x0,0x9,0xD,0x3,0xE,0x7,0xA,0xF,0x4,0x1,0x8},
	{0x9,0xB,0xC,0x0,0x3,0x6,0x7,0x5,0x4,0x8,0xE,0xF,0x1,0xA,0x2,0xD},
	{0x8,0xF,0x6,0xB,0x1,0x9,0xC,0x5,0xD,0x3,0x7,0xA,0x0,0xE,0x2,0x4},
	{0x3,0xE,0x5,0x9,0x6,0x8,0x0,0xD,0xA,0xB,0x7,0xC,0x2,0x1,0xF,0x4},
	{0xE,0x9,0xB,0x2,0x5,0xF,0x7,0x1,0x0,0xD,0xC,0x6,0xA,0x4,0x3,0x8},
	{0xD,0x8,0xE,0xC,0x7,0x3,0x9,0xA,0x1,0x5,0x2,0x4,0x6,0xF,0x0,0xB},
	{0xC,0x9,0xF,0xE,0x8,0x1,0x3,0xA,0x2,0x7,0x4,0xD,0x6,0x0,0xB,0x5},
	{0x4,0x2,0xF,0x5,0x9,0x1,0x0,0x8,0xE,0x3,0xB,0xC,0xD,0x7,0xA,0x6}
};


/* 1.2.643.2.2.31.1 */
static const gost_subst_block Gost28147_CryptoProParamSetA = {
	{0xB,0xA,0xF,0x5,0x0,0xC,0xE,0x8,0x6,0x2,0x3,0x9,0x1,0x7,0xD,0x4},
	{0x1,0xD,0x2,0x9,0x7,0xA,0x6,0x0,0x8,0xC,0x4,0x5,0xF,0x3,0xB,0xE},
	{0x3,0xA,0xD,0xC,0x1,0x2,0x0,0xB,0x7,0x5,0x9,0x4,0x8,0xF,0xE,0x6},
	{0xB,0x5,0x1,0x9,0x8,0xD,0xF,0x0,0xE,0x4,0x2,0x3,0xC,0x7,0xA,0x6},
	{0xE,0x7,0xA,0xC,0xD,0x1,0x3,0x9,0x0,0x2,0xB,0x4,0xF,0x8,0x5,0x6},
	{0xE,0x4,0x6,0x2,0xB,0x3,0xD,0x8,0xC,0xF,0x5,0xA,0x0,0x7,0x1,0x9},
	{0x3,0x7,0xE,0x9,0x8,0xA,0xF,0x0,0x5,0x2,0x6,0xC,0xB,0x4,0xD,0x1},
	{0x9,0x6,0x3,0x2,0x8,0xB,0x1,0x7,0xA,0x4,0xE,0xF,0xC,0x0,0xD,0x5}
};

/* 1.2.643.2.2.31.2 */
static const gost_subst_block Gost28147_CryptoProParamSetB = {
	{0x0,0x4,0xB,0xE,0x8,0x3,0x7,0x1,0xA,0x2,0x9,0x6,0xF,0xD,0x5,0xC},
	{0x5,0x2,0xA,0xB,0x9,0x1,0xC,0x3,0x7,0x4,0xD,0x0,0x6,0xF,0x8,0xE},
	{0x8,0x3,0x2,0x6,0x4,0xD,0xE,0xB,0xC,0x1,0x7,0xF,0xA,0x0,0x9,0x5},
	{0x2,0x7,0xC,0xF,0x9,0x5,0xA,0xB,0x1,0x4,0x0,0xD,0x6,0x8,0xE,0x3},
	{0x7,0x5,0x0,0xD,0xB,0x6,0x1,0x2,0x3,0xA,0xC,0xF,0x4,0xE,0x9,0x8},
	{0xE,0xC,0x0,0xA,0x9,0x2,0xD,0xB,0x7,0x5,0x8,0xF,0x3,0x6,0x1,0x4},
	{0x0,0x1,0x2,0xA,0x4,0xD,0x5,0xC,0x9,0x7,0x3,0xF,0xB,0x8,0x6,0xE},
	{0x8,0x4,0xB,0x1,0x3,0x5,0x0,0x9,0x2,0xE,0xA,0xC,0xD,0x6,0x7,0xF}
};

/* 1.2.643.2.2.31.3 */
static const gost_subst_block Gost28147_CryptoProParamSetC = {
	{0x7,0x4,0x0,0x5,0xA,0x2,0xF,0xE,0xC,0x6,0x1,0xB,0xD,0x9,0x3,0x8},
	{0xA,0x9,0x6,0x8,0xD,0xE,0x2,0x0,0xF,0x3,0x5,0xB,0x4,0x1,0xC,0x7},
	{0xC,0x9,0xB,0x1,0x8,0xE,0x2,0x4,0x7,0x3,0x6,0x5,0xA,0x0,0xF,0xD},
	{0x8,0xD,0xB,0x0,0x4,0x5,0x1,0x2,0x9,0x3,0xC,0xE,0x6,0xF,0xA,0x7},
	{0x3,0x6,0x0,0x1,0x5,0xD,0xA,0x8,0xB,0x2,0x9,0x7,0xE,0xF,0xC,0x4},
	{0x8,0x2,0x5,0x0,0x4,0x9,0xF,0xA,0x3,0x7,0xC,0xD,0x6,0xE,0x1,0xB},
	{0x0,0x1,0x7,0xD,0xB,0x4,0x5,0x2,0x8,0xE,0xF,0xC,0x9,0xA,0x6,0x3},
	{0x1,0xB,0xC,0x2,0x9,0xD,0x0,0xF,0x4,0x5,0x8,0xE,0xA,0x7,0x6,0x3}
};

/* 1.2.643.2.2.31.4 */
static const gost_subst_block Gost28147_CryptoProParamSetD = {
	{0x1,0xA,0x6,0x8,0xF,0xB,0x0,0x4,0xC,0x3,0x5,0x9,0x7,0xD,0x2,0xE},
	{0x3,0x0,0x6,0xF,0x1,0xE,0x9,0x2,0xD,0x8,0xC,0x4,0xB,0xA,0x5,0x7},
	{0x8,0x0,0xF,0x3,0x2,0x5,0xE,0xB,0x1,0xA,0x4,0x7,0xC,0x9,0xD,0x6},
	{0x0,0xC,0x8,0x9,0xD,0x2,0xA,0xB,0x7,0x3,0x6,0x5,0x4,0xE,0xF,0x1},
	{0x1,0x5,0xE,0xC,0xA,0x7,0x0,0xD,0x6,0x2,0xB,0x4,0x9,0x3,0xF,0x8},
	{0x1,0xC,0xB,0x0,0xF,0xE,0x6,0x5,0xA,0xD,0x4,0x8,0x9,0x3,0x7,0x2},
	{0xB,0x6,0x3,0x4,0xC,0xF,0xE,0x2,0x7,0xD,0x8,0x0,0x5,0xA,0x9,0x1},
	{0xF,0xC,0x2,0xA,0x6,0x4,0x5,0x0,0x7,0x9,0xE,0xD,0x1,0xB,0x8,0x3}
};

static const gost_subst_block Gost28147_TC26ParamSetZ = {
	{0x1,0x7,0xe,0xd,0x0,0x5,0x8,0x3,0x4,0xf,0xa,0x6,0x9,0xc,0xb,0x2},
	{0x8,0xe,0x2,0x5,0x6,0x9,0x1,0xc,0xf,0x4,0xb,0x0,0xd,0xa,0x3,0x7},
	{0x5,0xd,0xf,0x6,0x9,0x2,0xc,0xa,0xb,0x7,0x8,0x1,0x4,0x3,0xe,0x0},
	{0x7,0xf,0x5,0xa,0x8,0x1,0x6,0xd,0x0,0x9,0x3,0xe,0xb,0x4,0x2,0xc},
	{0xc,0x8,0x2,0x1,0xd,0x4,0xf,0x6,0x7,0x0,0xa,0x5,0x3,0xe,0x9,0xb},
	{0xb,0x3,0x5,0x8,0x2,0xf,0xa,0xd,0xe,0x1,0x7,0x4,0xc,0x9,0x6,0x0},
	{0x6,0x8,0x2,0x3,0x9,0xa,0x5,0xc,0x1,0xe,0x4,0x7,0xb,0xd,0x0,0xf},
	{0xc,0x4,0x6,0x2,0xa,0x5,0xb,0x9,0xe,0x8,0xd,0x7,0x0,0x3,0xf,0x1}
};

static const unsigned char CryptoProKeyMeshingKey[] = {
	0x69, 0x00, 0x72, 0x22,   0x64, 0xC9, 0x04, 0x23,
	0x8D, 0x3A, 0xDB, 0x96,   0x46, 0xE9, 0x2A, 0xC4,
	0x18, 0xFE, 0xAC, 0x94,   0x00, 0xED, 0x07, 0x12,
	0xC0, 0x86, 0xDC, 0xC2,   0xEF, 0x4C, 0xA9, 0x2B
};

static const struct gost89_parameters_info {
	int nid;
	const gost_subst_block *sblock;
	int key_meshing;
} gost_cipher_list[] =
{
	{NID_id_Gost28147_89_CryptoPro_A_ParamSet,&Gost28147_CryptoProParamSetA,1},
	{NID_id_Gost28147_89_CryptoPro_B_ParamSet,&Gost28147_CryptoProParamSetB,1},
	{NID_id_Gost28147_89_CryptoPro_C_ParamSet,&Gost28147_CryptoProParamSetC,1},
	{NID_id_Gost28147_89_CryptoPro_D_ParamSet,&Gost28147_CryptoProParamSetD,1},
	{NID_id_tc26_gost_28147_param_Z,&Gost28147_TC26ParamSetZ,1},
	{NID_id_Gost28147_89_TestParamSet,&Gost28147_TestParamSet,0},
	{NID_id_GostR3411_94_TestParamSet,&GostR3411_94_TestParamSet,0},
	{NID_id_GostR3411_94_CryptoProParamSet,&GostR3411_94_CryptoProParamSet,0},
	{NID_undef,NULL,0}
};

int
Gost2814789_set_sbox(GOST2814789_KEY *key, int nid)
{
	int i;
	const gost_subst_block *b = NULL;
	unsigned int t;

	for (i = 0; gost_cipher_list[i].nid != NID_undef; i++) {
		if (gost_cipher_list[i].nid != nid)
			continue;

		b = gost_cipher_list[i].sblock;
		key->key_meshing = gost_cipher_list[i].key_meshing ? 1024 : 0;
		break;
	}

	if (b == NULL)
		return 0;

	for (i = 0; i < 256; i++) {
		t = (unsigned int)(b->k8[i >> 4] <<4 | b->k7 [i & 15]) << 24;
		key->k87[i] = (t << 11) | (t >> 21);
		t = (unsigned int)(b->k6[i >> 4] <<4 | b->k5 [i & 15]) << 16;
		key->k65[i] = (t << 11) | (t >> 21);
		t = (unsigned int)(b->k4[i >> 4] <<4 | b->k3 [i & 15]) << 8;
		key->k43[i] = (t << 11) | (t >> 21);
		t = (unsigned int)(b->k2[i >> 4] <<4 | b->k1 [i & 15]) << 0;
		key->k21[i] = (t << 11) | (t >> 21);
	}

	return 1;
}

void
Gost2814789_set_key(GOST2814789_KEY *key, const unsigned char *userKey)
{
	int i;

	for (i = 0; i < 8; i++)
		c2l(userKey, key->key[i]);

	key->count = 0;
}

void
Magma_set_key_int(MAGMA_KEY *key, const unsigned char *userKey)
{
	int i;

	for (i = 0; i < 8; i++)
		be_c2l(userKey, key->key[i]);

	key->count = 0;
}

void
Magma_set_key(MAGMA_KEY *key, const unsigned char *userKey)
{
	unsigned int km = key->key_meshing;

	/* Preserve key meshing setting around setting sbox */
	Gost2814789_set_sbox(key, NID_id_tc26_gost_28147_param_Z);

	key->key_meshing = km;

	Magma_set_key_int(key, userKey);
}

void
Gost2814789_cryptopro_key_mesh(GOST2814789_KEY *key)
{
	unsigned char newkey[32];

	Gost2814789_decrypt(CryptoProKeyMeshingKey +  0, newkey +  0, key);
	Gost2814789_decrypt(CryptoProKeyMeshingKey +  8, newkey +  8, key);
	Gost2814789_decrypt(CryptoProKeyMeshingKey + 16, newkey + 16, key);
	Gost2814789_decrypt(CryptoProKeyMeshingKey + 24, newkey + 24, key);

	Gost2814789_set_key(key, newkey);
}
#endif
