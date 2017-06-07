/* Copyright 2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <stdbool.h>
#include "container.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <sysexits.h>

char *progname;
int debug;

void usage(int status);

void printBytes(char *lead, unsigned char *buffer, size_t buflen, int wrap)
{
	unsigned int i;
	unsigned int leadbytes = strlen(lead);
	leadbytes = leadbytes > 30 ? 30 : leadbytes;

	fprintf (stderr, "%s", lead);
	for (i = 1; i < buflen + 1; i++) {
		fprintf (stderr, "%02x", buffer[i - 1]);
		if (((i % wrap) == 0) && (i < buflen))
			fprintf (stderr, "\n%*c", leadbytes, ' ');
	}
	fprintf (stderr, "\n");
}

bool stb_is_container(const void *buf, size_t size)
{
	ROM_container_raw *c;

	c = (ROM_container_raw*) buf;
	if (!buf || size < SECURE_BOOT_HEADERS_SIZE)
		return false;
	if (be32_to_cpu(c->magic_number) != ROM_MAGIC_NUMBER )
		return false;
	return true;
}

int parse_stb_container(const void* data, size_t len, struct parsed_stb_container *c)
{
	const size_t prefix_data_min_size = 3 * (EC_COORDBYTES * 2);
	c->buf = data;
	c->bufsz = len;
	c->c = data;
	c->ph = data += sizeof(ROM_container_raw);
	c->pd = data += sizeof(ROM_prefix_header_raw) + (c->ph->ecid_count * ECID_SIZE);
	c->sh = data += prefix_data_min_size + c->ph->sw_key_count * (EC_COORDBYTES * 2);
	c->ssig = data += sizeof(ROM_sw_header_raw) +
		c->sh->ecid_count * ECID_SIZE;

	return 0;
}

static void display_version_raw(const ROM_version_raw v)
{
	printf("ver_alg:\n");
	printf("  version:  %04x\n", be16_to_cpu(v.version));
	printf("  hash_alg: %02x (%s)\n", v.hash_alg, (v.hash_alg == 1)? "SHA512" : "UNKNOWN");
	printf("  sig_alg:  %02x (%s)\n", v.sig_alg, (v.sig_alg == 1) ? "SHA512/ECDSA-521" : "UNKNOWN");
}

static void display_sha2_hash_t(const sha2_hash_t h)
{
	int i;
	for(i=0; i<SHA512_DIGEST_LENGTH; i++)
		printf("%02x", h[i]);
}

static void display_ecid(const uint8_t *ecid)
{
	for(int i=0; i<ECID_SIZE; i++)
		printf("%02x", ecid[i]);
}

static void display_prefix_header(const ROM_prefix_header_raw *p)
{
	printf("Prefix Header:\n");
	display_version_raw(p->ver_alg);
	printf("code_start_offset: %08lx\n", be64_to_cpu(p->code_start_offset));
	printf("reserved:          %08lx\n", be64_to_cpu(p->reserved));
	printf("flags:             %08x\n",  be32_to_cpu(p->flags));
	printf("sw_key_count:      %02x\n", p->sw_key_count);
	printf("payload_size:      %08lx\n", be64_to_cpu(p->payload_size));
	printf("payloah_hash:      ");
	display_sha2_hash_t(p->payload_hash);
	printf("\n");
	printf("ecid_count:        %02x\n", p->ecid_count);
	for(int i=0; i< p->ecid_count; i++) {
		printf("ecid:              ");
		display_ecid(p->ecid[i].ecid);
		printf("\n");
	}
}

static void display_sw_header(const ROM_sw_header_raw *swh)
{
	printf("Software Header:\n");
	display_version_raw(swh->ver_alg);
	printf("code_start_offset: %08lx\n", be64_to_cpu(swh->code_start_offset));
	printf("reserved:          %08lx\n", be64_to_cpu(swh->reserved));
	printf("flags:             %08x\n", be32_to_cpu(swh->flags));
	printf("reserved_0:        %02x\n", swh->reserved_0);
	printf("payload_size:      %08lx (%lu)\n", be64_to_cpu(swh->payload_size), be64_to_cpu(swh->payload_size));
	printf("payloah_hash:      ");
	display_sha2_hash_t(swh->payload_hash);
	printf("\n");
	printf("ecid_count:        %02x\n", swh->ecid_count);

	for(int i=0; i< swh->ecid_count; i++) {
		printf("ecid:              ");
		display_ecid(swh->ecid[i].ecid);
		printf("\n");
	}
}

static void display_ec_coord(const uint8_t *e)
{
	for(int i=0; i<EC_COORDBYTES*2; i++)
		printf("%02x", e[i]);
}

static void display_prefix_data(const int sw_key_count, const ROM_prefix_data_raw *pd)
{
	printf("Prefix Data:\n");
	printf("hw_sig_a:  "); display_ec_coord(pd->hw_sig_a); printf("\n");
	printf("hw_sig_b:  "); display_ec_coord(pd->hw_sig_b); printf("\n");
	printf("hw_sig_c:  "); display_ec_coord(pd->hw_sig_c); printf("\n");
	if (sw_key_count >=1) {
		printf("sw_pkey_p: "); display_ec_coord(pd->sw_pkey_p); printf("\n");
	}
	if (sw_key_count >=2) {
		printf("sw_pkey_q: "); display_ec_coord(pd->sw_pkey_q); printf("\n");
	}
	if (sw_key_count >=3) {
		printf("sw_pkey_r: "); display_ec_coord(pd->sw_pkey_r); printf("\n");
	}
}

static void display_sw_sig(const ROM_sw_sig_raw *s)
{
	printf("Software Signatures:\n");
	printf("sw_sig_p: "); display_ec_coord(s->sw_sig_p); printf("\n");
	printf("sw_sig_q: "); display_ec_coord(s->sw_sig_q); printf("\n");
	printf("sw_sig_r: "); display_ec_coord(s->sw_sig_r); printf("\n");
}

static void display_rom_container_raw(const ROM_container_raw *rcr)
{
	printf("Container:\n");
	printf("magic:          0x%04x\n", be32_to_cpu(rcr->magic_number));
	printf("version:        0x%02x\n", be16_to_cpu(rcr->version));
	printf("container_size: 0x%08lx (%lu)\n", be64_to_cpu(rcr->container_size), be64_to_cpu(rcr->container_size));
	printf("target_hrmor:   0x%08lx\n", be64_to_cpu(rcr->target_hrmor));
	printf("stack_pointer:  0x%08lx\n", be64_to_cpu(rcr->stack_pointer));
	printf("hw_pkey_a: ");
	for(int i=0; i < EC_COORDBYTES*2; i++)
		printf("%02x", rcr->hw_pkey_a[i]);
	printf("\n");
	printf("hw_pkey_b: ");
	for(int i=0; i < EC_COORDBYTES*2; i++)
		printf("%02x", rcr->hw_pkey_b[i]);
	printf("\n");
	printf("hw_pkey_c: ");
	for(int i=0; i < EC_COORDBYTES*2; i++)
		printf("%02x", rcr->hw_pkey_c[i]);
	printf("\n");
}

static void display_container(char* f)
{
	int fd = open(f, O_RDONLY);
	void *container = malloc(SECURE_BOOT_HEADERS_SIZE);
	struct parsed_stb_container c;
	size_t sz;

	assert(container);
	if (fd == -1) {
		perror(strerror(errno));
		exit(EXIT_FAILURE);
	}

	sz = read(fd, container, SECURE_BOOT_HEADERS_SIZE);
	if (sz != SECURE_BOOT_HEADERS_SIZE) {
		perror(strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!stb_is_container(container, SECURE_BOOT_HEADERS_SIZE)) {
		fprintf(stderr, "Not a container, missing magic number\n");
		exit(EXIT_FAILURE);
	}

	if (parse_stb_container(container, SECURE_BOOT_HEADERS_SIZE, &c) != 0) {
		fprintf(stderr, "Failed to parse container.\n");
		exit(EXIT_FAILURE);
	}

	display_rom_container_raw(c.c);
	printf("\n");

	display_prefix_header(c.ph);
	printf("\n");

	display_prefix_data(c.ph->sw_key_count, c.pd);
	printf("\n");

	display_sw_header(c.sh);
	printf("\n");

	display_sw_sig(c.ssig);

	free(container);
	close(fd);
}

__attribute__((__noreturn__)) void usage (int status)
{
	if (status != 0) {
			fprintf(stderr, "Try '%s --help' for more information.\n", progname);
	}
	else {
		printf("Usage: %s [options]\n", progname);
		printf(
			"\n"
			"Options:\n"
			" -d, --debug             show additional debug info\n"
			" -h, --help              display this message and exit\n"
			" -I, --imagefile         file to write containerized payload (output)\n"
			"\n");
	};
	exit(status);
}

static struct option const opts[] = {
	{ "debug",            no_argument,       0,  'd' },
	{ "help",             no_argument,       0,  'h' },
	{ "imagefile",        required_argument, 0,  'I' },
	{}
};

static struct {
	char *imagefn;
} params;


int main(int argc, char* argv[])
{
	int indexptr;

	progname = strrchr (argv[0], '/');
	if (progname != NULL)
		++progname;
	else
		progname = argv[0];

	while (1) {
		int opt;
		opt = getopt_long(argc, argv, "I:dh", opts, &indexptr);
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
		case '?':
			usage(EX_OK);
			break;
		case 'd':
			debug = 1;
			break;
		case 'I':
			params.imagefn = optarg;
			break;
		default:
			usage(EX_USAGE);
		}
	}

	display_container(params.imagefn);

	return 0;
}
