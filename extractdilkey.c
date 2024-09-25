/* Copyright 2024 IBM Corp.
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

#include "crystals-oids.h"
#include "dilutils.h"
#include "mlca2.h"
#include "pqalgs.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 8000

int main(int argc, char** argv)
{
    size_t      sRawBytes  = BUF_SIZE;
    size_t      sKeyBytes  = BUF_SIZE;
    int         sRc        = 0;
    int         sIdx       = 0;
    int         sMlcaRet   = 0;
    bool        sPubIn     = false;
    bool        sPubOut    = false;
    bool        sRawIn     = false;
    bool        sRawOut    = false;
    const char* sInFile    = NULL;
    const char* sOutFile   = NULL;
    bool        sPrintHelp = false;
    bool        sVerbose   = false;

    for(sIdx = 1; sIdx < argc; sIdx++)
    {
        if(strcmp(argv[sIdx], "-h") == 0)
        {
            sPrintHelp = true;
        }
        else if(strcmp(argv[sIdx], "-k") == 0)
        {
            sIdx++;
            sInFile = argv[sIdx];
        }
        else if(strcmp(argv[sIdx], "-o") == 0)
        {
            sIdx++;
            sOutFile = argv[sIdx];
        }
        else if(strcmp(argv[sIdx], "-pubin") == 0)
        {
            sPubIn = true;
        }
        else if(strcmp(argv[sIdx], "-pubout") == 0)
        {
            sPubOut = true;
        }
        else if(strcmp(argv[sIdx], "-outraw") == 0)
        {
            sRawOut = true;
        }
        else if(strcmp(argv[sIdx], "-inraw") == 0)
        {
            sRawIn = true;
        }
        else if(strcmp(argv[sIdx], "-v") == 0)
        {
            sVerbose = true;
        }
        else
        {
            printf("**** ERROR : Unknown parameter : %s\n", argv[sIdx]);
            sPrintHelp = true;
        }
    }

    if(!sPrintHelp && (NULL == sInFile || (NULL == sOutFile && sRawOut)))
    {
        printf("**** ERROR : Invalid input parms\n");
        sPrintHelp = true;
    }

    if(sPrintHelp)
    {
        printf(
            "\nextractdilkey -k <input key> [-pubin] [-inraw] [-o <output filename> [-outraw]]\n");
        exit(0);
    }

    unsigned char* sRawKey = malloc(BUF_SIZE);
    unsigned char* sKey    = malloc(BUF_SIZE);

    if(!sRawKey || !sKey)
    {
        printf("**** ERROR : Allocation Failure\n");
        exit(1);
    }

    sRc = readFile(sKey, &sKeyBytes, sInFile);
    if(0 != sRc)
    {
        printf("**** ERROR : Unable to read from : %s\n", sInFile);
        sRc = 1;
    }
    if(sVerbose)
    {
        printf("extractdilkey: Key Size: %d\n", (int)sKeyBytes);
    }
    do
    {
        // Now validate our input
        if(0 == sRc && sPubIn)
        {
            if(sRawIn)
            {
                // We have a raw Dilithium R2 8x7 public key
                if(RawDilithiumR28x7PublicKeySize == sKeyBytes)
                {
                    // We have a raw public key, lets convert it
                    if(sVerbose)
                        printf("extractdilkey: Found raw public key\n");
                    memcpy(sRawKey, sKey, sKeyBytes);
                    sRawBytes = sKeyBytes;

                    sKeyBytes = BUF_SIZE;

                    // Convert public key
                    sMlcaRet = mlca_key2wire(
                        sKey, sKeyBytes, sRawKey, sRawBytes, 0, NULL, 0, NULL, 0);
                    if(sMlcaRet < 0)
                    {
                        printf("**** ERROR: Failure during public key conversion : %d\n", sMlcaRet);
                        sRc = 1;
                        break;
                    }
                    sKeyBytes = sMlcaRet;
                }
                // We have a raw MLDSA-87 public key
                else if(RawMldsa87PublicKeySize == sKeyBytes)
                {
                    // We have a raw public key, lets convert it
                    if(sVerbose)
                        printf("extractdilkey: Found raw public key\n");
                    memcpy(sRawKey, sKey, sKeyBytes);
                    sRawBytes = sKeyBytes;

                    sKeyBytes = BUF_SIZE;

                    // Convert public key
                    sMlcaRet = mlca_key2wire(
                        sKey, sKeyBytes, sRawKey, sRawBytes, 0, NULL, 0, NULL, 0);
                    if(sMlcaRet <= 0)
                    {
                        printf("**** ERROR: Failure during public key conversion : %d\n", sMlcaRet);
                        sRc = 1;
                        break;
                    }
                    sKeyBytes = sMlcaRet;
                }
                else
                {
                    printf("**** ERROR: Unrecognized raw public key : %s\n", sInFile);
                    sRc = 1;
                    break;
                }
            }
            else
            {
                // Attempt to convert encoded key
                unsigned int sWireType = 0;
                sMlcaRet = mlca_wire2key(sRawKey, sRawBytes, &sWireType, sKey, sKeyBytes, NULL, ~0);
                if(sVerbose)
                    printf("extractdilkey: Found public key\n");
                // We have a raw Dilithium R2 8x7 or MLDSA-87 public key
                if(RawDilithiumR28x7PublicKeySize != sMlcaRet
                   && RawMldsa87PublicKeySize != sMlcaRet)
                {
                    printf("**** ERROR: Unable to convert public key : %d\n", sMlcaRet);
                    sRc = 1;
                    break;
                }
                else
                {
                    sRawBytes = sMlcaRet;
                }
            }

            if(NULL != sOutFile)
            {
                printf("Writing public key to : %s\n", sOutFile);
                if(sRawOut)
                {
                    sRc = writeFile(sRawKey, sRawBytes, sOutFile);
                }
                else
                {
                    sRc = writeFile(sKey, sKeyBytes, sOutFile);
                }
            }
            else if (RawMldsa87PublicKeySize == sRawBytes)
            {
                printf("Valid MLDSA-87 public keyfile detected\n");
            }
            else
            {
                printf("Valid Dilithium public keyfile detected\n");
            }
        }

        // Private keys
        else if(0 == sRc && !sPubIn)
        {
            if(sRawIn)
            {
                // Raw private key size for dilithium r2 8/7
                if(RawDilithiumR28x7PrivateKeySize == sKeyBytes)
                {
                    if(sVerbose)
                        printf("extractdilkey: Found raw private key\n");
                    // We have a raw private key, lets convert it
                    memcpy(sRawKey, sKey, sKeyBytes);
                    sRawBytes = sKeyBytes;

                    sKeyBytes = BUF_SIZE;

                    // TODO , convert raw private key to encoded format without the public key
                    if(sOutFile)
                    {
                        sRc = 1;
                        printf("**** ERROR: Unable to convert private raw -> encoded\n");
                        break;
                    }
                }
                // Raw private key for mldsa 87
                else if(RawMldsa87PrivateKeySize == sKeyBytes)
                {

                    if(sVerbose)
                        printf("extractdilkey: Found raw private key\n");
                    // We have a raw private key, lets convert it
                    memcpy(sRawKey, sKey, sKeyBytes);
                    sRawBytes = sKeyBytes;

                    sKeyBytes = BUF_SIZE;

                    // TODO , convert raw private key to encoded format without the public key
                    if(sOutFile)
                    {
                        sRc = 1;
                        printf("**** ERROR: Unable to convert private raw -> encoded\n");
                        break;
                    }
                }
                else
                {
                    printf("**** ERROR: Unrecognized raw private key : %s\n", sInFile);
                    sRc = 1;
                    break;
                }
            }
            else
            {
                // Attempt to convert encoded key
                unsigned int sWireType = 0;
                if(sPubOut)
                {
                    // Get the raw public key
                    sMlcaRet = mlca_wire2key(sRawKey,
                                             sRawBytes,
                                             &sWireType,
                                             sKey,
                                             sKeyBytes,
                                             (const unsigned char*)CR_OID_SPECIAL_PRV2PUB,
                                             CR_OID_SPECIAL_PRV2PUB_BYTES);
                    if(0 >= sMlcaRet)
                    {
                        printf("**** ERROR: Unable to convert private key : %d\n", sMlcaRet);
                        sRc = 1;
                        break;
                    }
                    else
                    {
                        sRawBytes = sMlcaRet;
                    }
                    if(sVerbose)
                        printf("extractdilkey: Found public key\n");

                    // Encode it
                    sMlcaRet = mlca_key2wire(
                        sKey, sKeyBytes, sRawKey, sRawBytes, 0, NULL, 0, NULL, 0);
                    if(sMlcaRet < 0)
                    {
                        printf("**** ERROR: Failure during public key conversion : %d\n", sMlcaRet);
                        sRc = 1;
                        break;
                    }
                    sKeyBytes = sMlcaRet;
                }
                else
                {
                    sMlcaRet = mlca_wire2key(
                        sRawKey, sRawBytes, &sWireType, sKey, sKeyBytes, NULL, ~0);

                    // Raw private key size for dilithium r2 8/7 or MLDSA-87
                    if(0 >= sMlcaRet
                       || (RawDilithiumR28x7PrivateKeySize != sMlcaRet
                           && RawMldsa87PrivateKeySize != sMlcaRet))
                    {
                        printf("**** ERROR: Unable to convert private key : %d\n", sMlcaRet);
                        sRc = 1;
                        break;
                    }
                    else
                    {
                        sRawBytes = sMlcaRet;
                    }
                }
            }

            if(NULL != sOutFile)
            {
                printf("Writing private key to : %s\n", sOutFile);
                if(sRawOut)
                {
                    sRc = writeFile(sRawKey, sRawBytes, sOutFile);
                }
                else
                {
                    sRc = writeFile(sKey, sKeyBytes, sOutFile);
                }
            }
            else if(RawMldsa87PrivateKeySize == sRawBytes)
            {
                printf("Valid MLDSA-87 private keyfile detected\n");
            }
            else
            {
                printf("Valid Dilithium private keyfile detected\n");
            }
        }
    } while(0);

    free(sKey);
    free(sRawKey);
    exit(sRc);
}
