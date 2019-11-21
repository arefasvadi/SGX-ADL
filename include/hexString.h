/*
 *  hexString.h
 *  byteutils
 *
 *  Created by Richard Murphy on 3/7/10.
 *  Copyright 2010 McKenzie-Murphy. All rights reserved.
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <memory>
#include <vector>

std::vector<uint8_t>
hexStringToBytes(const char *inhex);

std::string
bytesToHexString(const uint8_t *bytes, size_t buflen);