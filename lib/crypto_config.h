/**
 * @file crypto_config.h
 * @brief CycloneCRYPTO configuration file
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2021 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.3.0
 **/

#ifndef _CRYPTO_CONFIG_H
#define _CRYPTO_CONFIG_H

#define GPL_LICENSE_TERMS_ACCEPTED

// Desired trace level (for debugging purposes)
#define CRYPTO_TRACE_LEVEL TRACE_LEVEL_INFO

// Multiple precision integer support
#define MPI_SUPPORT ENABLED
// Assembly optimizations for time-critical routines
#define MPI_ASM_SUPPORT DISABLED 

// Base64 encoding support
#define BASE64_SUPPORT ENABLED

// SHA-1 hash support
#define SHA1_SUPPORT ENABLED

// SHA-256 hash support
#define SHA256_SUPPORT ENABLED

// SECP256K1 curve support
#define SECP256K1_SUPPORT ENABLED

// ECDSA support
#define ECDSA_SUPPORT ENABLED
//secp192r1 elliptic curve support (NIST P-192)
#define SECP192R1_SUPPORT ENABLED

#endif