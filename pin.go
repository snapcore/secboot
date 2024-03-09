// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package secboot

import (
	"errors"
	"fmt"
	"math"
	"math/big"
)

type PIN struct {
	length uint8   // the length of the input PIN. This is *not* the length of the encoded binary number
	value  big.Int // the PIN value. This is encoded in big-endian form without leading zeroes.
}

func ParsePIN(s string) (PIN, error) {
	l := len(s)
	if l > math.MaxUint8 {
		return PIN{}, errors.New("invalid PIN: too long")
	}

	val, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return PIN{}, errors.New("invalid PIN")
	}

	return PIN{
		length: uint8(l),
		value:  *val,
	}, nil
}

func (p PIN) String() string {
	return fmt.Sprintf("%0*s", p.length, p.value.String())
}

func (p PIN) Bytes() []byte {
	maxS := make([]byte, p.length)
	for i := range maxS {
		maxS[i] = '9'
	}
	max, _ := new(big.Int).SetString(string(maxS), 10)
	b := make([]byte, len(max.Bytes()))
	return append([]byte{p.length}, p.value.FillBytes(b)...)
}
