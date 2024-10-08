// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

// Package bootscope provides a way to bind keys to certain system properties for
// platforms that don't support measured boot.
//
// It is used to track the currently used boot mode and model, provides
// the KeyDataScope object which encapsulates the binding of boot environment
// information to a key, and helper functions used to authenticate and bind a
// scope with a key.
package bootscope

import (
	"sync/atomic"

	"github.com/snapcore/secboot"
	internal_bootscope "github.com/snapcore/secboot/internal/bootscope"
)

var (
	currentBootMode atomic.Value
)

func SetModel(model secboot.SnapModel) {
	internal_bootscope.SetModel(model)
}

func SetBootMode(mode string) {
	currentBootMode.Store(mode)
}
