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

package preinstall

import (
	"errors"
	"fmt"

	"github.com/canonical/tcglog-parser"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

type driversAndAppsResultFlags int

const (
	driversAndAppsDriversPresent driversAndAppsResultFlags = 1 << iota
)

func checkDriversAndAppsMeasurements(log *tcglog.Log) (result driversAndAppsResultFlags, err error) {
	// Iterate over the log until OS-present and make sure we have expected
	// event types.
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex != internal_efi.DriversAndAppsPCR {
			// Not PCR2
			continue
		}
		if ev.EventType == tcglog.EventTypeSeparator {
			break
		}

		switch ev.EventType {
		case tcglog.EventTypeAction, tcglog.EventTypeEFIAction:
			// Some sort of action. The event data is a non-NULL terminated ASCII string.
			// The data in these events is not informational (the event digests are the tagged
			// hashes of the event data), but we don't verify that the event data is consistent
			// with the digests yet because we don't do any prediction here.
		case tcglog.EventTypeNonhostCode, tcglog.EventTypeNonhostInfo:
			// Non-host platform code running on an embedded controller. The second one is used
			// if the host platform cannot reliably measure the non-host code. The event data is
			// determined by the platform manufacturer and is purely informational.
		case tcglog.EventTypeEFIBootServicesApplication, tcglog.EventTypeEFIBootServicesDriver, tcglog.EventTypeEFIRuntimeServicesDriver:
			// Code from value-added-retailer component loaded via the LoadImage API.
			// We don't check the digests here because it's likely that the device path
			// takes us to something we can't read, and we don't do any prediction here
			// yet either.
			result |= driversAndAppsDriversPresent
		case tcglog.EventTypeEFIPlatformFirmwareBlob:
			// Code blob from value-added-retailer component - deprecated. Event data should
			// contain a UEFI_PLATFORM_FIRMWARE_BLOB structure.
			result |= driversAndAppsDriversPresent
		case tcglog.EventTypeEFIPlatformFirmwareBlob2:
			// Code blob from value-added-retailer component. Event data should contain a
			// UEFI_PLATFORM_FIRMWARE_BLOB2 structure.
			result |= driversAndAppsDriversPresent
		case tcglog.EventTypeEFISPDMFirmwareBlob:
			// Firmware of a component that supports SPDM "GET_MEASUREMENTS".
			// Note that this is very new (only in the TCG PFP spec v1.06)
			result |= driversAndAppsDriversPresent
		default:
			return 0, fmt.Errorf("unexpected pre-OS log event type %v", ev.EventType)
		}
	}

	// Nothing should measure to PCR2 outside of pre-OS - we'll generate an invalid profile
	// if it does.
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex == internal_efi.DriversAndAppsPCR {
			return 0, errors.New("firmware measures events as part of the OS-present environment")
		}
	}

	return result, nil
}
